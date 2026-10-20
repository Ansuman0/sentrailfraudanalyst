# Sentrail — project memory

Long-lived technical context. Read this, then [CURRENT_STATE.md](CURRENT_STATE.md) and [CHANGELOG.md](CHANGELOG.md),
before changing anything. Release notes for users live in [../CHANGES.md](../CHANGES.md); the security design
in [../SECURITY.md](../SECURITY.md).

## What it is

Multi-tenant AML platform for MSBs, payment companies and crypto on/off-ramps: real-time screening of crypto
transfers (`POST /screen`, API key), alert queue and case work, STR drafting with a local LLM and four-eyes
approval, wallet tracing, tamper-evident audit log. Platform staff (the SaaS operator) manage tenants but must
never see tenant customer data.

## Architecture

Repository: `backend/` and `frontend/` are separate services (own deps, Dockerfile, tests); `infra/` holds deployment files; `.env`,
`docker-compose.yml`, `docs/`, `memory/` at the root. Python commands run from `backend/` (see DECISIONS.md, 2026-10-17).

```
frontend/ (React 18 + TS, Vite)  ──Bearer token──▶  backend/ (FastAPI, Python 3.11)──▶  PostgreSQL 16 (RLS)
                                 ──refresh cookie─▶  /auth/*                      ──▶  Keycloak (OIDC, optional)
                                                                                  ──▶  OpenBao (key unwrap, prod)
                                                                                  ──▶  Ollama (local LLM), TronGrid, Etherscan, mempool.space, OFAC list
```

| Area | Where |
|---|---|
| HTTP API, case/screening routes | `backend/app/main.py` |
| Sign-in, MFA, orgs, users, roles, features, security, API keys, audit, platform console | `backend/app/admin_api.py` (large; one router) |
| AuthN/AuthZ per request | `backend/app/security/rbac.py` (`current_user`, `require`, `require_any`, `api_key`) |
| Tokens | `backend/app/security/tokens.py` (Ed25519 JWT 10 min; claims `sub org rid sv amr sid`) |
| Encryption | `backend/app/security/crypto.py` (AES-256-GCM per value, AAD = org+column; blind index HMAC for email lookup) |
| Audit hash chain | `backend/app/security/audit.py` |
| DB access | `backend/app/pg.py` `tx(org_id, platform)` sets `app.org_id`/`app.platform` per transaction → RLS; `backend/app/db.py` case data |
| Detection | `backend/app/detection/` (rules, XGBoost+SHAP, NetworkX graph, `scorer.combine`) |
| Services | `backend/app/services/` (screening, cases, wallet_trace, search, mailer, keycloak_admin) |
| AI agent | `backend/app/agent/` (LangGraph, Presidio masking, Chroma RAG, `guardrails.verify` figure check) — imported lazily |
| Schema | `backend/migrations/NNN_*.sql`, applied by `backend/scripts/migrate.py` (checksummed; never edit an applied file) |
| Web app | `frontend/src/` — `services/http.ts` is the only fetch wrapper; `services/sentrail.ts` every endpoint; `hooks/useAuth.tsx` session |

## Database and tenancy

- Roles: `sentrail_owner` (owns schema, migrations only), `sentrail_app` (API; RLS applies), `sentrail_auth`
  (NOLOGIN, BYPASSRLS, owns SECURITY DEFINER lookup functions such as `auth_lookup`, `api_key_lookup`).
- Every tenant table is scoped by RLS on `current_setting('app.org_id')`. Always go through `pg.tx(...)`;
  never query tenant tables on a bare pool connection (only the lookup functions do that).
- Personal data (email, name, TOTP secret, STR text) is encrypted per value; emails are found by blind index.
- Audit events: append-only (trigger + revoked privileges), per-org hash chain, advisory lock per org.

## Authentication and sessions

- `AUTH_MODE=keycloak` (recommended): org users sign in via OIDC (code + PKCE, backend-for-frontend; the browser
  never sees OIDC tokens). Platform staff keep a break-glass password + TOTP login. `AUTH_MODE=local`: everyone
  uses the API's password sign-in (used for local dev and most tests), plus TOTP once two-factor is on.
- **Decision (2026-10-16, requested by the user): two-factor is optional per organization, default optional.**
  `users.mfa_enabled` = the person confirmed TOTP; `security_settings.mfa_required` = the org makes it mandatory
  (migration 007 removed the trigger that forced it true). Password login without two-factor returns a
  password-only session (amr `pwd`, refresh-token `auth_method='password'`); `rbac.signed_in_user` accepts it,
  `rbac.current_user` only when setup is "optional". **Superseded 2026-10-17 (requested by the user): nothing is forced by
  default** — `MFA_ALWAYS_PERMS` and the platform-staff rule are gone; only an org admin switching on `mfa_required` makes it
  "required". Each person turns it on from My account (QR code). Migration 008 adds `users.mfa_enabled_at` (trigger-maintained)
  and CHECK `users_mfa_has_secret`. Keycloak mode still enforces TOTP in Keycloak itself. Never without two-factor:
  `str.approve`, `data.export`, `policy.edit`, `screening.override` (`MFA_SENSITIVE_PERMS`, checked in `require`).
  Setup: `POST /me/mfa/setup` → `/me/mfa/confirm` (ends all sessions, issues a two-factor session, 8 recovery codes).
  Invitations no longer enroll TOTP; admin `reset-mfa` turns it off and the user is prompted at next sign-in.
  The web app shows `/setup-2fa` automatically only when `/me.mfa_setup` is "required"; otherwise My account has "Turn on two-factor".
- After sign-in the API returns an access token (JSON) and sets `sentrail_rt` (HttpOnly, Secure, SameSite=Strict,
  **path=/auth**). Refresh rotates the token; presenting a used one revokes the whole family.
- **Decision (2026-10-16):** the current session is identified by the `sid` claim in the access token, not by the
  cookie (which never reaches `/me/*`).
- **Decision (2026-10-16):** the web app keeps the access token in memory only and serializes refreshes within a
  tab (shared promise) and across tabs (`navigator.locks`). Never add a second code path that calls `/auth/refresh`.
- Permission changes take effect immediately via `users.session_version` (checked on every request).

## Business rules worth remembering

- Screening fails closed: if chain data or the OFAC list can't be checked, the answer is `hold`, never `release`.
- Thresholds are in fiat; non-stablecoins need `fiat_value`. `client_ref` makes `/screen` idempotent per org.
- Alert lifecycle: `open|pending_info` → decision (`false_positive`→closed, `request_info`→pending_info,
  `escalate`→escalated) → STR submit → `awaiting_approval` → approval by a *different* officer → `str_filed`.
  Closed and filed are final. Enforced in `backend/app/db.py` with row locks plus a DB CHECK.
- Only held screenings can be overridden, once.
- Platform roles can only hold platform permissions and vice versa (DB trigger `check_perm_scope`).

## Conventions

- Error messages in `HTTPException` are written for end users; the frontend shows them as-is (`ApiError.message`).
- Missing or empty `ENV` = production (no `/docs`, no invite links in responses, signing key required).
- Secrets only in `.env` (git- and docker-ignored). `backend/scripts/dev_env.py` for local values; OpenBao in production.
- Local DB URLs use `127.0.0.1`, not `localhost` (IPv6 stall on Windows with Docker).
- Python 3.11 (matches the Dockerfile). Frontend dependencies pinned to exact versions.
- Tests: plain scripts printing `PASS`/`FAIL` lines, run by `backend/tests/run_all.sh` on database `sentrail_test`;
  frontend uses Vitest + Testing Library (`npm test`).
- Commit style: Conventional Commits (`feat:`, `fix:`, `docs:` …). The directory is not a git repository yet.

## Known limitations

- SSO enforcement (`sso_enforced`) and passkey-only platform staff are stored but not enforced by the API.
- Data region is checked only at org creation. Blind-index key can't be rotated.
- Demo graph "reported accounts" come from dataset labels (optimistic scores).
- `/cases/{id}/investigate` runs three LLM calls synchronously.
- React app doesn't yet cover: live screening feed, customer wallets, statement upload, reports, admin screens
  (users, roles, features, API keys, reveal-email, reset-mfa and security settings (two-factor switch, idle timeout, password length, allowlist,
  retention) and company SSO domain setup exist since 2026-10-17, and platform plans (Plans screen, org plan selector); platform security baseline; platform roles and staff do not), graph view of traces.
- Keycloak, OpenBao and Ollama have not been run end to end in this environment; tests simulate Keycloak,
  chain APIs and OFAC.
