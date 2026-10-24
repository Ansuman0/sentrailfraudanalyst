# Sentrail

**Guard the gate. Follow the trail.**

Open-source AML platform for MSBs, payment companies and crypto on/off-ramps. Sentrail screens
crypto deposits and withdrawals in real time, scores bank, card and crypto activity, traces wallets
on public blockchains, and drafts STRs with a local open-source model. Analysts make every decision,
and every action is recorded in a tamper-evident audit log.

Docs: [Access runbook](docs/RUNBOOK_ACCESS.md) · [Cut-over](docs/CUTOVER.md) · [Local development](docs/LOCAL_DEVELOPMENT.md) · [Changes](CHANGES.md) · [Security design](SECURITY.md) · [Identity and sign-in](docs/IDENTITY.md) · [Roles and permissions](docs/ROLES.md) · [Database](docs/DATABASE.md) · [Table reference](docs/schema-tables.md)

## Architecture

```
Browser (React)  ─HTTPS─▶  FastAPI
                            ├── admin_api.py   sign-in + MFA, organizations, users, invitations, roles, features, security, audit
                            ├── security/      encryption, argon2id, TOTP, tokens, RBAC, audit chain, headers
                            ├── detection/     rules, XGBoost + SHAP, NetworkX graph, scorer
                            ├── services/      screening, wallet trace, cases, search, mail
                            ├── connectors/    TronGrid, Etherscan v2, mempool.space, OFAC and blocklists
                            └── agent/         LangGraph agent, Presidio masking, Chroma RAG, figure checks
Ramp ─API key─▶ POST /screen
                           PostgreSQL 16 (row-level security)   Keycloak (identity)   OpenBao (keys)   Ollama (local LLM)
```

## Run it

**On your machine** (API and React app on the host, PostgreSQL in Docker) — full guide in
[docs/LOCAL_DEVELOPMENT.md](docs/LOCAL_DEVELOPMENT.md):

```bash
cd backend                                                # backend commands run from backend/; .env stays at the repo root
py -V:3.11 -m venv .venv && .venv/Scripts/python -m pip install -r requirements.txt   # Python 3.11
.venv/Scripts/python -m scripts.dev_env                   # random dev secrets into ../.env (ENV=dev only)
docker compose -f ../docker-compose.yml --project-directory .. up -d postgres
.venv/Scripts/python -m scripts.migrate
.venv/Scripts/python -m scripts.seed --demo > .dev-credentials.txt   # demo logins + TOTP URIs (git-ignored)
.venv/Scripts/python -m uvicorn app.main:app --port 8000 --reload   # http://localhost:8000 (/docs in dev)
cd ../frontend && npm install && npm run dev              # http://localhost:5173
```

**Whole stack in Docker** (Keycloak, OpenBao, Ollama):

```bash
cp .env.example .env                           # fill in the passwords and secrets
(cd backend && python -m scripts.generate_keys) >> .env   # dev encryption + signing keys (OpenBao in production)

docker compose up -d postgres keycloak         # databases, roles, Keycloak with the sentrail realm
docker compose run --rm migrate                # schema + row-level security, sets the app role password
docker compose run --rm api python -m scripts.seed --demo   # master login + two demo tenants
docker compose up -d api ollama
```

- Master login: the `SEED_ADMIN_EMAIL` account, a **Platform owner** with a break-glass password + TOTP (printed once by the seed).
- Demo platform team: a platform admin, support and auditor (`--demo`).
- Demo users: sign in through Keycloak at the app with `SEED_DEMO_PASSWORD`, then set up two-factor.
- Keycloak console: http://localhost:8080 with `KEYCLOAK_ADMIN_USER` (for the identity provider itself, not Sentrail).

Detection data: download "IBM Transactions for Anti Money Laundering" from Kaggle, then
`python scripts/prepare_data.py data/HI-Small_Trans.csv` and `SEED_ORG_ID=<org uuid> python -m scripts.train_and_score` (both from `backend/`).
Put the same id in `.env` as `DEMO_DATA_ORG_ID`: the demo dataset is served to that organization only.
A real organization's own data goes in `backend/data/orgs/<org_id>/` (`transactions.parquet`, `profiles.json`, optional `model.joblib`).

Tests. Backend: each suite on its own fresh database `sentrail_test` (never the dev database); exits non-zero if any check fails:
`set -a; . ./.env; set +a; PG_SUPERUSER_URL="postgresql://postgres:${POSTGRES_SUPERUSER_PASSWORD}@127.0.0.1" OWNER_PASSWORD="$SENTRAIL_OWNER_PASSWORD" sh backend/tests/run_all.sh` (run from the repo root; the script changes into `backend/` itself).
Frontend: `cd frontend && npm test && npm run typecheck && npm run build`.

| Suite | Checks | Covers |
|---|---|---|
| `detection_unit` | 20 | AI figure check, fiat thresholds, wallet age, fail-closed sanctions screening (no database) |
| `security_e2e` | 33 | Sign-in, MFA, encryption at rest, tenant isolation, roles, refresh rotation, audit tampering, lockout, current-session detection |
| `oidc_e2e` | 20 | Keycloak sign-in, state/nonce/audience checks, SSO linking, open redirects |
| `platform_e2e` | 27 | Platform roles, plans, security baseline, support access |
| `cases_e2e` | 78 | Screening, idempotency, alert lifecycle, STR four-eyes, overrides, export, API keys, session limits, throttling, user-chosen/mandatory two-factor and its DB flag, sign-in error handling |
| `frontend` (Vitest) | 23 | Single-flight token refresh, 401 retry, memory-only token, open-redirect guard, route guards by permission, two-factor gate |

## Access control and security

People work for organizations through **memberships**: a role and a status per organization (one person, several organizations, one at a time), and
Sentrail's own staff are a separate platform team. Every permission is defined once in `backend/app/access/catalogue.py`; the generated
[permissions](docs/permissions.md) and [route permissions](docs/route-permissions.md) show who may do what, and the API refuses to start if a route
has no declared permission. The server enforces everything; the web app only hides what a role can't use (and the tests prove the API refuses it anyway).

* **Sign-in:** one account, password plus authenticator app or passkey; tenant picker for people in several organizations; fresh second factor for
  sensitive actions; company single sign-on (OIDC or SAML through Keycloak) can be enforced per organization.
* **Isolation:** PostgreSQL row-level security on every tenant table, plus membership checks; restricted (need-to-know) cases; a cross-tenant test
  runs every route and every background job against two tenants.
* **Platform staff** never see customer data except through a time-limited access session the organization controls; owners approve each other's
  highest-risk actions; a sealed break-glass account exists for emergencies.
* **Governance:** access reviews, dormant-member suspension, SCIM, signed audit export and streaming, export limits, anomaly alerts, data export and removal.
* **Background jobs** run in the `worker` container (`python -m scripts.run_jobs`).

Read [Security design](SECURITY.md), [Identity and sign-in](docs/IDENTITY.md), the [access runbook](docs/RUNBOOK_ACCESS.md) (break-glass, owner access,
tenant recovery), the [cut-over guide](docs/CUTOVER.md) and the [SOC 2 evidence guide](docs/soc2-access-evidence.md).

## API

| Area | Endpoints |
|---|---|
| Sign-in (Keycloak) | `POST /auth/discover`, `GET /auth/oidc/login`, `/auth/oidc/callback`, `/auth/oidc/logout` |
| Sign-in (break-glass) | `POST /auth/login`, `/auth/mfa`, `/auth/refresh`, `/auth/logout` |
| Two-factor | `POST /me/mfa/setup`, `/me/mfa/confirm` (also from a password-only session) |
| Me | `GET /me` (user + tenant, `mfa_enabled`, `mfa_setup`), `GET /me/sessions`, `DELETE /me/sessions/{id}`, `POST /me/sessions/end-others` |
| Company SSO | `PUT /admin/sso`, `POST /admin/sso/verify` |
| Invitations | `POST /admin/invitations`, `/invitations/accept` (name + password; two-factor comes after sign-in) |
| Users | `GET /admin/users`, `PATCH /admin/users/{id}`, `POST /admin/users/{id}/reveal-email`, `/reset-mfa` |
| Roles | `GET/POST /admin/roles`, `PUT /admin/roles/{id}` |
| Organization | `GET/PUT /admin/features`, `GET/PUT /admin/security` (send only the fields to change) |
| API keys | `GET/POST /admin/api-keys`, `DELETE /admin/api-keys/{prefix}` |
| Platform: tenants | `GET/POST /platform/orgs`, `PUT /platform/orgs/{id}/plan`, `GET /platform/orgs/{id}/users?reason=`, `POST /platform/orgs/{id}/users/{uid}/resend-invitation` |
| Platform: team | `GET /platform/users`, `POST /platform/invitations`, `PATCH /platform/users/{id}` |
| Platform: roles | `GET/POST /platform/roles`, `PUT /platform/roles/{id}` |
| Platform: plans | `GET /platform/plans`, `PUT /platform/plans/{key}` |
| Platform: security | `GET/PUT /platform/security` |
| Health | `GET /healthz`, `/readyz` |
| Audit | `GET /admin/audit`, `/admin/audit/verify` |
| Screening | `POST /screen` (API key), `GET /screenings/{id}`, `POST /screenings/{id}/override`, `GET/PUT /policy` |
| Cases | `GET /alerts`, `/cases/{id}`, `/cases/{id}/export`, `/search`, `/wallets/{address}/trace`, `POST /cases/{id}/investigate`, `/decision`, `/assign`, `/str/submit`, `/str/approve`, `/upload` |

### Screening request

```json
POST /screen   Authorization: Bearer sk_live_…
{"direction": "deposit", "customer_id": "CUST-77", "address": "bc1q…", "amount": 0.5, "asset": "BTC",
 "fiat_value": 41000, "client_ref": "ramp-tx-1", "travel_rule_ok": false, "self_hosted": true, "ownership_proven": false}
```

`fiat_value` is required for anything that isn't a stablecoin: policy thresholds are in the reporting currency.
`client_ref` makes retries safe: the same value returns the stored answer instead of screening again.
If chain data or the sanctions list can't be checked, the answer is `hold` with a reason, never `release`.

### Alert lifecycle

`open` → `false_positive` → `closed` · `request_info` → `pending_info` · `escalate` → `escalated` → STR submitted →
`awaiting_approval` → approved by a second officer → `str_filed`. Closed and filed alerts are final.

## Frontend

`frontend/` is the React + TypeScript app (Vite, React Router, TanStack Query) that calls the real API:
sign-in (password + TOTP, or company SSO through Keycloak), invitation enrollment (`/join`), two-factor setup after sign-in (`/setup-2fa`), the alert queue, case view with decisions,
STR drafting (AI draft, submit, four-eyes approval), search, wallet trace, screening policy, audit log with
chain verification, signed-in devices, the platform's organization list with plan changes, platform plans, the platform security baseline, and organization admin screens
(users: invite, change role, suspend, reveal a masked email or reset two-factor with a recorded reason; roles: edit permissions, create custom roles; features: switch on or off; API keys: create once, revoke; security: two-factor switch, inactivity timeout, password length, allowed networks, audit retention; company sign-in: domain DNS check for SSO). Navigation follows the user's
permissions and features from `/me`; the API enforces every permission on its own.

The access token is kept in memory only; the HttpOnly refresh cookie restores the session on reload.
Set the API address with `VITE_API_BASE_URL` (see `frontend/.env.example`).

```
frontend/src/
  services/http.ts       the only fetch wrapper: bearer token, single-flight refresh, error messages
  services/sentrail.ts   every API call
  hooks/useAuth.tsx      session state, permissions, sign-in/out
  components/            layout, route guards, shared UI
  pages/                 one file per screen
  types/api.ts           API response shapes
```

`frontend/sentrail-prototype.html` is the original clickable design prototype (no API calls). Screens it shows
that the React app doesn't have yet: live screening feed, customer wallets, statements upload, reports, and the
remaining admin screens (platform roles, platform staff).
