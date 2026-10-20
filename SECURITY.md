# Sentrail security design

Sentrail handles customer financial data and suspicious transaction reports for regulated
companies, so the design assumes attackers will try to read another tenant's data, escalate
privileges, steal sessions, and cover their tracks. Every control below is enforced by the
server and the database. The UI hides what a role can't do only for clarity.

## Who can do what

| Role | Scope | Can | Can't |
|---|---|---|---|
| Platform owner | Platform | Everything in the platform console: staff, platform roles, plans, security baseline, tenants. Holds the break-glass login | See any organization's customers, cases, alerts or STRs |
| Platform admin | Platform | Create organizations, change plans, manage platform staff (not owners), support tenants | Same as above; can't create or change platform owners or the security baseline |
| Platform support | Platform | See an organization's user list (masked emails, no names) and resend invitations, with a written reason logged in that organization's own audit log | Same as above |
| Platform auditor | Platform | Read and verify the platform audit log | Change anything |
| Organization admin | One organization | Invite users, assign roles, edit roles, toggle features, security settings, view audit | Decide cases (separation of duties), change their own role |
| Compliance officer | One organization | Everything case-related, approve STRs, change screening policy | Approve an STR they drafted |
| Compliance analyst | One organization | Work alerts, trace wallets, override screening, draft STRs | Approve STRs, manage users |
| Auditor (read-only) | One organization | View cases and audit log | Change anything |

Custom roles can be created per organization and for the platform. Each permission belongs to one login
type, and a database trigger rejects any role that mixes them. The platform sets a security baseline
(password length, inactivity, session length, retention, passkeys) that every organization must meet;
organizations can be stricter but never looser, and two-step verification can't be turned off.

## Controls

| Area | Control | Where |
|---|---|---|
| Tenant isolation | PostgreSQL row-level security on every tenant table, `FORCE`d, app connects as a non-owner role; tenant set per transaction with `SET LOCAL` so pooled connections can't leak context | `backend/migrations/001_init.sql`, `backend/app/pg.py` |
| Personal data at rest | AES-256-GCM per field (email, name, phone, TOTP secret, STR text); associated data binds each value to its org and column | `backend/app/security/crypto.py` |
| Searchable encryption | HMAC-SHA256 blind index on email with a separate key | `crypto.blind_index` |
| Key management | Versioned keys; production keys unwrapped by OpenBao/Vault transit, master key never leaves it; online rotation script | `crypto.OpenBaoKeyring`, `backend/scripts/rotate_keys.py` |
| Identity provider | Keycloak over OpenID Connect: authorization code + PKCE, server-side code exchange, ID token signature/issuer/audience/nonce/age checks, no self-registration, linking only on verified SSO domains, break-glass local login for platform admins only | `backend/app/security/oidc.py`, `infra/keycloak/realm-sentrail.json`, `docs/IDENTITY.md` |
| Company SSO | Keycloak brokers Entra ID, Google Workspace, Okta or any SAML/OIDC IdP; domains proven by DNS TXT record | `/admin/sso`, `/admin/sso/verify` |
| Passkeys | WebAuthn with user verification, through Keycloak | realm `webAuthnPolicy*` |
| Database roles | App role can't bypass row-level security; owner has row-level security forced; sign-in lookups run as a no-login role that reads only the columns they need | `backend/migrations/004_lookup_role.sql`, `docs/DATABASE.md` |
| Sessions visible to users | Users see and end their own sessions, or all others at once. The current session is identified by the signed `sid` claim in the access token (the refresh cookie is scoped to `/auth` and never reaches `/me`) | `/me/sessions` |
| Backups | Nightly `pg_dump` of both databases encrypted with age to an offline key, checksummed, restore test documented | `infra/postgres/backup.sh` |
| Logs | JSON logs with emails, card-like numbers and tokens scrubbed | `backend/app/logging_config.py` |
| Passwords | argon2id, 14+ characters by default, breached-password check via HIBP k-anonymity, no composition rules (NIST SP 800-63B) | `backend/app/security/passwords.py` |
| MFA | Each person's choice, turned on from My account with a QR code (nobody is forced by default, platform staff included). An organization admin can make it mandatory (`security_settings.mfa_required`, off by default). Without it nobody can approve STRs, export cases, change policy or override screenings. The database records it: `users.mfa_enabled`, `users.mfa_enabled_at` (kept by a trigger) and a CHECK that "on" needs a stored secret (migration 008); a password-only session stays password-only on refresh, and turning two-factor on ends it. Replay of a used code rejected; single-use recovery codes stored hashed | `backend/app/security/rbac.py`, `backend/app/security/mfa.py` |
| Login abuse | Rate limits; lockout after 5 failures for 15 minutes per (email, client IP), applied to unknown emails too; one identical error and timing for unknown users, wrong passwords and organization users in Keycloak mode | `admin_api.login`, `login_throttle` |
| Session limits | Organization idle timeout and platform maximum session length enforced at every refresh; access tokens never outlive the idle window | `admin_api.refresh`, `_session_limits` |
| Fail closed | Transfers that can't be checked against chain data or a loaded OFAC list are held, never released; OFAC reloads every 6 hours | `services/screening.py`, `connectors/risk_lists.py` |
| Safe defaults | A missing `ENV` means production: no API docs, no invitation links in responses, no ephemeral signing key | `backend/app/config.py`, `security/tokens.py` |
| Sessions | Ed25519-signed 10-minute access tokens; refresh tokens rotated on every use, stored only as hashes, HttpOnly Secure SameSite=Strict cookie; reuse of an old token revokes the whole family. The web app keeps the access token in memory only and makes refreshes single-flight, across calls in a tab (shared promise) and across tabs (Web Locks), so the same refresh token is never presented twice | `backend/app/security/tokens.py`, `frontend/src/services/http.ts` |
| Instant revocation | Role change, suspension or MFA reset bumps `session_version`; every request re-checks it | `rbac.current_user` |
| Authorization | Permission + feature check on every endpoint; no self-escalation; can't suspend or demote yourself; at least one active org admin always kept | `rbac.require`, `admin_api` |
| Login-type separation | Permissions tagged `platform` or `tenant`; trigger blocks mixing; platform staff have no customer-data permission | `backend/migrations/005_platform_console.sql` |
| Security baseline | Platform floors enforced on every tenant by trigger; raising the floor raises every tenant below it | `platform_settings`, `/platform/security` |
| Support access transparency | Support lookups need a reason and are written to the customer's own audit log | `/platform/orgs/{id}/users` |
| Four-eyes | STR approval by someone other than the drafter, enforced in code and by a database CHECK constraint | `db.approve_str`, `str_drafts.four_eyes` |
| Invitations | 256-bit single-use token, stored as SHA-256, expires in 72 hours, sent in the URL fragment so it isn't logged by servers | `admin_api._invite` |
| Network | Per-organization IP allowlist; changes that would lock out the admin are rejected | `security_settings.ip_allowlist` |
| Machine access | Ramp API keys scoped to `screen`, shown once, stored hashed, revocable | `api_keys`, `rbac.api_key` |
| Audit | Every sign-in, data view, search, decision, permission and setting change; hash-chained, append-only (trigger + revoked privileges); `/admin/audit/verify` detects edits even by a database superuser | `backend/app/security/audit.py` |
| Sensitive reveals | Unmasking an email requires a written reason that is audited | `/admin/users/{id}/reveal-email` |
| HTTP | HSTS, strict CSP, no-sniff, no-referrer, no-store, request IDs, strict CORS, API docs off outside dev | `backend/app/security/middleware.py` |
| AI privacy | Personal data masked with Presidio before reaching the local model; no data sent to external AI services | `backend/app/agent/masking.py` |
| Containers | Non-root user, read-only filesystem, no-new-privileges, database and key manager bound to localhost | `backend/Dockerfile`, `frontend/Dockerfile`, `docker-compose.yml` |
| Retention | Minimum 5 years (FINTRAC record keeping) enforced in the schema | `security_settings.retention_years` |

## Tested

All suites run against a real PostgreSQL 16 database installed with the same roles and migrations as
production (owner is not a superuser):

- `backend/tests/test_security_e2e.py` (31 checks): tenant isolation including the organizations table,
  replay protection, refresh-token theft detection, lockout persistence, self-escalation, tenant info,
  and detection of audit tampering by a superuser.
- `backend/tests/test_platform_e2e.py` (28 checks): platform staff and owner protections, roles by login type
  (API and database trigger), plans switching features on and off, the security baseline raising tenants
  and blocking weaker settings, two-step verification that can't be turned off, and audited support access.
- `backend/tests/test_oidc_e2e.py` (20 checks): Keycloak sign-in with a simulated IdP signing real RS256 tokens:
  PKCE, state replay, wrong nonce, issuer, audience, unverified email, stale authentication, no
  self-registration, account takeover by email outside the verified domain, open redirects,
  suspension, and break-glass login.

## Not done yet (be upfront about these with judges and customers)

- **Live Keycloak test.** The OIDC flow is tested against a simulated IdP. Run it once against the real
  Keycloak container and confirm the realm settings imported as expected (see docs/IDENTITY.md).
- **Point-in-time recovery.** Nightly encrypted dumps exist; continuous WAL archiving (pgBackRest) doesn't.
- **Keycloak hardening for production:** run `start --optimized` behind TLS, its own admin on a private network.
- **Independent penetration test** and a formal threat model review.
- **Data residency** is a label on the organization; enforcing it needs region-specific deployments.

## Reporting a vulnerability

Email security@yourdomain.ca. Don't open a public issue.
