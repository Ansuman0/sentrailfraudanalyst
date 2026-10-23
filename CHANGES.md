# Unreleased (0.4)

Adds the React web app, makes two-factor optional per organization, and makes the project runnable and testable on
a developer machine. Backend: 160 checks, frontend: 23 tests, all passing. See [docs/LOCAL_DEVELOPMENT.md](docs/LOCAL_DEVELOPMENT.md).

## Changed

- **Tenant lifecycle (access model v2, in progress, not released)**: a new organization starts pending and goes live when its first admin accepts the 72-hour invitation (and sets up two-factor); platform owners can suspend and reactivate it, delete it only with a second owner's approval, and appoint a replacement admin; plans now enforce their seat limits. See [docs/IDENTITY.md](docs/IDENTITY.md).

- **Isolation and need-to-know (access model v2, in progress, not released)**: the database itself now refuses a person who has lost their membership; a case can be marked restricted so only people with restricted-case access or named on it can open it; case and STR views are audited; the Tenant admin role is read-only on the roles screen; "Reveal email", security settings and API keys have their own permissions. See [docs/IDENTITY.md](docs/IDENTITY.md).

- **Sign-in and sessions (access model v2, in progress, not released)**: one sign-in for everyone that routes to the console, one tenant, a tenant picker or a no-access page; a header switcher for people in several organizations; a "Confirm it's you" prompt (fresh two-factor check) before sensitive actions; accounts lock after 10 wrong passwords from one network in 15 minutes; sign-out ends a session immediately; you are told by email about sign-ins from a new device and about two-factor and role changes. See [docs/IDENTITY.md](docs/IDENTITY.md).

- **Roles renamed (access model v2, in progress, not released)**: "Organization admin" becomes the locked "Tenant admin" with every tenant permission, "Platform admin" is merged into "Platform owner", and analysts can no longer override held screenings. See [docs/permissions.md](docs/permissions.md).

- **Works before DNS is ready**: the app now also opens on the server's AWS public hostname (`https://ec2-…compute-1.amazonaws.com`, printed by the deploy log); the browser app talks to the API on the same address. Single sign-on still needs the real domain.

- **Project layout**: the API now lives in `backend/` and the web app in `frontend/`, each with its own dependencies, Dockerfile and tests;
  Postgres init, the Keycloak realm and observability config moved to `infra/`. Run Python commands from `backend/` (the virtualenv is
  `backend/.venv`); `.env` and `docker-compose.yml` stay at the root. See [docs/LOCAL_DEVELOPMENT.md](docs/LOCAL_DEVELOPMENT.md).

## Added

- **AWS deployment from GitHub**: pushing to `main` tests, builds and deploys only the service that changed (backend or frontend). Run the
  `deploy` workflow by hand to pick backend / frontend / both, list earlier versions, or roll one service back. See [docs/DEPLOYMENT_AWS.md](docs/DEPLOYMENT_AWS.md).

- **Platform security baseline** screen: the minimum password length, longest inactivity and shortest audit retention every
  organization must meet. Applying it asks for confirmation first because it affects every organization at once.
- **Platform plans** in the web app: a Plans screen (edit which features each plan includes) and a plan selector on Organizations.
  Both ask for confirmation first and say what switches off, because a change applies to every organization on the plan at once.
- **Organization admin screens** in the web app: Users (invite, change role, suspend/reactivate, reveal a masked email or reset two-factor, each with a written reason that goes to the audit log), Roles (edit permissions, create custom roles; your own role is read-only), Features (switch on or off within the plan; the menu updates at once), API keys (shown once on
  creation, revoke with confirmation) Company sign-in (claim an email domain with a DNS record and check it; the DNS record is shown once), and Security settings (the "require two-factor for everyone" switch, inactivity timeout, minimum password length, allowed networks and audit retention; the API still refuses an allowlist that would lock you out or values below the platform's floor). They appear
  under "Administer" for people who can manage users; the API still enforces every permission.
- **React web app** in `frontend/` (React 18 + TypeScript, Vite, React Router, TanStack Query) wired to the real API:
  sign-in with password + TOTP or company SSO, invitation enrollment (`/join`), alerts, case view and decisions, STR draft/submit/approve, search,
  wallet trace, screening policy, audit log with chain verification, signed-in devices, platform organizations.
  Access token in memory only; refresh is single-flight within a tab and across tabs (Web Locks).
- `scripts/dev_env.py`: fills empty `.env` values with random development secrets (refuses unless `ENV=dev`).
- `.gitignore`, `.dockerignore`, `.gitattributes`; `frontend/.env.example`; `docs/LOCAL_DEVELOPMENT.md`.

## Changed: two-factor is your choice, from My account (2026-10-17)

- Nobody is forced to use two-factor by default any more, platform staff and admins included. **My account → Turn on two-factor**
  shows a QR code to scan (the typed key is still there) and then 8 recovery codes. The after-sign-in prompt and banner are gone.
  An organization admin can still make it mandatory in Security settings (off by default).
- The database records it: `users.mfa_enabled`, a new `users.mfa_enabled_at`, and a rule that it can't be "on" without a stored
  authenticator secret (migration `008_mfa_flag_in_db.sql`). The user list shows when each person turned it on.
- Sign-in errors are clearer and still reveal nothing about who has an account: an unknown email, a wrong password and a suspended
  account all get "Email or password is incorrect", plus a hint to ask for an invitation. A bad email, too many attempts, a server
  error and an unreachable API each get their own message; a stale two-factor token ends in a clean "sign in again".
- The bootstrap and seed scripts no longer create accounts with two-factor on.

## Earlier in 0.4: two-factor is set up after sign-in, and optional per organization

- Invitations set only name and password (`/invitations/verify` is removed). After signing in with the password,
  a user without two-factor is asked to set it up (`POST /me/mfa/setup`, `POST /me/mfa/confirm`).
- New `users.mfa_enabled` records whether each person has two-factor on. `security_settings.mfa_required` (Security
  settings, org admins) decides whether the organization's users must set it up or may skip it. **Default: optional,
  for new and existing organizations** (migration `007_optional_mfa.sql`). Existing enrolled users keep two-factor.
- (Superseded: the always-required rule for platform staff and admins was removed on 2026-10-17, see above.)
- Without two-factor nobody can approve STRs, export cases, change the screening policy or override screenings.
- Turning two-factor on ends every password-only session and starts a two-factor session; refreshing a password-only
  session never upgrades it. Admin "reset two-factor" now turns it off and the user is prompted at next sign-in
  (it used to send a new invitation).
- Keycloak sign-in is unchanged: Keycloak's realm policy decides two-factor for those users.

## Fixed

| Problem | Fix | Check |
|---|---|---|
| `/me/sessions` read the refresh cookie, which is scoped to `/auth` and never sent to `/me`: no session was ever "current", and "end other sessions" also ended the caller's own session | Access tokens carry the session (refresh-token family) as a signed `sid` claim; `/me/sessions` and `/me/sessions/end-others` use it. End-others with no `sid` is a 409 instead of ending everything | `security_e2e` (2 new checks) |
| No `.dockerignore`: `docker build` copied `.env` (database passwords, data keys, signing key) into the image | `.dockerignore` excludes `.env*`, keys, `.venv`, data, tests, frontend | — |
| `db/init/01_set_passwords.sh` pasted passwords into SQL: a `'` broke database init or injected SQL | Passwords passed as psql variables and quoted with `:'var'` | first boot of a fresh volume |
| `scripts/seed.py --demo` refused only when `ENV=production` literally, though a missing `ENV` means production | Uses `config.ENV` | — |
| An empty `ENV=` counted as a non-production environment name | Empty or missing `ENV` means production | `cases_e2e` "production is the default" |
| `scripts/migrate.py` didn't read `.env`, so it couldn't run outside Docker | `load_dotenv()` | — |
| `tests/run_all.sh` dropped and recreated the development database `sentrail`, needed `psql`, and used whatever `python3` was on the PATH | Uses its own database `sentrail_test` (refuses `sentrail`), Python+psycopg instead of psql, the project `.venv` when present | — |
| `test_security_e2e.py` hard-coded the app role password `apppw`; the production-default check in `test_cases_e2e.py` was defeated by a developer's `.env` | Uses `DATABASE_URL`; blanks `ENV` and the signing key instead of removing them | — |
| Database connections took ~2 minutes on Windows | `.env.example` uses `127.0.0.1` (Docker publishes PostgreSQL on IPv4 only; `localhost` tried `::1` first) | — |

## Upgrading

- Run `python -m scripts.migrate` (applies `007_optional_mfa.sql`). Every organization becomes "two-factor optional";
  an org admin can make it mandatory again in Security settings (`PUT /admin/security {"mfa_required": true}`).
- `POST /auth/login` can now answer with an access token (`"mfa_enabled": false`) instead of an `mfa_token`.
  API clients that sign in with a password must handle both.
- Access tokens issued before this release have no `sid`: until they expire (10 minutes at most), "end other
  sessions" answers 409 and asks the user to sign in again.
- `tests/run_all.sh` now uses the `sentrail_test` database (override with `TEST_DB`).

# Changes in 0.3

This release fixes the issues found in the code review of 0.2. Every fix has a check in the test
suites, and the original 77 checks still pass. `./tests/run_all.sh` now runs 137 checks and fails
the build when any of them fails.

## Fixed

| # | Problem in 0.2 | Fix | Check |
|---|---|---|---|
| 1 | Alerts raised by `/screen` returned a 500 when opened, because the case view looked the ramp's customer up in the demo dataset | A case is scored from the organization's own transaction history when it has one, otherwise from the screening that raised it (`alerts.screening_id`) | `cases_e2e`: "an alert raised by screening opens" |
| 2 | If the OFAC download failed on first use, the list was never retried and transfers were released unchecked; it also never refreshed | OFAC reloads every 6 hours and keeps the last good copy if a reload fails. If it has never loaded, screening holds the transfer with a reason (`OFAC_REQUIRED=false` for an offline demo) | `detection_unit`, `cases_e2e` |
| 3 | The travel-rule and wallet-proof thresholds compared the coin amount with 1,000, so 0.5 BTC was released | Thresholds use the fiat value: stablecoins count 1:1, every other asset needs `fiat_value` from the ramp (400 without it) | `detection_unit`, `cases_e2e` |
| 4 | Decisions worked on any status, including filed STRs and non-existent alerts; STRs could be submitted for closed alerts | Alert lifecycle enforced in `db.py` with row locks and a status CHECK; 404 for unknown alerts, 409 for invalid moves | `cases_e2e` (6 checks) |
| 5 | A missing `ENV` meant dev: public `/docs` and invite links in API responses | Missing `ENV` means production; the API also refuses to start without a signing key outside dev | `cases_e2e`: "production is the default" |
| 6 | Every organization searched and scored the same shared demo dataset | Data is per organization (`data/orgs/<org_id>/`); the demo dataset is served only to `DEMO_DATA_ORG_ID` | `cases_e2e`: tenant isolation |
| 7 | No way to list or revoke API keys; `screening.override`, `data.export` and `assigned_to` had no endpoints | `GET/DELETE /admin/api-keys`, `POST /screenings/{id}/override` (held transfers only, once), `GET /cases/{id}/export` (with reason, audited), `POST /cases/{id}/assign` | `cases_e2e` |
| 8 | The organization idle timeout and platform maximum session length were stored but never enforced | Both are checked on every refresh; access tokens never outlive the idle window | `cases_e2e`: idle and 12-hour checks |
| 9 | `PUT /admin/security` with one field reset all the others to defaults | Only the fields sent change; the audit entry records what changed | `cases_e2e` |
| 10 | Wallet age came from the latest 200 transfers, so busy exchange wallets looked "first used today" (+35) | Connectors report whether the history is complete; age-based signals are skipped on partial history | `detection_unit` |
| 11 | The AI figure check let any number from 0 to 31 through | Dates are checked as whole dates; every other number must appear in the facts | `detection_unit` |
| 12 | In Keycloak mode an organization user's email got a different error than an unknown email; a 429 also revealed real accounts; anyone could lock the break-glass owner out | One 401 for every failure; lockout per (email, client IP) in `login_throttle`, applied to unknown emails too | `oidc_e2e`, `cases_e2e` |
| 13 | CORS didn't allow `DELETE`, so the browser couldn't end a session | `DELETE` allowed | `cases_e2e` |
| 14 | `/admin/audit?limit=-1` was a database error 500 | Validated (1–1000) | `cases_e2e` |
| 15 | `/auth/discover` didn't encode the email, so `a+b@x.ca` broke | URL-encoded | `cases_e2e` |
| 16 | `/screen` retries created duplicate alerts; rate limit was per IP | `client_ref` returns the stored answer (unique per organization, race-safe); limit is per API key | `cases_e2e` |
| 17 | `/upload` without a `timestamp` column was a 500; a second organization verifying a claimed SSO domain was a 500 | 400 with the missing columns; 409 for the domain | `cases_e2e` (upload) |
| 18 | Chain-data failures during screening were a 500 | The transfer is held with a reason | `detection_unit` |
| 19 | `tests/run_all.sh` always exited 0, and nothing tested `main.py` | Runner exits non-zero on any FAIL or crash; new `cases_e2e` and `detection_unit` suites | — |
| 20 | Chroma and Presidio loaded at import, so the read-only container couldn't start before the index existed | Both load on first use; `data/` is mounted as the one writable volume | — |

Smaller fixes:
- API keys stop working when the organization is suspended or loses screening from its plan.
- Activating a user who hasn't finished their invitation is refused.
- MFA reset for an unknown user is a 404.
- New organizations must use a data region the platform allows.
- A failed Keycloak setup email no longer leaves an orphan account in Keycloak.
- Overlapping Presidio detections no longer corrupt the masked text.
- Saving a screening policy creates the row if it's missing.

## Upgrading

Run `python -m scripts.migrate` (applies `006_review_fixes.sql`).

Ramps calling `/screen` for non-stablecoin assets must now send `fiat_value`, and should send `client_ref`.

If you use the demo dataset, set `DEMO_DATA_ORG_ID` in `.env`.

## Still open

These need decisions or infrastructure outside this codebase:
- **SSO enforcement and passkey-only staff.** `sso_enforced` and `platform_staff_passkey_only` are stored but not enforced by the API. They belong in Keycloak flows, or need an `identity_provider` / `amr` claim mapper that the API can check.
- **Data region.** `allowed_regions` is checked only when an organization is created; data isn't actually placed by region.
- **Graph "reported accounts".** In the demo, these come from the dataset's laundering labels, so graph scores are optimistic. A real deployment should use the organization's own filed STRs.
- **Blind-index key rotation.** The blind index key can't be rotated yet; data keys can.
- **Frontend.** `frontend/sentrail-prototype.html` is still a clickable mock that doesn't call the API.
- **Investigation speed.** `/cases/{id}/investigate` runs three LLM calls synchronously; a background job would suit long models better.
- **Not tested end to end here.** The Docker stack (Keycloak, OpenBao, Ollama) wasn't run. The tests use real PostgreSQL 16 with simulated Keycloak, chain APIs and OFAC list.
