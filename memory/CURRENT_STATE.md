# Current state

_Last updated: 2026-10-17 (docs/memory added; CI + web container written but never run; logging and correlation-id code changed). Verified today: logging unit 18, detection 20, frontend 24, tsc. NOT re-run since the logging change: the database suites (cases/security/oidc/platform) — Docker was off._

Open problems now live in [KNOWN_ISSUES.md](KNOWN_ISSUES.md); next planned work: first real run of CI and the web image (K-03, K-04),
then start the observability profile for the first time (K-01). Event logging and request/trace IDs are done (K-02 fixed).

## Two-factor (2026-10-17)

User's choice from My account (QR); only an org-level switch makes it mandatory. DB: `mfa_enabled`, `mfa_enabled_at`, CHECK. Tests: backend 207, frontend 57; not browser-checked.

## Layout (2026-10-17)

`backend/` (API, venv, tests), `frontend/`, `infra/`; root keeps `.env`, `docker-compose.yml`, docs, memory. Run Python from `backend/`.
Image builds (`api`, `web`) and CI have not been re-run since the move.

## Summary

Backend and React frontend run locally against PostgreSQL in Docker. All backend suites and frontend tests pass.
A browser end-to-end check (Playwright, Chromium) of the main analyst flow passed with no console errors.

| Part | Status |
|---|---|
| Backend (FastAPI, Python 3.11 venv) | Working. `/healthz`, `/readyz` OK on http://localhost:8000 |
| Frontend (React + Vite) | Working on http://localhost:5173; typecheck and production build clean |
| Database (PostgreSQL 16, Docker) | Working; migrations 001–006 applied; demo data seeded |
| Keycloak / OpenBao / Ollama | Not started in this environment (optional for local dev with `AUTH_MODE=local`) |

## Last successful local run (2026-10-16)

- `docker compose up -d postgres` → `scripts.migrate` → `scripts.seed --demo` → uvicorn :8000 → `npm run dev` :5173.
- Backend tests: detection_unit 20, security_e2e 33, oidc_e2e 20, platform_e2e 27, cases_e2e 60 — all pass (160).
- Frontend: 23 Vitest tests pass; `tsc` clean; `vite build` OK.
- Migration 007 (optional two-factor) applied to the dev database; both demo orgs are "optional"; the 11 existing
  users keep two-factor on.
- Browser E2E of two-factor: optional offer + skip + banner + turn on later; mandatory org blocks until set up.
- Browser E2E as the demo compliance officer: redirect to sign-in, password + TOTP sign-in, alert queue, case view,
  escalate decision, reload resumes session, account page marks exactly one current device, audit chain verifies,
  full card number search refused, no horizontal scroll at 390 px, sign-out revokes the refresh cookie.
  Two tabs reloading simultaneously (7 concurrent refreshes) keep the session.
- Browser E2E of invitation enrollment: admin invites → `/join#token` → name + password (policy message on a short one)
  → TOTP setup key → 8 recovery codes → new user signs in with a recovery code.

## Completed features

- All API features listed in the README (sign-in, MFA, tenants, roles, screening, cases, STR four-eyes, audit…).
- Two-factor: set up after sign-in; optional or mandatory per organization (`users.mfa_enabled`, `security_settings.mfa_required`).
- React app: sign-in (password + TOTP, recovery code, SSO hand-off), invitation enrollment, two-factor setup, alerts, case view + decisions, STR
  draft/submit/approve, search, wallet trace (table), screening policy, audit log + verify, account/sessions,
  platform organizations list.

## In progress / pending

- React admin screens: Users, Roles, Features, API keys and the two-factor switch are done (2026-10-17, tests only, not run against the live
  API). Platform plans screen and org plan selector are done. Platform security baseline screen is done. Still missing: platform roles and platform staff screens.
- Run the full Docker stack (Keycloak realm import, `AUTH_MODE=keycloak` seed, Ollama model) end to end.
- Initialize git and make the first commit (not done: not a git repository, and commits only on request).
- CI pipeline (none exists).

## Known issues

- None open from this session. Environment notes: Windows Defender can lock files in a fresh venv during
  `pip install --upgrade pip`; recreate the venv without upgrading pip.
- On 2026-10-16 another session or person was editing this working tree at the same time (an overlapping test run
  and a parallel edit to `backend/tests/test_security_e2e.py`). Don't run two copies of `backend/tests/run_all.sh` at once.

## Demo logins moved to sentrail.qatech.world (2026-10-17)

All seeded users (master + demo) use `<name>@sentrail.qatech.world`; demo org SSO enforcement removed so passwords work. `.dev-credentials.txt` now lists email + password. Sign-in page shows the new domain. **The dev DB still holds the old emails: needs `docker compose down -v` + migrate + seed --demo (Docker was off, not done).** Frontend 57 tests + tsc pass.

## Docker Desktop run on the domain (2026-10-17)

Stack runs via docker-compose.prod.yml + Caddyfile.local at https://sentrail.qatech.world (needs hosts-file entry, admin). DB recreated and demo-seeded with @sentrail.qatech.world users. Old localhost .env saved outside the repo as ../.env.bak-localhost. Not browser-checked.

## AWS pipeline (2026-10-18)

Written, never run (K-12): push to `main` deploys only the changed service (backend/frontend); manual run picks service + deploy / rollback / list-versions. Host state in `/opt/sentrail/versions`. Setup, DNS records and GitHub variables: [docs/DEPLOYMENT_AWS.md](../docs/DEPLOYMENT_AWS.md). Local sign-in error on the domain was a missing hosts-file entry (`scripts/add-hosts.ps1`, admin).

## GCP deployment files (2026-10-18)

Written, never run (K-13): `infra/gcp`, `docker-compose.gcp.yml`, `scripts/deploy-gcp.sh`, `.github/workflows/deploy-gcp.yml` (manual only), [docs/DEPLOYMENT_GCP.md](../docs/DEPLOYMENT_GCP.md). 8 GB VM, 30 GB disk. `ci.yml` restored. AWS: `terraform plan` OK (3 to add, 30 GB disk, m7i-flex.large), apply blocked/not run; AWS creds in git-ignored `aws_credentials.env`.



## Access model v2 work (2026-10-23)
Phase 2 (sign-in and session) is also done on the branch (see CHANGELOG). Phase 3 (authorization and isolation: actor-aware row-level security, restricted cases, read auditing, route check, isolation suite) is done too. Phase 4 (tenant lifecycle: pending/active/suspended/deleted, seats, delete with second-owner approval, admin recovery) is done on the branch as well. Phase 7 (job runner and worker container, dormant members, access reviews, signed audit export and streaming, export controls, anomaly alerts, SCIM, tenant data export and removal) is done too. Phase 5 (owner access sessions, second-owner approvals, break-glass, password change) is done on the branch too. Phase 6 (tenant SSO enforcement, passkeys, Tenant-admin two-factor, API-key hardening, every stored setting enforced) is done on the branch as well. Not yet run on the AWS host; the demo users there are unchanged.
Phase 0 and Phase 1 done locally on branch `access-v2/phase-1` (uncommitted until asked). Main and the AWS host are unchanged: pushing migration 009 to main would run it on the live database at the next deploy, so it waits for the Phase 9 cut-over. Next: Phase 2 (sign-in and session) after approval.

## Demo data on the AWS server (2026-10-23)
Seeded by the user's request with `seed --demo` run in the api container (ENV overridden for that one command; the server stays ENV=production). 2 demo orgs (Northwind Remit, Maple Ridge), 9 demo users (@sentrail.qatech.world), 3 alerts. AUTH_MODE=keycloak: demo users sign in via Keycloak (needs the domain, not the fallback URL) and set up TOTP on first sign-in. Password in git-ignored `.prod-credentials.txt`. To remove: delete both orgs by registration M23456789 / M24567810 + demo platform staff (roles ...0001/0003/0004), and delete the demo users in Keycloak; audit rows stay (append-only).

## AWS live state and fallback URL (2026-10-22)
Terraform applied (state in `infra/aws`), images in ECR, DNS at Namecheap resolves to the EIP. Instance had been stopped; restarted. Deployed 2026-10-22 (commit 2f444cc, all jobs green): domain, API, Keycloak, `https://44-196-164-178.sslip.io` (trusted) and the ec2 hostname (self-signed; Let's Encrypt refuses amazonaws.com) all answer 200. Boot service + swap installed; a real stop/start test is still to do. Browser sign-in not yet checked. Password sign-in works on the fallback; SSO (Keycloak) still uses the domain names. Developer PC hosts file must not map the domain to 127.0.0.1 when testing AWS.
## Consolidated Single Multi-Cloud Pipeline (2026-10-20)

- Merged CI testing, AWS deployment, and GCP deployment into a single all-in-one file: [`.github/workflows/deploy.yml`](file:///d:/AIworkspase/sentrail/sentrailfraudanalyst/.github/workflows/deploy.yml).
- Deleted `ci.yml`, `deploy-gcp.yml`, and `deploy-multicloud.yml`.
- Supports Pull Requests, automated push deployments to AWS on `main`/`master`, and manual multi-cloud operations (`aws`, `gcp`, or `all` clouds).
- Fully validated YAML syntax.
