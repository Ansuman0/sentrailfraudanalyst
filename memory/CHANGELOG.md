# Development changelog

Engineering log of meaningful changes, newest first. User-facing release notes: [../CHANGES.md](../CHANGES.md).

## 2026-10-22 — GitHub Actions cache: one backend + one frontend entry

Found 38 entries / 2.3 GB (Docker `type=gha` stores each layer as its own never-replaced entry; `setup-python` pip cache 859 MB; npm cache). `deploy.yml` build jobs (AWS and GCP) now use `type=local` Docker cache in `/tmp/buildx-{backend,frontend}`, restored with `actions/cache/restore` (prefix key), saved once per push as `buildx-<service>-<sha>`, then older caches are deleted with `gh cache delete` (build jobs need `actions: write`). The first run also deletes every legacy cache. AWS and GCP share the same two caches. Removed `cache: npm` / `cache: pip` from the test jobs (tests install dependencies from scratch: slower, but no extra cache entries). Not yet run on GitHub.

## 2026-10-22 — AWS public-hostname fallback; domain outage diagnosed

**Login "Too many attempts" on AWS.** Root cause: behind Caddy the API saw Caddy's container IP for every client, so the 5/min login limiter and the per-(email, IP) lockout were one shared bucket and audit IPs were wrong. Fix: `FORWARDED_ALLOW_IPS=*` on `api` in `docker-compose.prod.yml` (uvicorn then trusts Caddy's X-Forwarded-For; Caddy overwrites client-sent values). Master login seeded on the server (credentials in git-ignored `.prod-credentials.txt`). Server-side seed-demo / remove-demo / reset-lockout were given to the user as manual SSM steps (not run by the assistant).

**First deploy run (2026-10-22), two findings.** (1) `deploy.sh` bug: the workflow passes `API_TAG=""`/`WEB_TAG=""`, and Compose lets shell variables beat `--env-file`, so single-service deploys failed with "API_TAG is missing"; fixed by exporting the resolved tags (commit cbb100f). Second run: all jobs green incl. smoke test; boot service enabled, 2 GB swap active, root disk 47% used. (2) Let's Encrypt rejects `ec2-*.amazonaws.com` (rejectedIdentifier), so that fallback had no certificate; now `tls internal` there plus a trusted `<ip>.sslip.io` fallback (`SSLIP_HOST`).

**Stop/start survival (decided with the user: keep ONE 30 GB root disk, no second EBS volume, because free tier covers 30 GB EBS in total).** `scripts/deploy.sh` now also creates a 2 GB swap file and installs `/opt/sentrail/start.sh` + `sentrail.service` (enabled at boot, `up -d --pull never`, so no ECR login is needed). Takes effect on the next deploy run; not yet run on the host. Docker Desktop was quit locally.

**Diagnosis.** The AWS stack (EC2 `i-00dbe6361a3a8a0d7`, EIP 44.196.164.178, Namecheap A records for the 3 names, Let's Encrypt certs) was fine except the instance had been **stopped**; started it, web/API/Keycloak then answered 200 with valid certs. On the developer PC the Windows hosts file still mapped the 3 names to 127.0.0.1 (local Docker leftover), so the browser never reached AWS.

**Added**
- Caddy fallback site on the host's AWS public hostname (`FALLBACK_HOST`, read from IMDSv2 in `scripts/deploy.sh`, passed via `.deploy.env` and `docker-compose.prod.yml`): web at `/`, API at `/api/*` (prefix stripped, refresh cookie `Path=/auth` rewritten to `/api/auth`). Plain-HTTP requests for any other name (bare IP) redirect to it.
- `resolveApiBase()` in `frontend/src/services/http.ts`: on a host that is neither the app domain nor local, the API base becomes `<origin>/api`. +3 tests.
- Caddyfile validated and routing/cookie rewrite exercised with `caddy:2` in Docker; **not yet deployed**.

## 2026-10-20 — Consolidated Multi-Cloud Pipeline with Docker Hub & Auto-Rollback

**Added**
- Docker Hub integration in [`.github/workflows/deploy.yml`](file:///d:/AIworkspase/sentrail/sentrailfraudanalyst/.github/workflows/deploy.yml): logs into Docker Hub (`qaansuman`) using `secrets.DOCKERHUB_TOKEN` or `DOCKER_PASSWORD` and pushes immutable commit tags plus `:latest` (`qaansuman/sentrail-api` and `qaansuman/sentrail-web`).
- High compression for Docker images (`outputs: type=image,push=true,compression=gzip,compression-level=9,force-compression=true`) in Docker Buildx to minimize image sizes across cloud pulls.
- `docker-compose.dockerhub.yml` overlay for pulling microservice images directly from Docker Hub.
- Auto-recovery / crash rollback in `scripts/deploy.sh` and `scripts/deploy-gcp.sh`: if a deployed service crashes or fails health checks, it automatically reverts to the previous known good version without operator intervention.
- Automated Docker Hub tags listing in workflow summaries during `list-versions`.
- Optimized `backend/Dockerfile` layer cleanup (purging `__pycache__`, `.pyc`, and pip caches).

**Consolidated**
- Combined all CI, AWS deployment, and GCP deployment pipelines into **one single** unified GitHub Action workflow: [`.github/workflows/deploy.yml`](file:///d:/AIworkspase/sentrail/sentrailfraudanalyst/.github/workflows/deploy.yml).
- Removed redundant workflow files (`ci.yml`, `deploy-gcp.yml`, `deploy-multicloud.yml`).



## 2026-10-18 — GCP deployment files (Compute Engine, Artifact Registry, Secret Manager, WIF)

**Added** `infra/gcp/*.tf` (e2-standard-2 = 8 GB, 30 GB boot disk, static IP, IAP-only SSH, Artifact Registry, Secret Manager secret, daily snapshots, Workload Identity Federation limited to `main` of the repo), `docker-compose.gcp.yml`, `scripts/deploy-gcp.sh` (derived from deploy.sh; `gcloud` instead of `aws`), `.github/workflows/deploy-gcp.yml` (manual run only; deploys over IAP SSH), `docs/DEPLOYMENT_GCP.md`. Restored `.github/workflows/ci.yml` from git history (it was deleted in commit 369d7a5; the deploy workflow reuses it).
**Verified:** `terraform validate` and `fmt -check` clean (Terraform 1.16.6 installed with winget), `bash -n`, workflow YAML parses. **Not run** against GCP or GitHub (K-13).
Also: AWS `infra/aws/terraform.tfvars` set to `m7i-flex.large` + `root_volume_gb = 30`; `terraform plan` showed 3 to add; apply not run.

## 2026-10-18 — AWS deployment pipeline (GitHub Actions → ECR → EC2 via SSM), per-service deploy and rollback

**Added**
- `.github/workflows/deploy.yml`: `plan` (changed folders on push; service/action inputs on manual run; main only) → `test` (reuses ci.yml per service) →
  `build-backend` / `build-frontend` (push `sentrail-api`/`sentrail-web:<sha>` to ECR, OIDC role) → `deploy` (S3 bundle + SSM Run Command, smoke test).
  Actions: deploy, rollback (version empty = previous), list-versions (ECR).
- `scripts/deploy.sh` (runs on the host): per-service history `/opt/sentrail/versions/{api,web}`, `.env` pulled from Secrets Manager and sanity-checked,
  `.deploy.env` (ECR_REGISTRY, API_TAG, WEB_TAG), health waits, history recorded only after healthy.
- `docker-compose.aws.yml` (ECR images, named volume `api-data`), `infra/aws/` Terraform (EC2 t3.large + EIP, SG 80/443, ECR, S3, Secrets Manager, DLM snapshots, OIDC deploy role), `docs/DEPLOYMENT_AWS.md`.
**Changed**
- `ci.yml`: push to `main` no longer runs it (deploy.yml calls it); `run_backend`/`run_frontend` inputs; image build checks.
- `backend/Dockerfile`: creates `/srv/data` owned by `app` (a named volume copies that owner; the API runs as uid 10001 on a read-only root).
- `.gitignore`: Terraform state and tfvars.
**Verified**: YAML parse, `bash -n`, `docker compose config` merge (images, volume), version-history logic in a scratch directory. **Not run**: GitHub Actions, Terraform (not installed), AWS, jq (not installed locally).

## 2026-10-17 — Two-factor is the user's choice; QR setup; DB flag; sign-in errors

**Changed**
- `rbac.mfa_setup_state(org_requires, mfa_enabled, idp)`: "required" only when the org switched `mfa_required` on; platform staff and
  admin-permission holders are no longer forced (`MFA_ALWAYS_PERMS` removed). `MFA_SENSITIVE_PERMS` action gate kept.
- Migration 008: `users.mfa_enabled_at` + trigger `users_mfa_stamp` + CHECK `users_mfa_has_secret`. `/admin/users` returns `mfa_enabled_at`.
- `/auth/mfa` returns a clean 401 when the user is gone, suspended or has no two-factor (was an unhandled error).
- `create_platform_admin.py` (now loads `.env`) and `seed.py` create users with two-factor off.
- Web: `components/QrCode.tsx` (SVG from `qrcode@1.5.4`, no HTML injection), setup page shows the QR + typed key, "Not now"/"Cancel" return
  to My account; after-sign-in offer and banner removed (`mfaGate` is only "required"); My account has a Turn-on panel; sign-in maps
  401/422/429/5xx/network to plain messages.
- Dev data: `ansuman@qatech.io` (platform admin) had two-factor switched off; the dev database contains only that user.

**Tested** backend 207 (cases 78: +4 changed/new for forced rule, DB flag, sign-in errors), frontend 57, `tsc`. Browser pass not run.
**Not changed (flag)**: Keycloak mode still forces TOTP inside Keycloak (`keycloak_admin.SETUP_ACTIONS`, `oidc.TRUST_IDP_MFA`).

## 2026-10-17 — Repository restructured into `backend/`, `frontend/`, `infra/`

**Changed**
- Moved `app/ migrations/ scripts/ tests/ data/ requirements.txt Dockerfile .venv` into `backend/`; `db/init` → `infra/postgres/init`,
  `ops/backup.sh` → `infra/postgres/backup.sh`, `keycloak/` → `infra/keycloak/`, `ops/observability` → `infra/observability/`.
  Python package is still `app` (no import changed). `.env`, `docker-compose.yml`, `docs/`, `memory/` stay at the root.
- `docker-compose.yml`: `build: ./backend`, mounts `./backend/data`, `./infra/...`. CI runs the backend job in `backend/`.
- `scripts/dev_env.py` finds the root `.env`; `scripts/migrate.py` and `generate_grafana.py` locate files from `__file__`;
  `tests/run_all.sh` changes into `backend/` and also finds a root `.venv`. `.gitignore` data rules re-anchored to `backend/data/`.
- Docs, README, SECURITY, CLAUDE.md and memory updated to the new paths (older changelog entries keep the old ones).
- Added `backend/README.md`, `frontend/README.md`, `infra/README.md`.

**Tested** backend 189 (detection 20, logging 20, llm 9, security 33, oidc 20, platform 27, cases 60), frontend 51, `tsc`,
`docker compose config` (also with the observability profile). NOT run: Docker image builds and CI after the move.
## 2026-10-17 — Verification run (Docker available)

**Tested**
- Backend: all suites pass with the logging, audit-log and LLM changes: detection 20, logging 20, llm 9, security 33, oidc 20,
  platform 27, cases 60 (189). `scripts.dev_env` appended `GRAFANA_ADMIN_PASSWORD` to the older `.env` as designed.
- `web` image built and run: healthy, uid 101, CSP rendered from `API_URL`, `/alerts` falls back to the app (200), assets immutable.

**Fixed (found by running it)**
- `web`: with `read_only: true` the image's start-up step could not write `/etc/nginx/conf.d/default.conf`, so nginx started with no
  server and refused connections. Now `/etc/nginx/conf.d` is a tmpfs owned by uid 101 (`docker-compose.yml`).
- `web`: `Permissions-Policy` was missing on `/` (nginx drops server-level `add_header` inside a location that sets its own).

## 2026-10-17 — Platform security baseline screen

**Added**
- `pages/PlatformSecurity.tsx` (`/platform-security`, nav "Security baseline", needs `platform.security.manage`): edits the three
  floors (`min_password_len_floor` 12–64, `max_idle_timeout_min` 5–60, `retention_years_floor` 5–15) behind a confirmation that it
  applies to every organization (weaker ones are raised, stricter keep theirs); shows `tenants_checked` after saving.
- `PUT /platform/security` replaces the whole object and resets omitted fields to defaults, so the screen always sends the
  unedited values (`max_session_hours`, passkey flags, regions) back as loaded; a test pins this.
- Passkey flags are shown read-only and labelled not enforced (K-08). 2 tests (frontend 51/51, `tsc`, build OK). Not run against
  the live API.

## 2026-10-17 — Platform plans: Plans screen and organization plan selector

**Added**
- `pages/Plans.tsx` (`/plans`, nav "Plans" under Tenants; view with `orgs.manage` or `platform.plans.manage`, edit with
  `platform.plans.manage`): per-plan feature checkboxes, "Review change" then a confirmation naming how many organizations change
  and which features switch off (they stay off if re-added: the API only sets `in_plan`), then `PUT /platform/plans/{key}`.
- `pages/Organizations.tsx`: with `orgs.manage` the Plan column is a selector (starter / professional / enterprise, the values the
  API accepts); a change needs a confirmation (`PUT /platform/orgs/{id}/plan`); other staff see plain text.
- `utils/features.ts` (shared names and descriptions; `Features.tsx` now uses it), `Plan` type, `platform.*` calls.
- `pages/Platform.test.tsx`: 5 tests (frontend 49/49, `tsc`, build OK). Not run against the live API.

## 2026-10-17 — Company sign-in (SSO) screen

**Added**
- `pages/Sso.tsx` (`/sso`, nav "Company sign-in", needs `users.manage`): domain + Keycloak provider alias → `PUT /admin/sso`,
  shows the DNS TXT record once, "Check DNS record" → `POST /admin/sso/verify`; the API's messages are shown as written.
  Input is trimmed and lowercased, then checked in plain words before calling the API.
- `enforced` is always sent as `false` and not offered: the API stores it but doesn't enforce it (K-08).
- The API has no read endpoint for the SSO setup, so the screen can't show the current state; the DNS record is lost if you
  leave the page (saving again issues a new one). A `GET /admin/sso` would fix both (backend change, not made).
- 3 tests (frontend 44/44, `tsc`, build OK). Not run against the live API; the DNS check and Keycloak are untested here.

## 2026-10-17 — Security settings: timeout, password length, allowlist, retention

**Changed**
- `pages/Security.tsx` now edits `idle_timeout_min` (5–60), `min_password_len` (12–64), `retention_years` (5–15) and the network
  allowlist (one CIDR per line) besides the two-factor switch. Only changed fields are sent (`SecurityPatch`), so a stale form
  can't overwrite someone else's change; an emptied allowlist is sent as `[]`. The API stays the authority (platform floors,
  lock-out check) and its messages are shown. Company SSO setup is not on this screen yet.
- Tests: 2 new, 1 updated (the stub now behaves like the API: a read after a save returns the saved value). Frontend 41/41,
  `tsc`, build OK. Not run against the live API.

## 2026-10-17 — Users: reveal email and reset two-factor

**Added**
- On `/users`, per person (not yourself): "Reveal email" and "Reset two-factor" (only when they have it on). Each opens a form that
  requires a 5–500 character reason (the API records it in the audit log). A revealed email is shown in the form and removed on
  "Done"; the API's refusals (for example SSO users) are shown as written. 2 tests (frontend 39/39, `tsc`, build OK).
  Not run against the live API.

## 2026-10-17 — React Features screen, `refreshMe`

**Added**
- `pages/Features.tsx` (`/features`, needs `features.manage`): toggle each feature; ones outside the plan are locked. Names and
  one-line descriptions for the six features (screening, alerts, ai, trace, statements, export) are written in the page, not
  served by the API.
- `useAuth().refreshMe()`: re-reads `/me` after an admin change so the menu follows the features at once (a failed refresh keeps
  the session). 2 tests (frontend 37/37, `tsc` clean). Not run against the live API.

## 2026-10-17 — React Roles screen

**Added**
- `pages/Roles.tsx` (`/roles`, needs `roles.manage`): edit any role's permissions, create custom roles, show the API's
  separation-of-duties warnings. Your own role is read-only (the API refuses it too); built-in role names are fixed.
- `utils/permissions.ts`: labels for the 12 organization permissions (wording from `docs/ROLES.md`). Unknown permissions the API
  returns are still listed under their raw id so saving a role never silently drops them.
- 2 tests (frontend 35/35, `tsc` clean). Not run against the live API.

**Notes**
- The permission labels duplicate `docs/ROLES.md`; there is no API endpoint listing permissions. Adding `GET /admin/permissions`
  would remove the duplication (backend change, needs the database suites: not made while Docker is off).

## 2026-10-17 — React admin screens: Users, API keys, Security settings

**Added**
- `frontend/src/pages/Users.tsx` (list, invite with role, change role, suspend/reactivate; no controls on your own row),
  `ApiKeys.tsx` (create, key shown once from the mutation result only, revoke with confirmation), `Security.tsx` (two-factor
  required switch sends only `{mfa_required}`; other settings read-only). Routes `/users`, `/api-keys`, `/security`; nav group
  "Administer" (needs `users.manage`; API keys also needs the `screening` feature); admins without `cases.view` land on `/users`.
- `admin` calls in `services/sentrail.ts`, types in `types/api.ts`, `.sr-only` and `dl.panel` styles.
- `pages/Admin.test.tsx`: 9 tests (nav gating, invite payload, role/status patches, API error shown, roles-permission fallback,
  key shown once, revoke confirmation, security payload).

**Testing**
- Frontend 33/33 (was 24), `tsc` clean, `vite build` OK. NOT run against the live API or in a browser (no PostgreSQL: Docker off).

**Notes**
- A user admin without `roles.manage` cannot list roles (`GET /admin/roles` needs it), so inviting and role changes are disabled
  for them with an explanation. Consider letting `users.manage` read the role list (API change; not made).

## 2026-10-17 — LLM provider switch

**Added**
- `AI_PROVIDER` (`ollama` | `openai_compatible`), `AI_BASE_URL`, `AI_MODEL`, `AI_API_KEY`, `AI_ALLOW_EXTERNAL` in `app/config.py`
  and `.env.example`. `app/agent/llm.py` dispatches per provider; `settings()` validates at call time.
- Guard: an `AI_BASE_URL` that is not localhost/loopback/a bare service name is refused unless `AI_ALLOW_EXTERNAL=true`, and
  then must be https (case text, though masked, would leave the network).
- `tests/test_llm_unit.py` (9 checks, stubbed HTTP, no database), added to `tests/run_all.sh`.

**Changed**
- Defaults are unchanged: with no `AI_*` variables the client behaves as before (`OLLAMA_URL`, `OLLAMA_MODEL`).
- `ai_request_*` events now report the resolved provider and model. `docs/AI.md` rewritten.

**Testing**
- llm unit 9/9, logging unit 20/20. Not run against a real Ollama/vLLM/hosted server; database suites not re-run (Docker off).

## 2026-10-17 — Loki/Grafana/Alloy profile, dashboard, alerts (unverified)

**Added**
- Compose profile `observability`: `loki` 3.2.1 (7-day retention, not published), `alloy` v1.4.2 (Docker socket read-only),
  `grafana` 11.2.2 on 127.0.0.1:3000; configs in `ops/observability/`. Provisioned datasource, dashboard "Sentrail overview"
  (15 panels) and 6 alert rules, generated by `ops/observability/generate_grafana.py`.
- `GRAFANA_ADMIN_PASSWORD` in `.env.example`; `scripts/dev_env.py` fills it and now appends keys missing from an older `.env`.

**Fixed**
- A failing `/healthz` or `/readyz` was logged at DEBUG like a healthy one; now only healthy probes are DEBUG.

**Testing**
- logging unit 20/20; YAML/JSON syntax checks; `docker compose config` (with and without the profile) OK.
- NOT verified: containers never started, so Alloy's pipeline, LogQL queries and alert rules are untested against real data.
  Image tags and config schemas were written from knowledge of those versions, not checked by a run.

## 2026-10-17 — Event logging for audit, external calls and AI; frontend correlation headers

**Added**
- `app/observability.py`: `external_call` / `@observed` log `external_api_request` or `external_api_failure`
  (`target_service`, `operation`, `success`, `duration_ms`, `error_category` = exception class only). Applied to TronGrid,
  Etherscan, mempool.space and the OFAC list (`app/connectors/`).
- `app/agent/llm.py`: `ai_request_started/completed/failed` with provider, model, input/output size, duration; no text.
- `app/security/audit.py`: every audit write also logs `audit_<action>` (e.g. `audit_login_failed`) with org and user ids only
  (no detail, no IP).
- React `services/http.ts` sends `X-Request-ID` and W3C `traceparent` on every API call (same ids on the 401 retry).
- CORS now allows those request headers and exposes `X-Request-ID`.

**Changed**
- `JsonFormatter` serializes with `default=str` (UUIDs) and knows the new fields.

**Testing**
- logging unit 18/18 (was 10), detection 20/20, frontend 24/24 (+1), `tsc` clean, CORS preflight with the new headers returns 200.
- Database suites still not re-run (Docker off). `audit.write` gained a log line after the INSERT: run `tests/run_all.sh`.

**Notes**
- The audit log line is written inside the DB transaction; if the transaction later rolls back, the log line still exists.

## 2026-10-17 — Request/trace IDs in logs, `api_request` event

**Added**
- `app/logging_config.py`: `service`, `environment`, `request_id`, `trace_id` (contextvars) on every JSON log line; optional
  `event`, `method`, `path`, `status_code`, `duration_ms`, `error_code`.
- `app/security/middleware.py`: validates `X-Request-ID` (8–64 chars `[A-Za-z0-9._-]`, else a new one is generated), reads W3C
  `traceparent` for `trace_id` (else = request id), logs one `api_request` per request (route template as `path`, never the raw
  path/query; INFO <400, WARNING 4xx, ERROR 5xx; `/healthz` and `/readyz` at DEBUG).
- `tests/test_logging_unit.py` (10 checks, no database), added to `tests/run_all.sh`.

**Fixed**
- K-02: the request ID was returned in the header but never logged.

**Testing**
- logging unit 10/10; app imports and serves `/healthz` with the new middleware. The database suites were NOT re-run (Docker
  daemon off); the change touches only logging and the middleware, but run `tests/run_all.sh` before relying on it.

## 2026-10-17 — CI workflow and frontend container (unverified)

**Added**
- `.github/workflows/ci.yml` (frontend test/typecheck/build; backend suites on a compose PostgreSQL with throwaway secrets from `scripts.dev_env`).
- `frontend/Dockerfile`, `nginx.conf.template`, `.dockerignore`; compose service `web` (127.0.0.1:5173).

**Testing**
- `docker compose config` validates. The image was NOT built and the workflow NOT run (Docker daemon off; no git remote).
  First real run may need fixes (CSP vs. inline styles, spaCy model not installed in CI).

## 2026-10-17 — Documentation and memory completed (no code changes)

**Added**
- `memory/ARCHITECTURE_MEMORY.md`, `DECISIONS.md`, `KNOWN_ISSUES.md` (K-01…K-11).
- `docs/`: SETUP, ARCHITECTURE, ENVIRONMENT_CONFIGURATION, KEYS_AND_CREDENTIALS, API, TESTING, DOCKER, AI,
  OBSERVABILITY (states honestly what doesn't exist), TROUBLESHOOTING. SETUP/ARCHITECTURE/TROUBLESHOOTING link to
  existing docs instead of duplicating them.

**Found (not fixed)**
- `X-Request-ID` is echoed but never reaches log lines (K-02); no observability stack, CI, frontend container (K-01, K-03, K-04).

**Testing**
- Not run: documentation only. Facts were checked against `.env.example`, compose, Dockerfile and route decorators.

## 2026-10-16 — Two-factor set up after sign-in, optional per organization

**Added**
- `users.mfa_enabled` (migration 007); `POST /me/mfa/setup`, `POST /me/mfa/confirm`; `/me` returns `mfa_enabled`,
  `mfa_setup` ("required" | "optional" | null), `session_mfa`.
- React `/setup-2fa` screen (required: no way past it; optional: offered once after sign-in with "Skip for now"),
  reminder banner, two-factor status + "Turn on" in My account.
- 21 backend checks (cases_e2e) and 2 frontend tests for the new flow.

**Changed**
- `security_settings.mfa_required` default false, existing orgs set to false; trigger no longer forces it true.
- `rbac`: `signed_in_user` (any assurance) + `current_user` (blocks when setup is required) + sensitive-permission
  check in `require`. Refresh keeps the session's assurance (`refresh_tokens.auth_method`).
- `/invitations/accept` activates the account (no TOTP); `/invitations/verify` removed; `/join` page simplified.
- Admin `reset-mfa` (local mode) turns two-factor off instead of re-inviting.
- Seeds and test fixtures set `mfa_enabled=true` for users created with a TOTP secret.

**Fixed**
- Frontend tests leaked rendered DOM between tests (no auto-cleanup without Vitest globals): explicit cleanup.

**Testing**
- Backend 160/160 (detection 20, security 33, oidc 20, platform 27, cases 60). Frontend 23/23, tsc, build OK.
- Browser (Playwright): invite → /join → password sign-in → optional offer → skip → banner → turn on from My account
  → 8 recovery codes → next sign-in asks for a code; with the org set to mandatory: no skip, every URL lands on setup.

**Notes**
- User's choices: per-organization flag, optional by default, sensitive actions still need two-factor, setup after
  first login. This lowers the default security posture versus 0.3 (two-factor was mandatory for everyone).

## 2026-10-16 — Analysis, local run, React app, fixes

**Added**
- React + TypeScript frontend in `frontend/` (Vite 5, React Router 6, TanStack Query 5, Vitest) wired to the live API, including invitation enrollment at `/join`.
- `scripts/dev_env.py` (local secrets), `docs/LOCAL_DEVELOPMENT.md`, `memory/`, `.gitignore`, `.dockerignore`,
  `.gitattributes`, `frontend/.env.example`.
- Regression checks for current-session detection (`tests/test_security_e2e.py`).

**Changed**
- `tests/run_all.sh`: database `sentrail_test`, no psql, uses `.venv` Python, portable temp dir.
- `.env.example` / `tests/run_all.sh`: `127.0.0.1` instead of `localhost` for PostgreSQL.
- `app/config.py`: empty `ENV` means production. `scripts/migrate.py` loads `.env`.
- README, SECURITY.md (session rows), CHANGES.md (Unreleased 0.4), docker-compose header comment.
- Local `.env` filled with dev secrets and `AUTH_MODE=local`.

**Fixed**
- `/me/sessions` current-session detection and "end other sessions" ending the caller's own session (`sid` claim).
- `.env` would have been baked into the Docker image (no `.dockerignore`).
- SQL injection / breakage in `db/init/01_set_passwords.sh`.
- Demo seed guard on missing `ENV`; hard-coded app password in a test; `.env` leaking into a subprocess test.

**Testing**
- Backend 139 checks pass; frontend 21 tests pass; tsc and vite build clean; Playwright browser E2E pass.

**Notes**
- Python 3.11 installed via `py install 3.11` to match the Dockerfile (3.14 is the machine default).
- Not a git repository; nothing committed.

## 2026-10-17 - demo domain

- seed.py, dev_env.py: emails -> @sentrail.qatech.world; demo SSO off. SignIn.tsx: placeholder/hint. Not reseeded.
