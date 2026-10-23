# Development changelog

Engineering log of meaningful changes, newest first. User-facing release notes: [../CHANGES.md](../CHANGES.md).

## 2026-10-23 — Access model v2, Phase 7 (governance and data controls) — branch `access-v2/phase-1`, NOT pushed to main

Migration `015_governance_and_data_controls.sql` (+ down): SCIM tables (`scim_tokens`, `scim_groups`, `scim_group_members`, `users.scim_external_id`), `access_reviews`/`access_review_items`, `audit_streams`, `export_links`, `user_countries`, `job_runs`, `tenant_memberships.reactivated_at`, six new `security_settings` columns (dormant_days, access_review_days, export_limit_per_hour, anomaly_searches_per_hour, anomaly_exports_per_hour, alert_new_country), Enterprise features `scim` and `audit_streaming` (org_features check widened), `scim_token_lookup`, `purge_tenant_audit` (owner-run, refuses unless the tenant is deleted and due). New `app/governance.py` (dormant sweep, review cycle, access review API for tenants and platform staff, signed audit export, single-use export links, streaming with SSRF checks, export guard + watermark, anomaly alerts, tenant data export and purge), `app/scim_api.py`, `app/jobs.py` + `scripts/run_jobs.py` (+ `worker` service in every compose file), `scripts/verify_audit_export.py`, `docs/soc2-access-evidence.md`. Hooks: case export (limit, watermark), search (anomaly), sign-in (new country, last activity).
Found by tests: a nested transaction that touched a row the login had just updated deadlocked (activity is now written in the login's own transaction); the new-country audit write deadlocked on the tenant's audit chain lock (now the same transaction, mail from a thread); access review sign-off must run as the system (a decision can remove the signer's own access); RLS hides other tenants' memberships inside a tenant scope, so shared people are handled from platform scope when a tenant is purged.
Tests: new `governance_e2e` (165), `scim_e2e` (80); settings suite maps the six new columns (36); migration test reverts 015 first; isolation runs the real jobs; routes doc regenerated.
Deviations: the worker is in compose from now on but must not start on AWS before the Phase 9 cut-over (migration 015 is not applied there); SSO is not yet an Enterprise-only feature (SCIM and audit streaming are); case export still answers inline (watermarked and rate limited) while audit and tenant exports use single-use links; new-country alerts need a trusted proxy header (no GeoIP database); SCIM manages only people homed in the tenant.

## 2026-10-23 — Access model v2, Phase 6 (authentication enforcement) — branch `access-v2/phase-1`, NOT pushed to main

Migration `014_authentication_enforcement.sql` (+ down): api_keys `expires_at/ip_allowlist/rate_limit_per_min/last_used_at`, passkey tables (`user_passkeys`, `webauthn_challenges`), `organizations.sso_default_role_id/sso_protocol`, `users.sso_emergency`, `sso_jit_lookup`, `platform_settings.passkeys_allowed/platform_staff_passkey_only` (default false), dropped `sso_enabled/oidc_issuer/oidc_client_id`. New `app/security/passkeys.py` + `app/passkey_api.py` (py_webauthn 2.8.0); `GET/PUT /admin/sso`, emergency account, just-in-time membership (`_jit_provision`), discover returns `enforced`; Tenant admins must use two-factor, owners must have a passkey when the platform setting is on; API-key expiry / IP / rate limit / rotation; `issue_access(factor=)` (amr `hwk`). Frontend: passkey register / sign-in / step-up, SetupPasskey page, SignIn calls discover first and redirects when SSO is enforced.
Tests: new `api_keys_e2e` 34, `passkeys_e2e` 55, `sso_e2e` 35, `settings_enforcement_e2e` 30 (every settings column mapped to a proof); frontend 79.
Deviations: passkey-only for owners defaults off (otherwise every owner is locked out until registering); SAML goes through the Keycloak broker (no SAML library in the API).

## 2026-10-23 — Access model v2, Phase 5 (owner access, approvals, break-glass) — branch `access-v2/phase-1`, NOT pushed to main

Migration `013_owner_access_and_break_glass.sql` (+ down): `users.break_glass/must_rotate/password_changed_at` (one sealed account, platform only), `organizations.legal_hold*`, access-session decision/legal-hold/expiry columns, one open session per owner and tenant, `refresh_tokens.access_session_id`. New `app/owner_access.py`: request / list / extend / end sessions, tenant approve/deny/end, legal-hold request; modes `allow` / `require_approval` / `deny`+legal hold; 60 min + one extension; lazy expiry (`expire_stale`, also via `rbac.access_session_ended_hook`). rbac: `asid` claim re-checked every request, owner acts as the tenant's locked Tenant admin role. `pg.tx(access_session=)` → `app.access_session` GUC → `audit.write` tags events and mirrors them into the platform chain. `POST /session/tenant` lets an owner into a tenant with a live session even with the flag off (and staff return to the console). Approvals generalised (`_request_approval`, `EXECUTORS`): tenant delete, legal hold, owner add, owner change, baseline loosening. `POST /me/password` (all users; ends all sessions; notifies), break-glass use alerts every owner and forces rotation (`ROTATE_MESSAGE`). `PUT /admin/security {owner_access}`; `/me` shows `access_session`; web app banner with End access; `scripts/create_break_glass.py`.
Tests: new `owner_access_e2e` (89); migration test reverts 013-009; logging unit fake updated; frontend 74.
Deviations: break-glass is password-only until Phase 6 (passkeys); expiry notices are lazy until Phase 7's job runner; no screen yet for Tenant admins to approve requests (API only; Phase 8).

## 2026-10-23 — Access model v2, Phase 4 (tenant lifecycle) — branch `access-v2/phase-1`, NOT pushed to main

Migration `012_tenant_lifecycle.sql` (+ down): `users.mfa_mandatory`, `organizations.status_reason/status_changed_at/deletion_due_at`, `platform_approvals.reason`. `POST /platform/orgs` now creates a `pending` tenant (validated permanent slug, baseline copied, audit in both logs, 72-hour first-admin invitation, or a membership for an existing account under the flag); acceptance activates the tenant and makes two-factor mandatory for the new Tenant admin (rbac reads `mfa_mandatory`); seat limits from the plan on invite and again on acceptance; `POST /platform/orgs/{id}/status` (suspend/reactivate, ends sessions, API keys refused, sign-in refused already at the password step in the old model); `POST /platform/orgs/{id}/delete` + `GET/approve/deny /platform/approvals` (second owner within 24 h, schedules data removal after retention); `POST /platform/orgs/{id}/admin` (replace a lost Tenant admin, both audit logs); support resend returns the dev link. Found while testing: provision_org must run without an actor (it writes the new tenant's own rows).
Tests: new `tenant_lifecycle_e2e` (70); migration test now reverts 012-009; routes doc regenerated; isolation suite covers the new routes.
Deviations: first-admin two-factor is enforced through a per-user flag (all Tenant admins become mandatory in Phase 6); deletion only schedules the data removal (the job is Phase 7); the worker container waits for Phase 7.

## 2026-10-23 — Access model v2, Phase 3 (authorization and isolation) — branch `access-v2/phase-1`, NOT pushed to main

Migration `011_row_level_security_v2.sql` (+ down): `pg.tx(..., actor=)` / `app.actor`; policies on 11 tenant tables + organizations + memberships + access sessions + platform tables now require an active membership (or live access session) via SECURITY DEFINER helpers (`actor_may_access`, `actor_is_platform`, `actor_has_perm`, `case_visible`, `alert_visible`, `screening_visible`, `customer_hidden`); a user always reaches their own `users` row (fixes K-14a); restricted cases (`alerts.restricted`, `case_access_grants`); Platform owner role locked; indexes for read auditing. Backend: every route must declare a permission (`app/access/routes.py`, checked at start-up and in CI, `docs/route-permissions.md` generated); routes moved to the new permission names (`security.manage`, `apikeys.manage`, `users.pii.reveal`, `platform.tenants.manage`) and owners are gated by `platform.owners.manage`; `PUT/GET/POST/DELETE /cases/{id}/restricted|access`; read auditing (`case_viewed`, `str_viewed`); `DELETE /me/sessions/{id}` answers 404 for a session that isn't yours (found by the isolation suite); rbac answers 401 (not 403) when a membership is gone. Frontend: new permission names, locked role read-only, "Restricted" badge, Reveal email needs `users.pii.reveal`.
Tests: new `routes_unit` 17, `authorization_e2e` 68, `isolation_e2e` 12 (54 routes x tenant A against tenant B, platform staff x 35 tenant routes, B unchanged, nothing in logs; negative control proves it fails when RLS is off); migration suite now reverts 011, 010, 009; all 14 backend suites pass with the flag off and on; frontend 72.
Deviations: defaults chosen for the open questions (restricted cases hidden from queue and search, one `case_viewed` per person per case per hour, build fails on an undeclared route); `refresh_tokens` and `recovery_codes` still have no RLS (C10, user-scoped queries only); no UI yet to restrict a case (API only; Phase 8); owner access sessions are only enforced in RLS (the routes come in Phase 5).

## 2026-10-23 — Access model v2, Phase 2 (sign-in and session) — branch `access-v2/phase-1`, NOT pushed to main

Migration `010_sessions_and_devices.sql` (+ down): `refresh_tokens.last_mfa_at/tenant_id/scope`, live-session index, `user_devices`, SECURITY DEFINER lookups `membership_lookup`, `platform_staff_lookup`, `session_user_lookup`. Backend: login routing (console/tenant/picker/no_access), `GET /me/tenants`, `POST /session/tenant`, `POST /session/step-up`, token claims (`tid scp prid asid lmfa`), step-up 401 `{"error":"step_up_required"}` (`rbac.StepUpRequired`, `install_handlers`), tenant-status check on every request, live-session check (sign-out/switch end access tokens at once), lockout 10/15 min per (account, IP) + progressive delay + account-wide cap 50, CSRF guard on refresh/logout, device cookie + notifications (`services/notify.py`), refresh now revokes and re-issues in ONE transaction, new audit action names. Frontend: tenant picker, no-access page, header switcher, step-up dialog, CSRF header, step-up retry in `http.ts`. Found by tests/browser: the Phase 1 sync trigger re-created a removed membership at the next login (fixed in 009, which was still unapplied outside dev).
Checks: backend 11 suites pass with the flag off and on (new `signin_session_e2e` 67); frontend 70; real Chromium run of picker, switcher, no-access, 2FA sign-in and step-up 14/14 (the only console errors are the expected 401s).
Deviations: the lock is per (account, IP) with a high account-wide cap (50), not a plain account lock, to keep an attacker from locking the owner out (existing rule); platform owners without two-factor are not challenged until phase 6; Keycloak/OIDC sign-in still routes by `users.org_id`.

## 2026-10-23 — Access model v2, Phase 1 (data model, catalogue, migration) — branch `access-v2/phase-1`, NOT pushed to main

Migration `009_access_model_v2.sql` (+ `migrations/down/009_access_model_v2.sql`, snapshots `av2_backup_*`): `tenant_memberships`, `platform_staff`, `tenant_access_sessions`, `platform_approvals`, `permission_aliases`; `roles.scope/is_locked`; `permissions.step_up`; organizations get `jurisdiction`, `owner_access`, `deleted_at`, status `deleted`, immutable slug; Platform admin merged into Platform owner; Organization admin -> locked Tenant admin with all 19 tenant permissions; `orgs.manage` renamed `platform.tenants.manage` with alias; users with `users.manage` also get `users.pii.reveal`, `security.manage`, `apikeys.manage`. Triggers keep memberships in step with `users` while the old model is live (only real role/status changes propagate: a login must not overwrite a membership; found by the new tests), and lock the Tenant admin role.
New: `app/access/catalogue.py` (single source; `sync()` run by `scripts/migrate.py`; generates `docs/permissions.md`), `app/access/cache.py` (permission cache keyed by user, session_version, role), `config.ACCESS_MODEL_V2` (rbac reads the role from memberships/platform_staff when on), per-user identity encryption in `crypto.py` (+ `scripts/reencrypt_identity.py`, reads both forms), `migrate.py --to / --down`.
Intended behaviour changes: analysts lose `screening.override`; Tenant admin gains all case permissions; old platform admins are owners; the roles screen no longer warns about the locked Tenant admin.
Tests: 4 new suites (`catalogue_unit` 27, `access_migration` 48, `access_model_e2e` 33) + existing suites updated; all pass with the flag off and on; frontend 60. CI runs both settings.

## 2026-10-23 — Access-control rebuild, Phase 0 (discovery only)

Wrote `docs/access-control-current-state.md` (no code or migration changes): where users/roles/sessions/2FA/SSO/API keys/plans/audit live, how RLS is set, every route with its permission, the scope trigger, status of G1–G20 and I1–I13, 14 conflicts/risks and 7 open questions. Awaiting the user's approval and answers before Phase 1. Biggest findings: per-organization encryption of user identity blocks multi-tenant users (C1); Tenant admin has no case permissions today but the target gives all (C3); owner access reverses the RLS "platform never sees case data" guarantee (C4); no job runner exists (C9). Not committed.

## 2026-10-23 — Single email+password sign-in; two-factor for demo users

User decision: no SSO button, one sign-in system, two-factor on for everyone except the owner (master) login. Sign-in page: removed "Continue with single sign-on". Backend: platform staff other than "Platform owner" now get `mfa_setup=required` (rbac.current_user); `seed --demo` sets `security_settings.mfa_required=true` for both demo orgs. Tests: backend 7 suites pass (platform_e2e +1 check), frontend 60. **Server still needs (blocked for the assistant, left to the user):** `AUTH_MODE=local` in the `sentrail/prod/env` secret + redeploy, then delete the old Keycloak-created demo users (orgs M23456789 / M24567810, platform staff roles …0001/0003/0004) and re-run `seed --demo` so they get local passwords. Until then demo users cannot sign in (Keycloak users are refused by the password form).

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
