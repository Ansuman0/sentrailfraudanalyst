# Decisions

Newest first. Don't reverse one without a stated reason and a new entry. Longer context is in
[PROJECT_MEMORY.md](PROJECT_MEMORY.md).

## Decision: Access model v2 (memberships, one Platform owner, locked Tenant admin), built in phases behind `ACCESS_MODEL_V2`
Date: 2026-10-23 · Status: accepted (requested by the user; brief in the conversation, discovery in [docs/access-control-current-state.md](../docs/access-control-current-state.md))
Decision: Keep the physical `organizations`/`org_id` names ("tenant" in new tables, API and UI); two-factor mandatory for Tenant admins and passkey-only owners (supersedes "two-factor optional" for those roles, from Phase 2/6); Tenant admin holds every tenant permission; Platform owner holds an explicit generated list, not a literal `*`; identity data (email, name, phone, authenticator secret) is encrypted per user, case data stays per organization; a separate worker container will run scheduled jobs (Phase 7); migrations reach the AWS host only at the Phase 9 cut-over, after a test on a copy. One permission catalogue (`backend/app/access/catalogue.py`) generates seeds, sync and docs/permissions.md.
Reason: A person must belong to several tenants; platform staff must reach tenant data only through audited sessions; access rules need one reviewable source.
Alternatives: physical rename to tenant*; literal `*` permission; scheduler thread inside the API; applying migrations phase by phase on the live host.
Impact: Phase 1 (done on branch `access-v2/phase-1`, not merged to main): migration 009 + down, catalogue, memberships, per-user encryption. Pushing 009 to main would run it on the AWS database at the next deploy, so it waits for the cut-over.

## Decision: AWS deploy = GitHub OIDC → ECR → SSM Run Command on one EC2 host; backend and frontend versioned separately
Date: 2026-10-18 · Status: accepted (requested by the user: choose service in GitHub, rollback to previous version)
Decision: Images tagged with the commit SHA per service; host keeps a per-service history and `.deploy.env` tags; `.env` lives only in Secrets Manager; no SSH, no stored AWS keys; only `main` can deploy.
Reason: Matches the existing single-VM plan (Caddy + compose) with the least moving parts; services must be deployable and reversible independently.
Alternatives: ECS Fargate + ALB + RDS (more robust, more cost/work; the documented next step); SSH deploy (key management); building on the server.
Impact: Single host, short API downtime per deploy, rollback never reverts DB migrations.

## Decision: Logs-based observability (Loki + Grafana + Alloy), no Prometheus/OpenTelemetry yet
Date: 2026-10-17 · Status: accepted
Context: Needed dashboards and alerts for requests, errors, latency, external services and AI.
Decision: Emit structured events from the API and compute dashboards/alerts with LogQL. Opt-in compose profile `observability`.
Reason: One extra data store fewer; the events are needed for audit-style troubleshooting anyway. Alloy reads container logs via the Docker socket (read-only), accepted for dev only.
Alternatives: Prometheus `/metrics` + Grafana (add later if you need cheap long-range numbers or non-log signals); OTel collector; Loki Docker driver plugin.
Impact: Metrics are only as good as the events; retention is Loki's 7 days.

## Decision: Service-oriented repository layout: `backend/`, `frontend/`, `infra/`
Date: 2026-10-17 · Status: accepted (requested by the user; supersedes "keep the existing layout" of the same day)
Decision: Each deployable service owns its code, dependencies, Dockerfile and tests: `backend/` (FastAPI API: `app/`, `migrations/`,
`scripts/`, `tests/`, `data/`, `requirements.txt`, `Dockerfile`, `.venv`) and `frontend/` (React web app). Deployment-only files live
in `infra/` (`postgres/init`, `postgres/backup.sh`, `keycloak/`, `observability/`). `docker-compose.yml`, `.env`, `docs/`, `memory/`
stay at the repo root because compose and the backend both read the one `.env`.
Reason: Two independently built and deployed services; the Python package is still `app`, so no import changed.
Alternatives: Split the API into several Python services (auth, screening, cases, AI) — not done: one database schema with RLS and a
shared audit chain make that a redesign, not a move. The seams are `app/security`, `app/services`, `app/detection`, `app/agent`.
Impact: Python commands run from `backend/`, `npm` from `frontend/`, `docker compose` from the root. Paths in docs updated.
Historical changelog entries keep the old paths.

## Decision: Two-factor optional per organization
Date: 2026-10-16 · Status: accepted (requested by the user)
Decision: `security_settings.mfa_required` default false; always required for platform staff and admin-type
permissions; never skipped for `MFA_SENSITIVE_PERMS`. Lowers the default posture versus 0.3.

## Decision: Session identified by `sid` claim; refresh only through `services/http.ts`
Date: 2026-10-16 · Status: accepted
Reason: refresh tokens are single-use; a replay revokes the whole family. Cookie never reaches `/me/*`.

## Decision: Screening fails closed
Status: accepted. Unreachable chain data or OFAC list → `hold`.

## Decision: Plain-script backend tests on a throwaway DB (`sentrail_test`)
Status: accepted. No pytest migration planned; frontend uses Vitest.

## Decision: Phase 7 governance defaults (access model v2)
Status: accepted 2026-10-23 (approved with the brief's defaults). Separate `worker` container runs `python -m scripts.run_jobs --loop` (every 5 min, DB advisory lock). Dormant period 90 days (tenant range 30-365); review every 90 days, overdue after 30, reminded weekly; export link 15 min single use; exports 20 per person per hour, alert at 10; searches alert at 100 per hour; audit stream https-only with HMAC signature, off after 50 failures; SCIM covers users and groups, groups map to roles (never the locked Tenant admin role), deprovision = suspend and end sessions, never delete. Tenant data removal keeps the organization row as a tombstone and cuts the audit log only through `purge_tenant_audit` after retention.

## Decision: Phase 6 authentication defaults (access model v2)
Status: accepted 2026-10-23. Passkeys use py_webauthn; SAML is supported only through the Keycloak broker (`sso_protocol`), so the API has no SAML code. Owner passkey-only (`platform_staff_passkey_only`) defaults off so no owner is locked out before registering; each tenant gets one emergency admin login (password + passkey) when SSO is enforced. An API key being rotated keeps working 24 hours. Every column of `security_settings` / `platform_settings` must map to an enforcement proof in `test_settings_enforcement_e2e.py`.
