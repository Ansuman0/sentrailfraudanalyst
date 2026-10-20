# Decisions

Newest first. Don't reverse one without a stated reason and a new entry. Longer context is in
[PROJECT_MEMORY.md](PROJECT_MEMORY.md).

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
