# Observability

**Status:** structured JSON logs, request/trace IDs and event logging are in place and tested. The Loki + Grafana stack
(opt-in compose profile), dashboard and alert rules are **written but have never been started** (Docker was off when they
were created; see K-01). There are no Prometheus metrics and no OpenTelemetry traces (see "Not built").

## Architecture

```
React ──X-Request-ID, traceparent──▶ API ──JSON lines on stdout──▶ Docker
                                                                     │ (Alloy reads the Docker socket)
                          Grafana (dashboard + alerts) ◀── Loki ◀── Alloy
```

Dashboards and alerts are computed from log events with LogQL (`count_over_time`, `quantile_over_time … unwrap duration_ms`);
no separate metrics store is needed. Decision recorded in `memory/DECISIONS.md`.

## Start it

```bash
(cd backend && .venv/Scripts/python -m scripts.dev_env)   # fills GRAFANA_ADMIN_PASSWORD (and appends it to an older .env)
docker compose up -d                                       # the app
docker compose --profile observability up -d               # loki, alloy, grafana
```

Open http://localhost:3000, user `admin`, password = `GRAFANA_ADMIN_PASSWORD` in `.env` (never print or commit it).
Folder **Sentrail** → dashboard **Sentrail overview**. Loki is not published to the host. Only the `api` container's logs
are parsed; other containers' logs are shipped unparsed.
The API must run as the compose `api` service for Alloy to see it. If you run uvicorn on the host, read its stdout directly.

## Log format (`backend/app/logging_config.py`)

One JSON object per line: `ts`, `level`, `service`, `environment`, `logger`, `msg`, `request_id`, `trace_id` (set per request) and,
where relevant, `event`, `method`, `path`, `status_code`, `duration_ms`, `error_code`, `org_id`, `user_id`, `target_service`,
`operation`, `success`, `error_category`, `provider`, `model`, `input_chars`, `output_chars`, `error` (traceback).
Pass optional fields with `extra={...}`. Levels: INFO normal events, WARNING 4xx and failed external/AI calls, ERROR 5xx.

**Privacy.** Emails, 12–19 digit numbers, `Bearer` tokens and `sk_live_` keys are scrubbed from messages and tracebacks.
Request/response bodies, prompts and responses, query strings, raw URLs, wallet addresses, headers and IP addresses are never logged.
`path` is the route template (`/cases/{alert_id}`). External failures record only the exception class (`error_category`).

## Request and trace IDs

`X-Request-ID` is accepted if it is 8–64 characters of `[A-Za-z0-9._-]`, otherwise replaced. It is returned on every response
and written on every log line of the request. `trace_id` comes from a W3C `traceparent` header, else equals the request ID.
The React app sends both on every API call (same ids on the retry after a 401). To follow one request: enter its id in the
dashboard's "request / trace id" box, or `docker compose logs api | jq 'select(.request_id=="<id>")'`.

## Events (`event`)

| Event | Source | Notes |
|---|---|---|
| `api_request` | middleware | method, route, status, duration. Healthy `/healthz` and `/readyz` are DEBUG; a failing probe is ERROR |
| `audit_<action>` | `audit.write` | every audited action (`audit_login`, `audit_login_failed`, `audit_mfa_failed`, `audit_refresh_token_reuse_detected`, …). Ids only |
| `external_api_request` / `external_api_failure` | `backend/app/observability.py` | `target_service` trongrid, etherscan, mempool.space, ofac; duration; `error_category` |
| `ai_request_started` / `_completed` / `_failed` | `backend/app/agent/llm.py` | provider, model, input/output size, duration |

The audit log line is written inside the database transaction; if it later rolls back, the line remains.

## Dashboard "Sentrail overview"

Backend (requests/min, 4xx/5xx, p95 latency by route, failed sign-ins), External services (calls, failures, p95 latency per
service), AI (outcomes, p95 latency per model), and log panels (find a request, warnings and errors). Not shown because the
events don't exist yet: frontend errors, database slow queries/connection failures, token usage, AI fallback. Regenerate the
files with `python infra/observability/generate_grafana.py` from the repo root after editing it.

## Alerts (`infra/observability/grafana/provisioning/alerting/rules.yaml`)

| Alert | Condition | Severity | Meaning / action |
|---|---|---|---|
| API server errors | > 5 responses ≥ 500 in 5 min | critical | Server bug or dependency down. Find a 5xx `request_id`, read its lines |
| API latency high | p95 > 2 s for 5 min (excluding `/screen`) | warning | Check latency by route, external services, database |
| Readiness probe failing | any `/readyz` ≥ 400 in 5 min | critical | Database unreachable. `docker compose ps`, postgres logs, `DATABASE_URL` |
| External service failures | > 3 failures in 5 min | warning | Chain API or OFAC list down. Screening holds transfers by design while OFAC can't load |
| AI requests failing | > 3 failures in 10 min | warning | Ollama down or model missing |
| Sign-in failures spike | > 20 failed sign-ins/second-factor in 5 min | warning | Possible password guessing; review audit log |

**No contact point is configured**, so alerts show in Grafana (Alerting → Alert rules) but notify nobody. Add one
(email, Slack, …) in Grafana → Alerting → Contact points. "Unhealthy containers" is not alerted: container health isn't in the logs.

## Retention and storage

Loki keeps 7 days (`infra/observability/loki.yaml`, `retention_period: 168h`) in the `loki-data` volume; Grafana state in `grafana-data`.
`docker compose --profile observability down -v` deletes both.

## Security notes

- Only Grafana is published, on `127.0.0.1:3000`. Without `GRAFANA_ADMIN_PASSWORD` Grafana falls back to its
  default password: always run `scripts.dev_env` first.
- Alloy mounts `/var/run/docker.sock` read-only; the socket still exposes container metadata and logs and is root-equivalent
  in many setups. Treat the profile as development-only. In production ship stdout through your platform's log agent instead.
- Logs contain organization and user ids, which are personal-data-adjacent: restrict who can open Grafana.

## Troubleshooting

| Symptom | Check |
|---|---|
| Dashboard empty | `docker compose logs alloy loki`; is `api` running as a compose service (not on the host)? Time range |
| No `event`/`level` labels | Alloy parses only `compose_service="api"`; check the service name in `docker-compose.yml` |
| Alerts never fire | They treat "no data" as OK by design; check the query in Explore |
| Grafana won't start | `docker compose logs grafana`; a YAML error in `provisioning/` is reported there |

## Not built

Prometheus `/metrics`, OpenTelemetry traces, database operation and background-job events, frontend error reporting to the API,
token usage and AI fallback fields (the LLM client has no fallback), container health alerts.
