# Architecture memory

The actual current architecture. Update when it changes. Details: [PROJECT_MEMORY.md](PROJECT_MEMORY.md).

```
Browser: React 18 + TS (Vite)            frontend/   dev server :5173
   │  Authorization: Bearer <access token, in memory>;  refresh cookie sentrail_rt (path /auth)
   ▼
FastAPI (Python 3.11)                    backend/app/  :8000   /healthz /readyz
   │  middleware: security headers, X-Request-ID, slowapi rate limits
   │  backend/app/security: rbac, tokens (Ed25519 JWT), crypto (AES-256-GCM), audit hash chain, oidc, mfa
   │  backend/app/services + backend/app/detection (rules, XGBoost+SHAP, NetworkX) + backend/app/agent (LangGraph, RAG)
   ├──▶ PostgreSQL 16   (RLS via app.org_id; roles sentrail_owner / sentrail_app / sentrail_auth)
   ├──▶ Keycloak        (OIDC, only AUTH_MODE=keycloak)
   ├──▶ OpenBao         (transit key unwrap, production)
   ├──▶ Ollama          (local LLM for STR drafts / investigation)
   └──▶ TronGrid, Etherscan, mempool.space, OFAC list (screening, fails closed)

Logs: backend/app/logging_config.py → JSON on stdout (personal data scrubbed). No collector, Loki, Grafana,
metrics or tracing exist yet (see KNOWN_ISSUES K-01).
```

Docker (`docker-compose.yml`): postgres, migrate (one-shot), keycloak, openbao (dev mode), ollama, api
(read-only filesystem, non-root, `no-new-privileges`), web (nginx, frontend/Dockerfile). Services are built from `backend/` and `frontend/`; deployment files are in `infra/`.
Volumes: `pgdata`, `ollama`; `./backend/data` bind mount for datasets, model and Chroma index.

Request flow for screening: API key → `/screen` → rules + ML + graph (`scorer.combine`) → OFAC/chain checks →
`hold` on any failed check → alert → case work → STR (four-eyes) → audit chain.
