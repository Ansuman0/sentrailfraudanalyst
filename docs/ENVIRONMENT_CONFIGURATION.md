# Environment configuration

The template is [`.env.example`](../.env.example) (commented per variable); secrets are covered in
[KEYS_AND_CREDENTIALS.md](KEYS_AND_CREDENTIALS.md). Frontend: `frontend/.env.example` (`VITE_API_BASE_URL`, build time).

| Variable | Required | Purpose | Dev example |
|---|---|---|---|
| `ENV` | Yes | `dev` or `production`. **Unset/empty = production** (no `/docs`, no invite links in responses, signing key required) | `dev` |
| `APP_URL` | Yes | Web app origin; the only CORS origin allowed | `http://localhost:5173` |
| `API_URL` | Yes | API origin (OIDC redirect URI) | `http://localhost:8000` |
| `AUTH_MODE` | Yes | `keycloak` or `local` | `local` |
| `DATABASE_URL` | Yes | API connection as `sentrail_app` (use `127.0.0.1`, not `localhost`, on Windows) | see `.env.example` |
| `OWNER_DATABASE_URL` | Migrations | Connection as `sentrail_owner` | see `.env.example` |
| `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_ADMIN_CLIENT_ID` | Keycloak mode | OIDC settings | `sentrail`, `sentrail-web`, `sentrail-admin` |
| `TRUST_IDP_MFA` | Keycloak mode | Keycloak enforces two-factor | `true` |
| `OLLAMA_URL`, `OLLAMA_MODEL` | AI drafts | Local LLM endpoint and model | `http://localhost:11434`, `qwen2.5:14b` |
| `AI_PROVIDER` | Optional | `ollama` (default) or `openai_compatible` ([AI.md](AI.md)) | `ollama` |
| `AI_BASE_URL`, `AI_MODEL` | `openai_compatible` | Server URL ending in `/v1`, and model name. `AI_MODEL` also overrides `OLLAMA_MODEL` | `http://localhost:8001/v1` |
| `AI_API_KEY` | If the server needs one | Server-side only | — |
| `AI_ALLOW_EXTERNAL` | Optional | `true` allows a provider outside this machine/network (https required). Default `false` | `false` |
| `DATA_DIR`, `CHROMA_PATH` | Optional | Dataset and RAG index locations | `data`, `backend/data/chroma` |
| `OFAC_REQUIRED` | Optional | `true` = hold transfers if the list can't load; `false` = offline demo | `true` |
| `RISK_LIST_TTL_SECONDS` | Optional | OFAC reload interval | `21600` |
| `SMTP_*`, `MAIL_FROM` | Optional | Email | — |
| `GRAFANA_ADMIN_PASSWORD` | Observability profile | Grafana `admin` password; empty falls back to Grafana's default, so always set it | filled by `scripts.dev_env` |
| `VITE_API_BASE_URL` | Frontend | API address baked into the build | `http://localhost:8000` |

Per-environment differences (development / STG / production) are in the table in
[LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md#environments).
