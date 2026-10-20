# Keys and credentials

Every secret lives only in `.env` (git- and docker-ignored). Never paste real values into docs, tickets or chat.
For local development, `python -m scripts.dev_env` fills every empty secret with a random value (requires `ENV=dev`).

| Variable | Required | Purpose | Generate / obtain | Rotate |
|---|---|---|---|---|
| `POSTGRES_SUPERUSER_PASSWORD` | Yes | Postgres `postgres` user, used by init and tests | `python -c "import secrets;print(secrets.token_urlsafe(32))"` | Change in DB, then `.env` |
| `SENTRAIL_OWNER_PASSWORD` | Yes | Schema owner; migrations only | same | same; rerun `scripts.migrate` |
| `APP_DB_PASSWORD` | Yes | `sentrail_app`, what the API uses | same | same; `scripts.migrate` sets it |
| `KEYCLOAK_DB_PASSWORD` | If Keycloak | Keycloak's database | same | same |
| `KEYCLOAK_CLIENT_SECRET`, `KEYCLOAK_ADMIN_CLIENT_SECRET` | If `AUTH_MODE=keycloak` | OIDC client secrets | same; must match the Keycloak client | Regenerate in Keycloak console and `.env` |
| `KEYCLOAK_ADMIN_USER` / `_PASSWORD` | If Keycloak | Keycloak console admin (not a Sentrail user) | Choose; strong password | Keycloak console |
| `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD` | Seed | Break-glass platform login | Choose a real mailbox you control; strong password | Change in app |
| `SEED_DEMO_PASSWORD` | Dev only | Demo tenants. Never in production | random | — |
| `SENTRAIL_DATA_KEYS` | Yes (dev) | AES-256-GCM key list `v1:<b64>[,v2:…]`, newest first | `python -m scripts.generate_keys` | Put new key first, restart, run `python -m scripts.rotate_keys`, drop old key at 0 remaining |
| `SENTRAIL_INDEX_KEY` | Yes (dev) | HMAC blind index for email lookup | `scripts.generate_keys` | **Not rotatable yet** (K-08) |
| `SENTRAIL_JWT_PRIVATE_KEY` | Yes (required in production) | Ed25519 token signing key (PEM, `\n` escaped) | `scripts.generate_keys` | Replace and restart; all sessions end |
| `BAO_ADDR`, `BAO_TOKEN`, `BAO_TRANSIT_KEY`, `SENTRAIL_WRAPPED_KEYS`, `SENTRAIL_WRAPPED_INDEX_KEY` | Production | Keys unwrapped through OpenBao transit instead of plain keys | Create the transit key in OpenBao; wrap the generated keys with it; give the token only transit decrypt permission | Rotate the transit key in OpenBao, rewrap |
| `GRAFANA_ADMIN_PASSWORD` | If observability profile | Grafana admin login | `scripts.dev_env`, or `python -c "import secrets;print(secrets.token_urlsafe(24))"` | Change in `.env`, then recreate the grafana container (or reset it in the Grafana UI: the stored password in `grafana-data` wins over the env var after first start) |
| `AI_API_KEY` | Only with a hosted or protected `openai_compatible` provider | Bearer key for the LLM server | Create in that provider's console with the narrowest scope (inference only); never reuse a personal key | Create a new key, update `.env`, restart the API, revoke the old one |
| `SMTP_HOST/PORT/USER/PASSWORD` | Optional | Invitation email | From your mail provider | Provider console |
| `ETHERSCAN_API_KEY` | Recommended | Ethereum chain lookups | Free key at etherscan.io (account → API Keys) | Etherscan console |
| `TRONGRID_API_KEY` | Recommended | Tron chain lookups | Key from trongrid.io | TronGrid console |
| `DEMO_DATA_ORG_ID` | Dev | Org that may see the IBM demo dataset | Set by seed output / admin | — |

Rules: never log or print these; never commit `.env`, `.dev-credentials.txt` or `*.pem`; the React app and its
`VITE_*` variables must never contain a secret. API keys issued to tenants (`sk_live_…`) are shown once and stored hashed.
Production keys come from OpenBao, not from `scripts.dev_env`.
