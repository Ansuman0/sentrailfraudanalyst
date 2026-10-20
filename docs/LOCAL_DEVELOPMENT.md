# Local development

How to run Sentrail on your own machine: PostgreSQL in Docker, the Python API and the React app on the host.
Everything here was run and checked on Windows 11 (Git Bash); the same commands work on Linux and macOS
with `.venv/bin/python` in place of `.venv/Scripts/python`.

Layout: `backend/` (API, migrations, scripts, tests, `.venv`) and `frontend/` (web app) are separate services, each with its own
dependencies, Dockerfile and tests. Run Python commands from `backend/`, `npm` commands from `frontend/`, and `docker compose`
from the repository root, where `docker-compose.yml` and `.env` live.

| Part | Runs as | URL |
|---|---|---|
| React web app (Vite dev server) | `npm run dev` in `frontend/` | http://localhost:5173 |
| API (FastAPI + uvicorn) | `backend/.venv` on the host | http://localhost:8000 · Swagger UI at http://localhost:8000/docs (only when `ENV=dev`) |
| PostgreSQL 16 | `docker compose up -d postgres` | 127.0.0.1:5432 |
| Keycloak (optional) | `docker compose up -d keycloak` | http://localhost:8080 |
| Ollama (optional, AI drafts) | `docker compose up -d ollama` or a local install | http://localhost:11434 |

## Prerequisites

- **Python 3.11** (the Docker image uses 3.11; spaCy, Presidio and SHAP/numba lag behind newer Pythons).
  On Windows: `py install 3.11`.
- **Node.js 20+** and npm.
- **Docker Desktop** (or Docker Engine) for PostgreSQL.

## First-time setup

```bash
# 1. Backend environment
cd backend
py -V:3.11 -m venv .venv                      # Linux/macOS: python3.11 -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt

# 2. Secrets for local development (fills only the empty values in ../.env, creating it from ../.env.example)
.venv/Scripts/python -m scripts.dev_env

# 3. Database: creates the sentrail and keycloak databases and roles on first start
docker compose -f ../docker-compose.yml --project-directory .. up -d postgres
.venv/Scripts/python -m scripts.migrate       # schema, row-level security, app role password

# 4. Demo data: master login, platform team, two demo organizations with sample alerts
.venv/Scripts/python -m scripts.seed --demo > ../.dev-credentials.txt

# 5. Frontend
cd ../frontend && npm install && cp .env.example .env.local && cd ..
```

`backend/scripts/dev_env.py` refuses to run unless `ENV=dev` is in `.env`. It generates random database passwords,
Keycloak client secrets, demo passwords, the AES data key, the blind-index key and the Ed25519 signing key, and
prints only the names of the variables it filled in.

`.dev-credentials.txt` (git-ignored) holds the seed output: each demo user's TOTP enrollment URI and the master
login's recovery codes. The demo password is `SEED_DEMO_PASSWORD` in `.env`. Add a user's `otpauth://` URI to
an authenticator app (or paste the `secret=` value), then sign in with their email, the demo password and the
6-digit code.

### Sign-in mode

`AUTH_MODE=local` (what this guide uses): everyone signs in through the API with a password, plus a TOTP code once
they've turned two-factor on. After sign-in, users without two-factor see the setup screen: required for platform
staff, org admins, and everyone in an organization with `mfa_required` on (Security settings); otherwise
they can skip it. The seeded demo users already have two-factor on.
`AUTH_MODE=keycloak`: organization users sign in through Keycloak (`docker compose up -d keycloak`, then
re-seed); only platform staff keep the break-glass password login. See [IDENTITY.md](IDENTITY.md).

## Running

Two terminals:

```bash
cd backend && .venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

```bash
cd frontend && npm run dev
```

Open http://localhost:5173. Check the API with `curl http://127.0.0.1:8000/readyz` (it confirms the database
connection and shows the sanctions-list status).

## How the browser talks to the API

```
React app (localhost:5173) ──fetch, Authorization: Bearer <access token>──▶ API (localhost:8000) ──▶ PostgreSQL
                           ──POST /auth/refresh with HttpOnly cookie ─────▶
```

- The app calls the API on its own origin, `VITE_API_BASE_URL` (default `http://localhost:8000`). The API's
  CORS allows exactly `APP_URL` with credentials. Keep `APP_URL` in `.env` and the app's address identical.
- The access token is held in memory only. A page reload resumes the session by calling `/auth/refresh`,
  which reads the `sentrail_rt` cookie (HttpOnly, Secure, SameSite=Strict, path `/auth`). Browsers accept
  Secure cookies on `http://localhost`, so this works without TLS locally. In STG and production, serve the
  app and the API over HTTPS on the same site (for example `app.example.com` and `api.example.com`), or the
  SameSite=Strict cookie isn't sent.
- Refreshes are single-flight within a tab and across tabs (Web Locks). This matters: the API treats a
  refresh token presented twice as stolen and ends the whole session.

## Environments

| Setting | Development | Testing / STG | Production |
|---|---|---|---|
| `ENV` | `dev` (Swagger UI, invite links in responses, ephemeral signing key allowed) | unset or `production` | unset or `production` (an empty or missing `ENV` always means production) |
| `APP_URL` / `API_URL` | `http://localhost:5173` / `http://localhost:8000` | STG https URLs | production https URLs |
| `VITE_API_BASE_URL` (frontend build) | `http://localhost:8000` | STG API URL | production API URL |
| `DATABASE_URL` | `…@127.0.0.1:5432/sentrail?sslmode=prefer` | `sslmode=verify-full` | `sslmode=verify-full&sslrootcert=…` |
| Keys | `scripts.dev_env` / `scripts.generate_keys` | OpenBao transit | OpenBao transit (`BAO_ADDR`, `SENTRAIL_WRAPPED_KEYS`) |
| Demo seed | `--demo` allowed | `--demo` allowed with `ENV=dev` only | refused |

The frontend reads `VITE_API_BASE_URL` at build time: build once per environment (`VITE_API_BASE_URL=https://api.stg.example.com npm run build`).

## Tests

```bash
# Frontend: unit and component tests (Vitest + Testing Library), type check, production build
cd frontend && npm test && npm run typecheck && npm run build

# Backend: every suite on its own fresh database "sentrail_test" (never your dev database)
set -a; . ./.env; set +a
PG_SUPERUSER_URL="postgresql://postgres:${POSTGRES_SUPERUSER_PASSWORD}@127.0.0.1" \
OWNER_PASSWORD="$SENTRAIL_OWNER_PASSWORD" sh backend/tests/run_all.sh
```

The runner uses `backend/.venv`'s Python when it exists (override with `PYTHON=`), needs no `psql`, and exits
non-zero on any failed check. Don't run two copies at once: each suite drops and recreates `sentrail_test`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Every database connection takes about 2 minutes, then works | `localhost` resolves to IPv6 `::1` first; Docker publishes PostgreSQL on `127.0.0.1` only, and the `::1` attempt stalls until it times out | Use `127.0.0.1` in `DATABASE_URL` and `OWNER_DATABASE_URL` (the default in `.env.example`) |
| `pip install` fails on Python 3.13/3.14 | ML dependencies don't have wheels for the newest Python yet | Use Python 3.11 |
| `WinError 32 … being used by another process` during `pip install --upgrade pip` | Antivirus scanning the new venv; the half-upgraded pip is left broken | Delete `.venv`, recreate it, and install without upgrading pip first |
| `docker compose` says `POSTGRES_SUPERUSER_PASSWORD … missing a value` | `.env` still has the empty template values | `python -m scripts.dev_env` |
| Sign-in says "The Sentrail API can't be reached" on `https://sentrail.qatech.world` | The browser can't resolve `api.sentrail.qatech.world` (no hosts-file entry) or doesn't trust Caddy's local certificate; the API itself is fine | Run `scripts/add-hosts.ps1` as Administrator, then trust Caddy's root: `docker cp sentrail-caddy-1:/data/caddy/pki/authorities/local/root.crt .` and `certutil -user -addstore Root root.crt` (Firefox: import it in its own certificate settings). Restart the browser |
| Browser console: CORS error on every call | The app isn't on the address in `APP_URL` (for example `127.0.0.1:5173` vs `localhost:5173`) | Open the app at exactly `APP_URL`, or change `APP_URL` and restart the API |
| Signed out after every reload | The refresh cookie isn't reaching the API: app and API on different sites, or http on a non-localhost host | Same site and HTTPS outside localhost |
| Screening holds every transfer with "sanctions list couldn't be checked" | The OFAC list hasn't loaded (no internet) | Expected: screening fails closed. For an offline demo set `OFAC_REQUIRED=false` |
| "Draft with AI" fails | Ollama isn't running or the model isn't pulled | `docker compose up -d ollama` then `docker compose exec ollama ollama pull qwen2.5:14b` |
| Postgres init didn't set passwords after changing `.env` | `infra/postgres/init` runs only when the data volume is first created | `docker compose down -v` (deletes local data) and start again |
