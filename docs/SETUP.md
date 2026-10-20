# Setup

The full from-scratch walkthrough (prerequisites, venv, secrets, database, seed, frontend, running, tests,
troubleshooting) is [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md); it is the single source so the steps can't drift.

Quick path (Git Bash; use `.venv/bin/python` on Linux/macOS):

```bash
docker compose up -d postgres                       # from the repo root (compose, .env and docs live there)
cd backend                                          # Python commands run from backend/
py -V:3.11 -m venv .venv && .venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python -m scripts.dev_env             # writes ../.env
.venv/Scripts/python -m scripts.migrate
.venv/Scripts/python -m scripts.seed --demo > ../.dev-credentials.txt
(cd ../frontend && npm install && cp .env.example .env.local)
.venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload   # terminal 1
(cd ../frontend && npm run dev)                                                      # terminal 2
```

Then open http://localhost:5173. Related: [ENVIRONMENT_CONFIGURATION.md](ENVIRONMENT_CONFIGURATION.md),
[KEYS_AND_CREDENTIALS.md](KEYS_AND_CREDENTIALS.md), [DOCKER.md](DOCKER.md), [TESTING.md](TESTING.md), [AI.md](AI.md),
[OBSERVABILITY.md](OBSERVABILITY.md). Not yet available: a one-command `docker compose up --build` for the whole app (K-04).
