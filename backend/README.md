# Sentrail backend (API service)

FastAPI on Python 3.11. Owns the database schema and every permission check.

```
backend/
  app/          API package: main.py + admin_api.py (routes), security/, services/, detection/, agent/, connectors/
  migrations/   NNN_*.sql, applied by scripts/migrate.py (never edit an applied file)
  scripts/      migrate, seed, dev_env, generate_keys, rotate_keys, train_and_score, doc generators
  tests/        plain-script suites; run_all.sh runs them on database sentrail_test
  data/         watchlist, per-organization datasets, model, RAG index (bind-mounted in Docker)
  Dockerfile    non-root image, read-only root filesystem when run by compose
```

Run everything from this directory. `.env` is read from the repository root (shared with `docker-compose.yml`).

```bash
py -V:3.11 -m venv .venv && .venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python -m scripts.dev_env && .venv/Scripts/python -m scripts.migrate
.venv/Scripts/python -m uvicorn app.main:app --port 8000 --reload
```

Full guide: [../docs/LOCAL_DEVELOPMENT.md](../docs/LOCAL_DEVELOPMENT.md).
