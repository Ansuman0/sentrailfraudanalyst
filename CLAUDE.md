# Working on Sentrail

Before any change, read `memory/PROJECT_MEMORY.md`, `memory/CURRENT_STATE.md`, `memory/CHANGELOG.md`
(plus `memory/KNOWN_ISSUES.md` and `memory/DECISIONS.md` when relevant),
then the relevant docs (`README.md`, `SECURITY.md`, `docs/`) and source.

After a meaningful change: run the tests, run the app and check the affected flow, then update
`memory/CHANGELOG.md` and `memory/CURRENT_STATE.md`, `memory/PROJECT_MEMORY.md` when an architecture or technical
decision changed, `CHANGES.md` for user-visible changes, and any affected docs. Skip memory updates for trivial edits.

- Two services: `backend/` (FastAPI, Python 3.11, `backend/.venv`; run Python commands from there) and `frontend/` (React + TypeScript,
  Vite). `infra/` holds Postgres init, Keycloak realm, observability. `.env` and `docker-compose.yml` stay at the root.
- Run and test: `docs/LOCAL_DEVELOPMENT.md`. Backend tests: `backend/tests/run_all.sh` (database `sentrail_test`; never run
  two at once). Frontend: `cd frontend && npm test && npm run typecheck`.
- The server enforces every permission; the UI only hides what a role can't use.
- Only `frontend/src/services/http.ts` may call `/auth/refresh` (refresh tokens are single-use).
- Never edit an applied migration; add a new `backend/migrations/NNN_*.sql`.
- Secrets live only in `.env` (git- and docker-ignored). Never print or commit them.
- Commits: Conventional Commits, only when asked.
