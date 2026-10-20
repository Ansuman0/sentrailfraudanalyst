# Testing

| Layer | Tool | Command | Count (2026-10-16) |
|---|---|---|---|
| Logging unit (request/trace IDs, scrubbing) | plain script, no database | `backend/tests/test_logging_unit.py` | 20 |
| LLM provider switch (stubbed HTTP) | plain script, no database | `backend/tests/test_llm_unit.py` | 9 |
| Detection unit | plain script | run by `backend/tests/run_all.sh` (`backend/tests/test_detection_unit.py`) | 20 |
| Security / API (auth, RLS, audit, crypto) | plain script, real PostgreSQL | `backend/tests/test_security_e2e.py` | 33 |
| OIDC (Keycloak simulated) | plain script | `backend/tests/test_oidc_e2e.py` | 20 |
| Platform console | plain script | `backend/tests/test_platform_e2e.py` | 27 |
| Cases, screening, STR, two-factor | plain script | `backend/tests/test_cases_e2e.py` | 78 |
| Frontend unit/component | Vitest + Testing Library | `cd frontend && npm test` | 24 |
| Types / build | tsc, Vite | `npm run typecheck`, `npm run build` | — |

Backend suites print `PASS`/`FAIL` lines; `backend/tests/run_all.sh` exits non-zero on any failure. Setup and the exact command
are in [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md#tests).

- Each suite drops and recreates database `sentrail_test`; the runner refuses `sentrail`. **Never run two runs at once.**
- Test data is created inside the suites with fake users and passwords; the seed (`backend/scripts/seed.py --demo`) is separate.
- Chain APIs, OFAC and Keycloak are simulated; no network is needed.
- Browser end-to-end checks (Playwright) have been done by hand; there is no committed E2E suite or load test. `.github/workflows/ci.yml` runs the frontend checks and the backend suites on push/PR (written, not yet run on GitHub; the directory isn't a git repository yet).
- Reports: none are written to disk; capture the console output if you need a record.
