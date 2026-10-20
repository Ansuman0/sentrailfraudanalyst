# Troubleshooting

The symptom → cause → fix table (slow DB connections, pip on new Python, CORS, signed out on reload, screening held,
"Draft with AI" failing, Postgres passwords not applied) is in
[LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md#troubleshooting). Open problems are tracked in
[memory/KNOWN_ISSUES.md](../memory/KNOWN_ISSUES.md).

Also: tests fail oddly or hang → another `backend/tests/run_all.sh` is running (they share `sentrail_test`); every user is
signed out after a restart with `ENV=dev` and no `SENTRAIL_JWT_PRIVATE_KEY` → an ephemeral signing key was used, run
`python -m scripts.dev_env`.
