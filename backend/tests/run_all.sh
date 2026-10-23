#!/bin/sh
# Run from backend/ (or anywhere: it changes into backend/ itself). Runs every suite on its own fresh, migrated database. Needs PostgreSQL with the roles from infra/postgres/init
# (docker compose up -d postgres). Works on Linux, macOS and Git Bash on Windows; no psql needed.
#   PG_SUPERUSER_URL=postgresql://postgres:...@127.0.0.1  OWNER_PASSWORD=...  APP_DB_PASSWORD=...  ./tests/run_all.sh
# Optional: PYTHON (default: .venv's python if present, else python3), TEST_DB (default: sentrail_test).
# The suites drop and recreate TEST_DB, so it must never be your development database.
# Exits non-zero if any check fails or any suite crashes, so CI goes red.
set -e
cd "$(dirname "$0")/.."
TEST_DB=${TEST_DB:-sentrail_test}
[ "$TEST_DB" = "sentrail" ] && { echo "TEST_DB must not be the development database 'sentrail'"; exit 2; }
if [ -z "$PYTHON" ]; then
  if [ -x .venv/bin/python ]; then PYTHON=.venv/bin/python
  elif [ -x .venv/Scripts/python.exe ]; then PYTHON=.venv/Scripts/python.exe
  elif [ -x ../.venv/bin/python ]; then PYTHON=../.venv/bin/python
  elif [ -x ../.venv/Scripts/python.exe ]; then PYTHON=../.venv/Scripts/python.exe
  else PYTHON=python3; fi
fi
OUT=${TMPDIR:-/tmp}
export SUPERUSER_DATABASE_URL="$PG_SUPERUSER_URL/$TEST_DB"     # tests use it to inspect raw rows
export PYTHONPATH=$(pwd) ENV=dev
export DATABASE_URL="postgresql://sentrail_app:${APP_DB_PASSWORD}@127.0.0.1:5432/$TEST_DB"
eval "$($PYTHON -m scripts.generate_keys | sed 's/^/export /')"
fresh() {
  $PYTHON - "$PG_SUPERUSER_URL/postgres" "$TEST_DB" <<'PY'
import sys, psycopg
from psycopg import sql
with psycopg.connect(sys.argv[1], autocommit=True) as c:
    c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(sys.argv[2])))
    c.execute(sql.SQL("CREATE DATABASE {} OWNER sentrail_owner").format(sql.Identifier(sys.argv[2])))
PY
  OWNER_DATABASE_URL="postgresql://sentrail_owner:${OWNER_PASSWORD}@127.0.0.1/$TEST_DB" $PYTHON -m scripts.migrate > /dev/null
}
status=0
$PYTHON tests/test_detection_unit.py > "$OUT/sentrail_detection_unit.full" 2>&1 || status=1
echo "== detection_unit"; echo "$(grep -c '^PASS' "$OUT/sentrail_detection_unit.full") passed"
grep '^FAIL' "$OUT/sentrail_detection_unit.full" && status=1
grep -q Traceback "$OUT/sentrail_detection_unit.full" && { tail -5 "$OUT/sentrail_detection_unit.full"; status=1; }
$PYTHON tests/test_logging_unit.py > "$OUT/sentrail_logging_unit.full" 2>&1 || status=1
echo "== logging_unit"; echo "$(grep -c '^PASS' "$OUT/sentrail_logging_unit.full") passed"
grep '^FAIL' "$OUT/sentrail_logging_unit.full" && status=1
$PYTHON tests/test_llm_unit.py > "$OUT/sentrail_llm_unit.full" 2>&1 || status=1
echo "== llm_unit"; echo "$(grep -c '^PASS' "$OUT/sentrail_llm_unit.full") passed"
grep '^FAIL' "$OUT/sentrail_llm_unit.full" && status=1
$PYTHON tests/test_catalogue_unit.py > "$OUT/sentrail_catalogue_unit.full" 2>&1 || status=1
echo "== catalogue_unit"; echo "$(grep -c '^PASS' "$OUT/sentrail_catalogue_unit.full") passed"
grep '^FAIL' "$OUT/sentrail_catalogue_unit.full" && status=1
grep -q Traceback "$OUT/sentrail_catalogue_unit.full" && { tail -5 "$OUT/sentrail_catalogue_unit.full"; status=1; }
# migration 009 up/down on seeded data (builds and drops its own database, next to TEST_DB)
OWNER_PASSWORD="$OWNER_PASSWORD" $PYTHON tests/test_access_model_migration.py > "$OUT/sentrail_access_migration.full" 2>&1 || status=1
echo "== access_migration"; echo "$(grep -c '^PASS' "$OUT/sentrail_access_migration.full") passed"
grep '^FAIL' "$OUT/sentrail_access_migration.full" && status=1
grep -q Traceback "$OUT/sentrail_access_migration.full" && { tail -5 "$OUT/sentrail_access_migration.full"; status=1; }
for t in "security_e2e local" "oidc_e2e keycloak" "platform_e2e local" "cases_e2e local" "access_model_e2e local"; do
  set -- $t; fresh; echo "== $1"
  AUTH_MODE=$2 $PYTHON tests/test_$1.py > "$OUT/sentrail_$1.full" 2>&1 || status=1
  echo "$(grep -c '^PASS' "$OUT/sentrail_$1.full") passed"
  if grep -q '^FAIL' "$OUT/sentrail_$1.full"; then grep '^FAIL' "$OUT/sentrail_$1.full"; status=1; fi
  if grep -q Traceback "$OUT/sentrail_$1.full"; then tail -5 "$OUT/sentrail_$1.full"; status=1; fi
done
[ $status -eq 0 ] && echo "ALL SUITES PASSED" || echo "SOME CHECKS FAILED"
exit $status
