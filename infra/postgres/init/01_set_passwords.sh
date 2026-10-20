#!/bin/sh
# Set real passwords from the container environment (never commit them).
# Passed as psql variables and quoted with :'var', so any character in a password is safe.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d postgres \
     -v owner_pw="$SENTRAIL_OWNER_PASSWORD" -v keycloak_pw="$KEYCLOAK_DB_PASSWORD" <<'SQL'
ALTER ROLE sentrail_owner PASSWORD :'owner_pw';
ALTER ROLE keycloak PASSWORD :'keycloak_pw';
SQL
