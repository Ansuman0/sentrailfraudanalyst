#!/bin/sh
# Encrypted nightly backup of both databases. Run from cron or a scheduled job.
# Uses age (open source) public-key encryption: the server can create backups but can't read them.
# Restore needs the private key, which is kept offline.
#   AGE_RECIPIENT=age1...  PGHOST=... PGUSER=postgres PGPASSWORD=...  BACKUP_DIR=/backups  ./infra/postgres/backup.sh
set -eu
stamp=$(date -u +%Y%m%dT%H%M%SZ)
for db in sentrail keycloak; do
  pg_dump --format=custom --no-owner "$db" | age -r "$AGE_RECIPIENT" > "$BACKUP_DIR/$db-$stamp.dump.age"
  sha256sum "$BACKUP_DIR/$db-$stamp.dump.age" > "$BACKUP_DIR/$db-$stamp.dump.age.sha256"
done
# keep 35 days locally; copy offsite (object storage with object lock) for the 5-year retention
find "$BACKUP_DIR" -name '*.age*' -mtime +35 -delete
echo "backup $stamp done"
# Restore test (do this monthly):
#   age -d -i key.txt sentrail-<stamp>.dump.age | pg_restore --dbname=sentrail_restore_test
