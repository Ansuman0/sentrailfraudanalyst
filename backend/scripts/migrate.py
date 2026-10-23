"""Apply migrations/*.sql in order, once each, as the schema owner, then sync the permission catalogue.
Usage: OWNER_DATABASE_URL=postgresql://sentrail_owner:...@host/sentrail python -m scripts.migrate
         --to 008_mfa_flag_in_db.sql   stop after this migration (tests; no catalogue sync)
         --down                        revert the LAST applied migration with migrations/down/<same file name>
Also sets the app role's password from APP_DB_PASSWORD."""
import argparse
import glob
import hashlib
import os
import sys
from pathlib import Path
import psycopg
from dotenv import load_dotenv

load_dotenv()                      # local runs read .env; in Docker the variables come from compose

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"

ap = argparse.ArgumentParser()
ap.add_argument("--to", help="stop after this migration file")
ap.add_argument("--down", action="store_true", help="revert the last applied migration")
args = ap.parse_args()

url = os.environ["OWNER_DATABASE_URL"]
with psycopg.connect(url, autocommit=True) as conn:
    conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
                      version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())""")
    if args.down:
        row = conn.execute("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1").fetchone()
        if not row:
            sys.exit("nothing to revert")
        down = MIGRATIONS / "down" / row[0]
        if not down.exists():
            sys.exit(f"{row[0]} has no down migration ({down})")
        with conn.transaction():
            conn.execute(down.read_text())
            conn.execute("DELETE FROM schema_migrations WHERE version = %s", (row[0],))
        print(f"reverted {row[0]}")
        sys.exit(0)

    done = dict(conn.execute("SELECT version, checksum FROM schema_migrations").fetchall())
    for path in sorted(glob.glob(str(MIGRATIONS / "*.sql"))):
        version = os.path.basename(path)
        sql = open(path).read()
        checksum = hashlib.sha256(sql.encode()).hexdigest()
        if version in done:
            if done[version] != checksum:
                sys.exit(f"{version} was changed after it was applied. Add a new migration instead.")
        else:
            with conn.transaction():
                conn.execute(sql)
                conn.execute("INSERT INTO schema_migrations (version, checksum) VALUES (%s,%s)", (version, checksum))
            print(f"applied {version}")
        if args.to and version == args.to:
            print(f"stopped after {version}")
            sys.exit(0)
    from app.access import catalogue      # needs migration 009 (permission_aliases, step_up)
    result = catalogue.sync(conn)
    if any(result.values()):
        print(f"permission catalogue synced: {result}")
    if os.environ.get("APP_DB_PASSWORD"):
        conn.execute(psycopg.sql.SQL("ALTER ROLE sentrail_app PASSWORD {}").format(psycopg.sql.Literal(os.environ["APP_DB_PASSWORD"])))
        print("app role password set")
print("database is up to date")
