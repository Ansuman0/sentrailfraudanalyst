"""Apply migrations/*.sql in order, once each, as the schema owner.
Usage: OWNER_DATABASE_URL=postgresql://sentrail_owner:...@host/sentrail python -m scripts.migrate
Also sets the app role's password from APP_DB_PASSWORD."""
import glob
import hashlib
import os
import sys
from pathlib import Path
import psycopg
from dotenv import load_dotenv

load_dotenv()                      # local runs read .env; in Docker the variables come from compose
url = os.environ["OWNER_DATABASE_URL"]
with psycopg.connect(url, autocommit=True) as conn:
    conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
                      version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())""")
    done = dict(conn.execute("SELECT version, checksum FROM schema_migrations").fetchall())
    for path in sorted(glob.glob(str(Path(__file__).resolve().parent.parent / "migrations" / "*.sql"))):
        version = os.path.basename(path)
        sql = open(path).read()
        checksum = hashlib.sha256(sql.encode()).hexdigest()
        if version in done:
            if done[version] != checksum:
                sys.exit(f"{version} was changed after it was applied. Add a new migration instead.")
            continue
        with conn.transaction():
            conn.execute(sql)
            conn.execute("INSERT INTO schema_migrations (version, checksum) VALUES (%s,%s)", (version, checksum))
        print(f"applied {version}")
    if os.environ.get("APP_DB_PASSWORD"):
        conn.execute(psycopg.sql.SQL("ALTER ROLE sentrail_app PASSWORD {}").format(psycopg.sql.Literal(os.environ["APP_DB_PASSWORD"])))
        print("app role password set")
print("database is up to date")
