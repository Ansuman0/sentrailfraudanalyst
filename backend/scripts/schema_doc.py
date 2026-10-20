"""Regenerate the table reference in docs/DATABASE.md from a live, migrated database.
Usage: SUPERUSER_DATABASE_URL=... python -m scripts.schema_doc > docs/schema-tables.md"""
import os
import psycopg

with psycopg.connect(os.environ["SUPERUSER_DATABASE_URL"]) as c:
    tables = c.execute("""SELECT c.relname, c.relrowsecurity, obj_description(c.oid)
                          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                          WHERE n.nspname='public' AND c.relkind='r' ORDER BY c.relname""").fetchall()
    print("# Table reference\n\nGenerated from the database by `scripts/schema_doc.py`. RLS = row-level security on.\n")
    for name, rls, _ in tables:
        print(f"## {name}{'  (RLS)' if rls else ''}\n\n| Column | Type | Null | Default |\n|---|---|---|---|")
        for col, typ, nul, dflt in c.execute("""SELECT column_name, data_type, is_nullable, column_default
                                                FROM information_schema.columns WHERE table_schema='public' AND table_name=%s
                                                ORDER BY ordinal_position""", (name,)):
            d = (dflt or "").replace("|", "\\|")[:50]
            print(f"| `{col}` | {typ} | {'yes' if nul == 'YES' else 'no'} | {d} |")
        print()
