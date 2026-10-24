"""Check a database after the access model v2 migrations (009 to 018). Run it on the copy during the rehearsal and again right after the real
cut-over. Read-only. Exit status 0 = every check passed.

  DATABASE_URL=postgresql://sentrail_app:...@host/dbname python -m scripts.cutover_check
Needs the encryption key variables like the API does (it only counts and verifies; it prints no personal data).
"""
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()
from app import pg                                                      # noqa: E402
from app.access import catalogue as cat                                 # noqa: E402
from app.security import audit                                          # noqa: E402

failed = []


def check(ok: bool, msg: str, detail: str = ""):
    print(("PASS " if ok else "FAIL ") + msg + (f"  [{detail}]" if detail and not ok else ""))
    if not ok:
        failed.append(msg)


with pg.tx(platform=True) as cur:
    files = sorted(p.name for p in (Path(__file__).resolve().parent.parent / "migrations").glob("*.sql"))
    # schema_migrations belongs to the owner role; the app role can't read it, so look at what the migrations created instead
    cur.execute("SELECT to_regclass('teams') IS NOT NULL, to_regclass('permission_aliases') IS NULL")
    has_016, no_aliases = cur.fetchone()
    cur.execute("SELECT count(*) FROM information_schema.columns WHERE table_name='users' AND column_name='role_id'")
    role_col = cur.fetchone()[0]
    check(has_016 and no_aliases and role_col == 0, f"all {len(files)} migrations are applied (teams exist, aliases and users.role_id are gone)")

    cur.execute("""SELECT count(*) FROM users u WHERE u.org_id IS NOT NULL
                   AND NOT EXISTS (SELECT 1 FROM tenant_memberships m WHERE m.user_id = u.id AND m.tenant_id = u.org_id)""")
    n = cur.fetchone()[0]
    check(n == 0, "every tenant user has a membership in their home tenant", f"{n} without")
    cur.execute("SELECT count(*) FROM users u WHERE u.org_id IS NULL AND NOT EXISTS (SELECT 1 FROM platform_staff s WHERE s.user_id = u.id)")
    n = cur.fetchone()[0]
    check(n == 0, "every platform user has a platform_staff row", f"{n} without")
    cur.execute("""SELECT count(*) FROM users u WHERE u.status = 'active'
                   AND NOT EXISTS (SELECT 1 FROM tenant_memberships m WHERE m.user_id = u.id AND m.status = 'active')
                   AND NOT EXISTS (SELECT 1 FROM platform_staff s WHERE s.user_id = u.id AND s.status = 'active')""")
    n = cur.fetchone()[0]
    check(n == 0, "nobody is an active account with no active place (they would sign in to 'no access')", f"{n} found")

    cur.execute("""SELECT o.legal_name FROM organizations o WHERE o.status = 'active' AND NOT EXISTS (
                     SELECT 1 FROM tenant_memberships m JOIN roles r ON r.id = m.role_id
                     WHERE m.tenant_id = o.id AND m.status = 'active' AND r.is_locked)""")
    bad = [r[0] for r in cur.fetchall()]
    check(not bad, "every active tenant has at least one active Tenant admin", f"{len(bad)} tenants without")
    cur.execute("SELECT count(*) FROM platform_staff WHERE role_id = %s AND status = 'active'", (cat.PLATFORM_OWNER_ROLE_ID,))
    check(cur.fetchone()[0] >= 1, "there is at least one active Platform owner")
    cur.execute("SELECT count(*) FROM users WHERE break_glass")
    n = cur.fetchone()[0]
    check(n <= 1, "at most one break-glass account", f"{n}")

    cur.execute("SELECT count(*) FROM permissions WHERE key = ANY(%s)", (list(cat.RETIRED_PERMISSIONS),))
    check(cur.fetchone()[0] == 0, "no retired permission name is left")
    cur.execute("SELECT count(*) FROM roles WHERE name = ANY(%s)", (list(cat.RETIRED_ROLES),))
    check(cur.fetchone()[0] == 0, "no retired role (Platform admin, Organization admin) is left")
    cur.execute("""SELECT r.id FROM roles r WHERE r.is_locked AND r.scope = 'tenant'
                   AND (SELECT count(*) FROM role_permissions rp WHERE rp.role_id = r.id) <> %s""", (len(cat.TENANT_PERMS),))
    check(not cur.fetchall(), "every locked Tenant admin role holds every tenant permission")

    cur.execute("SELECT DISTINCT org_id FROM audit_events")
    chains = [r[0] for r in cur.fetchall()]
    broken = []
    for org in chains:
        cur.execute("SELECT seq, org_id, at, actor_id, actor_role, action, target, detail, ip, prev_hash, hash FROM audit_events "
                    "WHERE org_id IS NOT DISTINCT FROM %s ORDER BY seq", (org,))
        if not audit.verify_rows(cur.fetchall())["ok"]:
            broken.append(str(org))
    check(not broken, f"every audit chain verifies ({len(chains)} chains: the platform's and each tenant's)", ", ".join(broken))

    cur.execute("SELECT count(*) FROM organizations WHERE status = 'active'")
    print(f"INFO {cur.fetchone()[0]} active tenants")
    cur.execute("SELECT count(*) FROM tenant_memberships WHERE status = 'active'")
    print(f"INFO {cur.fetchone()[0]} active memberships")

print("ALL CHECKS PASSED" if not failed else f"{len(failed)} CHECK(S) FAILED")
sys.exit(1 if failed else 0)
