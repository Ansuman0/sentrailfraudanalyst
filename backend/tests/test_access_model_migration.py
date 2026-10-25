"""Access model v2, phase 1: migration 009 up and down on seeded data, and the permission catalogue sync.

Builds its own scratch database at migration 008 with users in every built-in role (plus custom roles), applies 009 and the catalogue
sync, checks that every user keeps their access except for the intended template changes, then reverts 009 and checks the old model
came back exactly, then applies it again. Needs the same environment as tests/run_all.sh (SUPERUSER_DATABASE_URL, OWNER_PASSWORD).
Run: PYTHONPATH=. python tests/test_access_model_migration.py"""
import os
import subprocess
import sys
import uuid
import psycopg
from psycopg import sql
from app.access import catalogue as cat

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)

SUPER = os.environ["SUPERUSER_DATABASE_URL"]                     # .../<test db>
BASE, TEST_DB = SUPER.rsplit("/", 1)
SCRATCH = TEST_DB + "_mig"
OWNER_URL = f"postgresql://sentrail_owner:{os.environ['OWNER_PASSWORD']}@" + BASE.split("@", 1)[1] + "/" + SCRATCH
SCRATCH_SUPER = BASE + "/" + SCRATCH

OLD_ADMIN = "00000000-0000-0000-0000-000000000001"
OWNER = cat.PLATFORM_OWNER_ROLE_ID


def migrate(*args):
    env = {**os.environ, "OWNER_DATABASE_URL": OWNER_URL}
    env.pop("APP_DB_PASSWORD", None)
    r = subprocess.run([sys.executable, "-m", "scripts.migrate", *args], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-800:], r.stderr[-1500:])
    return r


with psycopg.connect(BASE + "/postgres", autocommit=True) as admin:
    admin.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(SCRATCH)))
    admin.execute(sql.SQL("CREATE DATABASE {} OWNER sentrail_owner").format(sql.Identifier(SCRATCH)))

ok(migrate("--to", "008_mfa_flag_in_db.sql").returncode == 0, "scratch database migrated to 008 (the state before access model v2)")

s = psycopg.connect(SCRATCH_SUPER, autocommit=True)
q = lambda text, *p: s.execute(text, p).fetchall()


def add_user(org, role, label, status="active"):
    uid = uuid.uuid4()
    s.execute("""INSERT INTO users (id, org_id, role_id, email_enc, email_bidx, status, last_login_at)
                 VALUES (%s,%s,%s,%s,%s,%s, now())""", (uid, org, role, "x", os.urandom(32), status))
    return uid


# ---- seed the old model: two tenants with the four built-in roles, custom roles, platform staff ----
orgs = {}
for name in ("Northwind", "Maple"):
    oid = q("INSERT INTO organizations (legal_name, business_type, registration, slug, status) VALUES (%s,'MSB','M1',%s,'active') RETURNING id",
            name, name.lower())[0][0]
    orgs[name] = oid
    for (tname,) in q("SELECT name FROM role_templates WHERE scope='tenant'"):
        rid = q("INSERT INTO roles (org_id, name, is_system) VALUES (%s,%s,true) RETURNING id", oid, tname)[0][0]
        s.execute("INSERT INTO role_permissions SELECT %s, perm FROM role_template_permissions WHERE template=%s", (rid, tname))
    s.execute("INSERT INTO security_settings (org_id) VALUES (%s)", (oid,))
roles = {(o, n): r for r, o, n in q("SELECT id, org_id, name FROM roles WHERE org_id IS NOT NULL")}
nw = orgs["Northwind"]
custom_admin_like = q("INSERT INTO roles (org_id, name) VALUES (%s,'Onboarding lead') RETURNING id", nw)[0][0]
for p in ("users.manage", "cases.view"):
    s.execute("INSERT INTO role_permissions VALUES (%s,%s)", (custom_admin_like, p))
custom_plain = q("INSERT INTO roles (org_id, name) VALUES (%s,'Reader') RETURNING id", nw)[0][0]
s.execute("INSERT INTO role_permissions VALUES (%s,'cases.view')", (custom_plain,))

people = {}
for o, oid in orgs.items():
    for role in ("Organization admin", "Compliance officer", "Compliance analyst", "Auditor (read-only)"):
        people[f"{o}:{role}"] = add_user(oid, roles[(oid, role)], role)
people["Northwind:Onboarding lead"] = add_user(nw, custom_admin_like, "custom")
people["Northwind:Reader"] = add_user(nw, custom_plain, "custom")
people["Northwind:invited analyst"] = add_user(nw, roles[(nw, "Compliance analyst")], "inv", status="invited")
people["platform:owner"] = add_user(None, OWNER, "owner")
people["platform:admin"] = add_user(None, OLD_ADMIN, "admin")
people["platform:support"] = add_user(None, cat.PLATFORM_SUPPORT_ROLE_ID, "support")
people["platform:auditor"] = add_user(None, cat.PLATFORM_AUDITOR_ROLE_ID, "auditor")
people["platform:suspended admin"] = add_user(None, OLD_ADMIN, "adm2", status="suspended")


def effective():
    """What each person can do: from users.role_id while it exists (before migration 018), from the memberships after it."""
    if q("SELECT count(*) FROM information_schema.columns WHERE table_name='users' AND column_name='role_id'")[0][0]:
        rows = q("""SELECT u.id, COALESCE(array_agg(rp.perm) FILTER (WHERE rp.perm IS NOT NULL), '{}')
                    FROM users u LEFT JOIN role_permissions rp ON rp.role_id = u.role_id GROUP BY u.id""")
    else:
        rows = q("""SELECT u.id, COALESCE(array_agg(rp.perm) FILTER (WHERE rp.perm IS NOT NULL), '{}') FROM users u
                    LEFT JOIN LATERAL (SELECT role_id FROM tenant_memberships m WHERE m.user_id = u.id AND m.tenant_id = u.org_id
                                       UNION ALL SELECT role_id FROM platform_staff s WHERE s.user_id = u.id) x ON true
                    LEFT JOIN role_permissions rp ON rp.role_id = x.role_id GROUP BY u.id""")
    return {r[0]: set(r[1]) for r in rows}


before = effective()
role_name_before = dict(q("SELECT u.id, r.name FROM users u JOIN roles r ON r.id = u.role_id"))
users_before = q("SELECT id, org_id, role_id, status FROM users")

# ---- up ----
r = migrate()
ok(r.returncode == 0 and "applied 009_access_model_v2.sql" in r.stdout, "migration 009 applies on seeded data")
ok("permission catalogue synced" in r.stdout or "database is up to date" in r.stdout, "the catalogue sync runs after the migrations")
after = effective()
label = {v: k for k, v in people.items()}
rename = {"orgs.manage": "platform.tenants.manage"}
lost = {}
for uid, was in before.items():
    now = after[uid]
    gone = {p for p in was if rename.get(p, p) not in now}
    if gone:
        lost[label[uid]] = gone
ok(lost == {"Northwind:Compliance analyst": {"screening.override"}, "Maple:Compliance analyst": {"screening.override"},
            "Northwind:invited analyst": {"screening.override"}},
   f"every user keeps their access except the intended change (analysts lose screening.override): {lost}")
gains = {label[u]: sorted(after[u] - {rename.get(p, p) for p in before[u]}) for u in before if after[u] - {rename.get(p, p) for p in before[u]}}
print("INFO gains:", {k: len(v) for k, v in gains.items()})
ok(set(after[people["Northwind:Onboarding lead"]]) >= {"users.manage", "users.pii.reveal", "security.manage", "apikeys.manage", "cases.view"},
   "a custom role that held users.manage keeps email reveal, security settings and API keys")
ok("users.pii.reveal" not in after[people["Northwind:Reader"]], "a custom role without users.manage gains nothing")

# platform
ok(q("SELECT role_id FROM platform_staff WHERE user_id=%s", people["platform:admin"])[0][0] == uuid.UUID(OWNER), "existing Platform admins are now Platform owners")
ok(q("SELECT count(*) FROM roles WHERE id=%s", OLD_ADMIN)[0][0] == 0, "the Platform admin role is gone")
ok(set(after[people["platform:owner"]]) == set(cat.PLATFORM_PERMS), "Platform owner holds every platform permission")
ok(after[people["platform:support"]] == {"platform.support"} and after[people["platform:auditor"]] == {"platform.audit.view"},
   "support and auditor are unchanged")

# tenant admin
ta = q("SELECT id, is_locked, is_system FROM roles WHERE name='Tenant admin'")
ok(len(ta) == 2 and all(t[1] and t[2] for t in ta), "each tenant's Organization admin became a locked Tenant admin")
ok(all(set(after[people[f'{o}:Organization admin']]) == set(cat.TENANT_PERMS) for o in orgs), "Tenant admin holds every tenant permission")
ok(q("SELECT count(*) FROM roles WHERE name='Organization admin'")[0][0] == 0, "no Organization admin role remains")

# memberships
mem = {(r[0], r[1]): (r[2], r[3]) for r in q("SELECT user_id, tenant_id, role_id, status FROM tenant_memberships")}
tenant_users = [t for t in users_before if t[1] is not None]
ok(len(mem) == len(tenant_users) and all(mem[(u, o)] == (r, st) for u, o, r, st in tenant_users),
   "one membership per tenant user, with the same role and status they had")
staff = {r[0]: (r[1], r[2]) for r in q("SELECT user_id, role_id, status FROM platform_staff")}
pusers = [(u, r, st) for u, o, r, st in users_before if o is None]
ok(len(staff) == len(pusers) and all(staff[u] == (uuid.UUID(OWNER) if str(r) == OLD_ADMIN else r, st) for u, r, st in pusers),
   "one platform_staff row per platform user, same status and the same role (old Platform admins are owners)")
ok(q("SELECT invite_expires_at IS NULL FROM tenant_memberships WHERE user_id=%s", people["Northwind:Onboarding lead"])[0][0],
   "active memberships carry no invite expiry")

# the old model is gone: no users.role_id and no trigger copying it into the membership tables
ok(q("SELECT count(*) FROM information_schema.columns WHERE table_name='users' AND column_name='role_id'")[0][0] == 0
   and q("SELECT to_regproc('users_sync_access_model') IS NULL")[0][0], "users.role_id and the sync trigger are gone (migration 018)")
new_uid = q("SELECT user_id FROM tenant_memberships WHERE tenant_id=%s LIMIT 1", nw)[0][0]
try:
    s.execute("INSERT INTO tenant_memberships (user_id, tenant_id, role_id) VALUES (%s,%s,%s)", (new_uid, nw, roles[(nw, "Compliance officer")]))
    ok(False, "duplicate membership refused")
except psycopg.errors.UniqueViolation:
    ok(True, "a second membership for the same user and tenant is refused")

# locked Tenant admin role
admin_role = ta[0][0]
for stmt, params, what in [
        ("DELETE FROM role_permissions WHERE role_id=%s", (admin_role,), "its permissions can't be removed"),
        ("DELETE FROM roles WHERE id=%s", (admin_role,), "it can't be deleted"),
        ("UPDATE roles SET name='Boss' WHERE id=%s", (admin_role,), "it can't be renamed"),
        ("UPDATE roles SET is_locked=false WHERE id=%s", (admin_role,), "it can't be unlocked")]:
    try:
        s.execute(stmt, params)
        ok(False, f"Tenant admin: {what}")
    except psycopg.Error:
        ok(True, f"Tenant admin is locked: {what} (database trigger)")
ok(q("SELECT count(*) FROM role_permissions WHERE role_id=%s", admin_role)[0][0] == 19, "Tenant admin still holds all 19 tenant permissions")

# scope triggers still hold with the new permissions
try:
    s.execute("INSERT INTO role_permissions VALUES (%s,'platform.tenants.manage')", (roles[(nw, 'Compliance officer')],))
    ok(False, "tenant role + platform permission refused")
except psycopg.Error:
    ok(True, "a tenant role still can't hold a platform permission")
new_role = q("INSERT INTO roles (org_id, name) VALUES (%s,'Late custom') RETURNING scope", nw)[0][0]
platform_role = q("INSERT INTO roles (org_id, name) VALUES (NULL,'Late platform') RETURNING scope")[0][0]
ok((new_role, platform_role) == ("tenant", "platform"), "role scope is set from the organization automatically")

# tenants
try:
    s.execute("UPDATE organizations SET slug='renamed' WHERE id=%s", (nw,))
    ok(False, "slug immutable")
except psycopg.Error:
    ok(True, "a tenant slug can't be changed")
ok(q("SELECT owner_access, jurisdiction FROM organizations WHERE id=%s", nw)[0] == ("allow", "CA"), "tenants default to owner_access=allow")
s.execute("UPDATE organizations SET status='deleted', deleted_at=now() WHERE id=%s", (orgs["Maple"],))
ok(True, "tenant status 'deleted' is allowed")
s.execute("UPDATE organizations SET status='active', deleted_at=NULL WHERE id=%s", (orgs["Maple"],))

# approvals need two different people
try:
    s.execute("""INSERT INTO platform_approvals (action, requested_by, approved_by, expires_at)
                 VALUES ('tenant.delete', %s, %s, now() + interval '24 hours')""", (people["platform:owner"], people["platform:owner"]))
    ok(False, "self approval refused")
except psycopg.errors.CheckViolation:
    ok(True, "an approval by the same person who requested it is refused (database check)")

# catalogue == database
dbp = {r[0]: (r[1], r[2], r[3]) for r in q("SELECT key, scope, grp, step_up FROM permissions")}
ok(set(dbp) == {p.key for p in cat.PERMISSIONS} and all(dbp[p.key] == (p.scope, p.group, p.step_up) for p in cat.PERMISSIONS),
   "permissions table equals the catalogue (keys, scope, group, step-up)")
tp = {}
for t, p in q("SELECT template, perm FROM role_template_permissions"):
    tp.setdefault(t, set()).add(p)
ok(all(tp[t.name] == set(t.perms) for t in cat.TEMPLATES) and set(tp) == {t.name for t in cat.TEMPLATES},
   "role templates equal the catalogue")
ok(q("SELECT to_regclass('permission_aliases') IS NULL")[0][0] and q("SELECT count(*) FROM permissions WHERE key = ANY(%s)", list(cat.RETIRED_PERMISSIONS))[0][0] == 0,
   "there is no alias table and no retired permission")
with psycopg.connect(OWNER_URL, autocommit=True) as oc:
    ok(cat.sync(oc) == {"owner_added": 0, "tenant_admin_added": 0}, "catalogue sync is idempotent")
    try:
        s.execute("DELETE FROM role_permissions WHERE role_id=%s AND perm='platform.tenants.delete'", (OWNER,))
        ok(False, "the Platform owner role is locked in the database")
    except psycopg.Error:
        ok(True, "the Platform owner role is locked in the database too (migration 011)")
    with s.transaction():       # only the catalogue sync / tenant deletion set this switch; no API path does
        s.execute("SELECT set_config('app.role_sync', 'on', true)")
        s.execute("DELETE FROM role_permissions WHERE role_id=%s AND perm='platform.tenants.delete'", (OWNER,))
    sv = q("SELECT session_version FROM users WHERE id=%s", people["platform:owner"])[0][0]
    ok(cat.sync(oc)["owner_added"] == 1, "sync gives the Platform owner a missing platform permission back")
    ok(q("SELECT session_version FROM users WHERE id=%s", people["platform:owner"])[0][0] == sv + 1, "and ends the owner's sessions so they reload")

# ---- migration 010 (sessions and devices) ----
ok(q("SELECT count(*) FROM information_schema.columns WHERE table_name='refresh_tokens' AND column_name IN ('last_mfa_at','tenant_id','scope')")[0][0] == 3,
   "010 adds last_mfa_at, tenant_id and scope to refresh_tokens")
ok(q("SELECT to_regclass('user_devices') IS NOT NULL")[0][0], "010 adds user_devices")
m = q("SELECT tenant_name, role_name, status FROM membership_lookup(%s)", people["Northwind:Compliance officer"])
ok(m == [("Northwind", "Compliance officer", "active")], "membership_lookup answers without a tenant context")
ok(q("SELECT role_name FROM platform_staff_lookup(%s)", people["platform:admin"])[0][0] == cat.PLATFORM_OWNER, "platform_staff_lookup answers for platform users")
ok(q("SELECT status, session_version FROM session_user_lookup(%s)", people["platform:owner"])[0][0] == "active", "session_user_lookup answers for any user")

# ---- down ----
r = migrate("--down")
ok(r.returncode == 0 and "reverted 019_two_factor_for_admins_setting.sql" in r.stdout and q("SELECT count(*) FROM information_schema.columns WHERE table_name='platform_settings' AND column_name='require_two_factor_admins'")[0][0] == 0,
   "migration 019 reverts first")
r = migrate("--down")
ok(r.returncode == 0 and "reverted 018_drop_user_role_column.sql" in r.stdout and q("SELECT count(*) FROM information_schema.columns WHERE table_name='users' AND column_name='role_id'")[0][0] == 1
   and q("SELECT count(*) FROM users WHERE role_id IS NULL")[0][0] == 0, "migration 018 reverts first: users.role_id is back, filled from the memberships")
r = migrate("--down")
ok(r.returncode == 0 and "reverted 017_drop_permission_aliases.sql" in r.stdout and q("SELECT to_regclass('permission_aliases') IS NOT NULL")[0][0],
   "migration 017 reverts first: the alias table is back")
r = migrate("--down")
ok(r.returncode == 0 and "reverted 016_teams.sql" in r.stdout and q("SELECT to_regclass('teams') IS NULL")[0][0], "migration 016 reverts first")
r = migrate("--down")
ok(r.returncode == 0 and "reverted 015_governance_and_data_controls.sql" in r.stdout, "then migration 015")
ok(q("SELECT to_regclass('scim_tokens') IS NULL AND to_regclass('access_reviews') IS NULL")[0][0] and
   q("SELECT count(*) FROM information_schema.columns WHERE table_name='security_settings' AND column_name='dormant_days'")[0][0] == 0,
   "015's tables and columns are gone")
r = migrate("--down")
ok(r.returncode == 0 and "reverted 014_authentication_enforcement.sql" in r.stdout, "then migration 014")
ok(q("SELECT to_regclass('user_passkeys') IS NULL")[0][0] and q("SELECT count(*) FROM information_schema.columns WHERE table_name='api_keys' AND column_name='expires_at'")[0][0] == 0,
   "014's tables and columns are gone")
r = migrate("--down")
ok(r.returncode == 0 and "reverted 013_owner_access_and_break_glass.sql" in r.stdout, "then migration 013")
ok(q("SELECT count(*) FROM information_schema.columns WHERE table_name='users' AND column_name='break_glass'")[0][0] == 0, "013's columns are gone")
r = migrate("--down")
ok(r.returncode == 0 and "reverted 012_tenant_lifecycle.sql" in r.stdout, "then migration 012")
ok(q("SELECT count(*) FROM information_schema.columns WHERE table_name='users' AND column_name='mfa_mandatory'")[0][0] == 0, "012's columns are gone")
r = migrate("--down")
ok(r.returncode == 0 and "reverted 011_row_level_security_v2.sql" in r.stdout, "then migration 011")
r = migrate("--down")
ok(r.returncode == 0 and "reverted 010_sessions_and_devices.sql" in r.stdout, "then migration 010")
ok(q("SELECT to_regclass('user_devices') IS NULL")[0][0] and q("SELECT count(*) FROM information_schema.columns WHERE table_name='refresh_tokens' AND column_name='scope'")[0][0] == 0,
   "010's table and columns are gone")
r = migrate("--down")
ok(r.returncode == 0 and "reverted 009_access_model_v2.sql" in r.stdout, "migration 009 reverts")
back = effective()
ok(all(back[u] == before[u] for u in before), "after the revert every user has exactly the permissions they had before")
ok(role_name_before == dict(q("SELECT u.id, r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = ANY(%s)", list(before))),
   "and the same role names (Organization admin, Platform admin ...)")
ok(q("SELECT role_id FROM users WHERE id=%s", people["platform:admin"])[0][0] == uuid.UUID(OLD_ADMIN), "Platform admins are Platform admins again")
ok(all(q("SELECT to_regclass(%s) IS NULL", t)[0][0] for t in ("tenant_memberships", "platform_staff", "tenant_access_sessions",
                                                              "platform_approvals", "permission_aliases", "av2_backup_roles")),
   "the new tables and the snapshots are gone")
ok(q("SELECT count(*) FROM permissions WHERE key='orgs.manage'")[0][0] == 1 and q("SELECT count(*) FROM permissions WHERE key='security.manage'")[0][0] == 0,
   "old permission keys are back and new ones are gone")
ok(q("SELECT count(*) FROM information_schema.columns WHERE table_name='roles' AND column_name IN ('scope','is_locked')")[0][0] == 0,
   "roles columns removed")
ok(q("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1")[0][0] == "008_mfa_flag_in_db.sql", "schema_migrations is back at 008")

# ---- up again ----
r = migrate()
ok(r.returncode == 0 and "applied 009_access_model_v2.sql" in r.stdout and "applied 010_sessions_and_devices.sql" in r.stdout and "applied 011_row_level_security_v2.sql" in r.stdout and "applied 012_tenant_lifecycle.sql" in r.stdout and "applied 013_owner_access_and_break_glass.sql" in r.stdout and "applied 014_authentication_enforcement.sql" in r.stdout and "applied 015_governance_and_data_controls.sql" in r.stdout and "applied 016_teams.sql" in r.stdout and "applied 017_drop_permission_aliases.sql" in r.stdout and "applied 018_drop_user_role_column.sql" in r.stdout and "applied 019_two_factor_for_admins_setting.sql" in r.stdout, "migrations 009 to 019 apply again after a revert")
again = effective()
ok({k: v for k, v in again.items() if k in before and label[k] in lost} != {} and
   all(again[u] >= {rename.get(p, p) for p in before[u]} - lost.get(label[u], set()) for u in before),
   "the second application gives the same result")
ok(q("SELECT count(*) FROM tenant_memberships")[0][0] == q("SELECT count(*) FROM users WHERE org_id IS NOT NULL")[0][0],
   "memberships are rebuilt from the users table")

s.close()
with psycopg.connect(BASE + "/postgres", autocommit=True) as admin:
    admin.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(SCRATCH)))
