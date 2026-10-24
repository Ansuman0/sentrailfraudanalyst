"""Memberships are the only source of role and status (phase 9): one person in two organizations keeps working in one while suspended in the
other, an account with no active place left can't sign in, role changes follow the membership, and the cut-over check passes on a healthy
database. Real app, real database. Needs a fresh migrated database.
Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_members_e2e.py"""
import os
import subprocess
import sys
import pyotp
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from fastapi.testclient import TestClient
from app import pg
from app.access import catalogue as cat, members
from app.admin_api import provision_org
from app.main import app
from app.security.middleware import limiter
from helpers_access import CSRF, PW, add_user, bearer, claims, password_login, password_token, sql, two_factor_token

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)

with pg.tx(platform=True) as cur:
    A, ar = provision_org(cur, "Members A", "MSB", "M8300001", plan="professional")
    B, br = provision_org(cur, "Members B", "MSB", "M8300002", plan="professional")
sa, sb = pyotp.random_base32(), pyotp.random_base32()
admin_a = add_user(A, ar[cat.TENANT_ADMIN], "admin@members-a.example.com", secret=sa)
admin_b = add_user(B, br[cat.TENANT_ADMIN], "admin@members-b.example.com", secret=sb)
owner = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "owner@members.example.com")
ADMIN_A = bearer(two_factor_token(c, "admin@members-a.example.com", sa))
ADMIN_B = bearer(two_factor_token(c, "admin@members-b.example.com", sb))
shared = add_user(A, ar["Compliance analyst"], "shared@members.example.com")                 # homed in A ...
sql(SUPER, "INSERT INTO tenant_memberships (user_id, tenant_id, role_id, status) VALUES (%s,%s,%s,'active')", shared, B, br["Auditor (read-only)"])   # ... and in B
status = lambda uid, org: sql(SUPER, "SELECT status FROM tenant_memberships WHERE user_id=%s AND tenant_id=%s", uid, org)[0][0]
account = lambda uid: sql(SUPER, "SELECT status FROM users WHERE id=%s", uid)[0][0]

# =============================== the schema ===============================
ok(sql(SUPER, "SELECT count(*) FROM information_schema.columns WHERE table_name='users' AND column_name='role_id'")[0][0] == 0, "users has no role column")
ok(sql(SUPER, "SELECT to_regproc('users_sync_access_model') IS NULL")[0][0], "and no trigger copying one into the memberships")

# =============================== a person in two organizations ===============================
print("# two organizations")
r = password_login(c, "shared@members.example.com").json()
ok(r["route"] == "picker" and {t["name"] for t in r["tenants"]} == {"Members A", "Members B"}, "someone with two memberships gets the picker")
sw = c.post("/session/tenant", headers=bearer(r["access_token"]), json={"tenant_id": str(B)}).json()
TOK_B = bearer(sw["access_token"])
ok(c.get("/me", headers=TOK_B).json()["role"] == "Auditor (read-only)", "in B they have B's role")
sw = c.post("/session/tenant", headers=bearer(r["access_token"]), json={"tenant_id": str(A)})
TOK_A = bearer(sw.json()["access_token"]) if sw.status_code == 200 else None
r = password_login(c, "shared@members.example.com").json()
TOK_A = bearer(c.post("/session/tenant", headers=bearer(r["access_token"]), json={"tenant_id": str(A)}).json()["access_token"])
r = password_login(c, "shared@members.example.com").json()
TOK_B = bearer(c.post("/session/tenant", headers=bearer(r["access_token"]), json={"tenant_id": str(B)}).json()["access_token"])
ok(c.get("/me", headers=TOK_A).json()["role"] == "Compliance analyst" and c.get("/me", headers=TOK_B).json()["role"] == "Auditor (read-only)", "a different role in each")

print("# suspending in one organization")
ok(c.patch(f"/admin/users/{shared}", headers=ADMIN_B, json={"status": "suspended"}).status_code == 200, "B's admin suspends them")
ok(status(shared, B) == "suspended" and status(shared, A) == "active", "only B's membership is suspended")
ok(account(shared) == "active", "the account itself stays active: they still have a place")
ok(c.get("/me", headers=TOK_B).status_code == 401, "their session in B ends at once")
ok(c.get("/me", headers=TOK_A).status_code == 200, "their session in A is untouched")
r = password_login(c, "shared@members.example.com")
ok(r.status_code == 200 and {t["name"] for t in r.json()["tenants"]} == {"Members A"} or r.json().get("route") == "tenant", "signing in again offers only A")
ok(c.patch(f"/admin/users/{shared}", headers=ADMIN_B, json={"status": "active"}).status_code == 200 and status(shared, B) == "active", "B's admin reactivates them")

print("# suspending the last place")
ok(c.patch(f"/admin/users/{shared}", headers=ADMIN_B, json={"status": "suspended"}).status_code == 200 and c.patch(f"/admin/users/{shared}", headers=ADMIN_A, json={"status": "suspended"}).status_code == 200,
   "suspended in both organizations")
ok(account(shared) == "suspended", "now the account is suspended too")
ok(password_login(c, "shared@members.example.com").status_code == 401, "and they can't sign in at all")
ok(c.get("/me", headers=TOK_A).status_code == 401, "no session of theirs survives")
ok(c.patch(f"/admin/users/{shared}", headers=ADMIN_A, json={"status": "active"}).status_code == 200 and account(shared) == "active", "reactivating anywhere reactivates the account")
ok(password_login(c, "shared@members.example.com").status_code == 200, "and they can sign in again")

print("# roles follow the membership")
ok(c.patch(f"/admin/users/{shared}", headers=ADMIN_A, json={"role_id": str(ar["Compliance officer"])}).status_code == 200, "A's admin changes their role")
ok(sql(SUPER, "SELECT r.name FROM tenant_memberships m JOIN roles r ON r.id=m.role_id WHERE m.user_id=%s AND m.tenant_id=%s", shared, A)[0][0] == "Compliance officer"
   and sql(SUPER, "SELECT r.name FROM tenant_memberships m JOIN roles r ON r.id=m.role_id WHERE m.user_id=%s AND m.tenant_id=%s", shared, B)[0][0] == "Auditor (read-only)",
   "only A's membership changed")
ok(c.patch(f"/admin/users/{shared}", headers=ADMIN_B, json={"role_id": str(ar["Compliance officer"])}).status_code == 404, "B's admin can't give a role of A's (it doesn't exist in B)")
ok(c.patch(f"/admin/users/{admin_b}", headers=ADMIN_A, json={"status": "suspended"}).status_code == 404, "A's admin can't touch B's people")

print("# helper behaviour")
with pg.tx(A) as cur:
    ok(members.person_role(cur, shared, A)[1] == "active" and members.role_name(cur, shared, A) == "Compliance officer", "person_role and role_name read the membership")
    ok(members.holds_role(cur, shared, ar["Compliance officer"]) and not members.holds_role(cur, shared, ar["Auditor (read-only)"]), "holds_role knows who holds what")
    ok(shared in [str(u) for u in members.active_holders(cur, ar["Compliance officer"], A)], "active_holders lists the active holders")
ok(c.get("/platform/users", headers=bearer(password_token(c, "owner@members.example.com"))).status_code == 200, "platform staff read their role from platform_staff")

# =============================== the cut-over check ===============================
print("# cut-over check")
out = subprocess.run([sys.executable, "-m", "scripts.cutover_check"], capture_output=True, text=True, env=os.environ.copy(),
                     cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ok(out.returncode == 0 and "ALL CHECKS PASSED" in out.stdout, "scripts.cutover_check passes on a healthy database " + out.stdout[-300:].replace("\n", " | "))
with pg.tx(platform=True) as cur:
    cur.execute("UPDATE tenant_memberships SET status='suspended' WHERE tenant_id=%s AND role_id=%s", (A, ar[cat.TENANT_ADMIN]))
out = subprocess.run([sys.executable, "-m", "scripts.cutover_check"], capture_output=True, text=True, env=os.environ.copy(),
                     cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ok(out.returncode == 1 and "FAIL every active tenant has at least one active Tenant admin" in out.stdout, "and fails when an active organization has no active Tenant admin")
