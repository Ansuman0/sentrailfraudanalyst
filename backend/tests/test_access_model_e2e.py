"""Access model v2, phase 1, end to end: the membership-based path behind ACCESS_MODEL_V2, permission aliases, the permission cache,
the locked Tenant admin role through the API, and per-user identity encryption (including the re-encryption script).
Needs a fresh migrated database. Run: PYTHONPATH=. AUTH_MODE=local python tests/test_access_model_e2e.py"""
import logging
import os
import subprocess
import sys
import psycopg
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.security.rbac import install_handlers
CSRF = {"X-Sentrail-CSRF": "1"}
from app import config, pg
from app.access import cache, catalogue as cat
from app.security import crypto, passwords
from app.security.middleware import limiter
import app.admin_api as api

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
app = FastAPI(); app.state.limiter = limiter; app.include_router(api.router); install_handlers(app); limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver")
PW = "violet harbour tram sixteen"


def add_user(org, role_id, email, status="active"):
    with pg.tx(org, platform=org is None) as cur:
        cur.execute("""INSERT INTO users (org_id, role_id, email_enc, email_bidx, name_enc, password_hash, mfa_enabled, status)
                       VALUES (%s,%s,%s,%s,%s,%s,false,%s) RETURNING id""",
                    (org, role_id, crypto.encrypt(email, org, "email"), crypto.blind_index(email),
                     crypto.encrypt(email.split("@")[0], org, "name"), passwords.hash_password(PW), status))
        return str(cur.fetchone()[0])


def login(email):
    r = c.post("/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


with pg.tx(platform=True) as cur:
    org, roles = api.provision_org(cur, "Access Test Org", "MSB", "M7000001")
    other, other_roles = api.provision_org(cur, "Other Org", "MSB", "M7000002")
officer_id = add_user(org, roles["Compliance officer"], "officer@access-check.example.com")
admin_id = add_user(org, roles[cat.TENANT_ADMIN], "admin@access-check.example.com")
owner_id = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "owner@access-check.example.com")
with psycopg.connect(SUPER, autocommit=True) as s:
    roles_by_name = {n: i for i, n in s.execute("SELECT id, name FROM roles WHERE org_id=%s", (org,)).fetchall()}
    ok(set(roles_by_name) == {cat.TENANT_ADMIN, "Compliance officer", "Compliance analyst", "Auditor (read-only)"},
       "a new tenant is provisioned with the v2 built-in roles")
    ok(s.execute("SELECT is_locked FROM roles WHERE id=%s", (roles[cat.TENANT_ADMIN],)).fetchone()[0], "provisioning creates the Tenant admin role locked")
    ok(set(r[0] for r in s.execute("SELECT perm FROM role_permissions WHERE role_id=%s", (roles[cat.TENANT_ADMIN],)).fetchall()) == set(cat.TENANT_PERMS),
       "provisioning gives the Tenant admin role every tenant permission")

# ---------------- flag off (old model) ----------------
config.ACCESS_MODEL_V2 = False
O = login("officer@access-check.example.com")
me = c.get("/me", headers=O).json()
ok(me["role"] == "Compliance officer" and "str.approve" in me["permissions"], "flag off: the role comes from users.role_id")

# ---------------- flag on (membership path) ----------------
config.ACCESS_MODEL_V2 = True
O = login("officer@access-check.example.com")
ok(c.get("/me", headers=O).json()["role"] == "Compliance officer", "flag on: the same user, role read from the tenant membership")
with psycopg.connect(SUPER, autocommit=True) as s:      # change ONLY the membership: users.role_id is untouched
    s.execute("UPDATE tenant_memberships SET role_id=%s WHERE user_id=%s", (roles_by_name["Auditor (read-only)"], officer_id))
    s.execute("UPDATE users SET session_version = session_version + 1 WHERE id=%s", (officer_id,))
ok(c.get("/me", headers=O).status_code == 401, "a membership change ends the old session (session_version bump)")
O = login("officer@access-check.example.com")
me = c.get("/me", headers=O).json()
ok(me["role"] == "Auditor (read-only)" and "str.approve" not in me["permissions"], "flag on: permissions follow the membership, not users.role_id")
config.ACCESS_MODEL_V2 = False
ok(c.get("/me", headers=login("officer@access-check.example.com")).json()["role"] == "Compliance officer",
   "flag off again: users.role_id is the source (both paths coexist)")
config.ACCESS_MODEL_V2 = True
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("UPDATE tenant_memberships SET status='suspended' WHERE user_id=%s", (officer_id,))
ok(c.get("/me", headers=O).status_code == 401, "flag on: a suspended membership blocks the session")
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("UPDATE tenant_memberships SET status='active', role_id=%s WHERE user_id=%s", (roles_by_name["Compliance officer"], officer_id))
ok(c.get("/me", headers=login("officer@access-check.example.com")).status_code == 200, "an active membership signs in again")
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("DELETE FROM tenant_memberships WHERE user_id=%s", (officer_id,))
ok(c.get("/me", headers=O).status_code == 401, "flag on: no membership in the session's tenant means no access")
config.ACCESS_MODEL_V2 = False

# ---------------- permission cache (I10) ----------------
cache.clear()
calls = []
loader = lambda: calls.append(1) or ("r", ["a"])
cache.get_or_load(("u", 1, "role", True), loader)
cache.get_or_load(("u", 1, "role", True), loader)
ok(len(calls) == 1, "the permission set is cached for the same user, session_version and role")
cache.get_or_load(("u", 2, "role", True), loader)
ok(len(calls) == 2, "a session_version bump is a different key, so a stale permission set can never be returned")
cache.get_or_load(("u", 1, "other-role", True), loader)
ok(len(calls) == 3, "a different role is a different key")
A = login("admin@access-check.example.com")
cache.clear()
c.get("/me", headers=A); hits = cache.stats["hits"]; c.get("/me", headers=A)
ok(cache.stats["hits"] == hits + 1, "repeated requests by the same session reuse the cached permission set")
# a role edit applies at once through session_version, never through a stale cache entry
custom = c.post("/admin/roles", headers=A, json={"name": "Readers", "perms": ["cases.view"]}).json()["id"]
reader_id = add_user(org, custom, "reader@access-check.example.com")
R = login("reader@access-check.example.com")
ok("cases.view" in c.get("/me", headers=R).json()["permissions"], "custom role: permission present")
r = c.put(f"/admin/roles/{custom}", headers=A, json={"name": "Readers", "perms": ["audit.view"]})
ok(r.status_code == 200 and c.get("/me", headers=R).status_code == 401, "editing a role ends its holders' sessions at once")
R = login("reader@access-check.example.com")
perms = c.get("/me", headers=R).json()["permissions"]
ok("audit.view" in perms and "cases.view" not in perms, "after the edit the new permission set is used, not the cached one")

# ---------------- aliases (G19) ----------------
records = []
class Capture(logging.Handler):
    def emit(self, record): records.append(record)
logging.getLogger("sentrail.access").addHandler(Capture()); logging.getLogger("sentrail.access").setLevel(logging.INFO)
OW = login("owner@access-check.example.com")
mine = c.get("/me", headers=OW).json()
ok("platform.tenants.manage" in mine["permissions"] and "orgs.manage" in mine["permissions"],
   "a Platform owner holds the new name and still shows the old alias until the cut-over")
records.clear()
r = c.get("/platform/orgs", headers=OW)
ok(r.status_code == 200 and any(getattr(x, "event", "") == "permission_alias_used" and getattr(x, "permission", "") == "orgs.manage" for x in records),
   "using the old name works and is logged as permission_alias_used")

# ---------------- locked Tenant admin through the API ----------------
lead = c.post("/admin/roles", headers=A, json={"name": "Role keeper", "perms": ["roles.manage", "users.manage"]}).json()["id"]
add_user(org, lead, "keeper@access-check.example.com")
K = login("keeper@access-check.example.com")
r = c.put(f"/admin/roles/{roles[cat.TENANT_ADMIN]}", headers=K, json={"name": cat.TENANT_ADMIN, "perms": ["users.manage"]})
ok(r.status_code == 409 and "locked" in r.json()["detail"], "another admin can't edit the locked Tenant admin role (409)")
listed = {r["name"]: r for r in c.get("/admin/roles", headers=K).json()["roles"]}
ok(listed[cat.TENANT_ADMIN]["locked"] and len(listed[cat.TENANT_ADMIN]["perms"]) == 19, "the roles list marks it locked with all 19 permissions")
warn = c.get("/admin/roles", headers=K).json()["warnings"]
ok(not any(cat.TENANT_ADMIN in w for w in warn), "the locked Tenant admin does not trigger the separation-of-duties warning")
ok(any("Role keeper" in w for w in warn) is False, "a custom role with users.manage but no case permissions does not either")
risky = c.post("/admin/roles", headers=K, json={"name": "Risky", "perms": ["users.manage", "cases.decide"]})
warn = c.get("/admin/roles", headers=K).json()["warnings"]
ok(any(w.startswith("Risky") for w in warn), "a custom role combining user admin with case decisions still triggers the warning")

# ---------------- identity encryption: per user, not per organization (C1) ----------------
tok = crypto.encrypt("pat@example.com", org, "email")
ok(crypto.decrypt(tok, other, "email") == "pat@example.com" and crypto.decrypt(tok, None, "email") == "pat@example.com",
   "identity data decrypts in any tenant context: it belongs to the person")
try:
    crypto.decrypt(crypto.encrypt("case text", org, "str"), other, "str")
    ok(False, "case data stays bound to its organization")
except Exception:
    ok(True, "case data (STR text) is still bound to its own organization")
legacy = crypto._seal("pat@example.com", crypto._legacy_aad(org, "email"))
ok(crypto.decrypt(legacy, org, "email") == "pat@example.com", "identity data written before v2 (organization-bound) still decrypts")
upgraded = crypto.reencrypt_identity(legacy, org, "email")
ok(upgraded and crypto.decrypt(upgraded, org, "email") == "pat@example.com" and crypto.reencrypt_identity(upgraded, org, "email") is None,
   "re-encryption upgrades a legacy value and is idempotent")
back = crypto.reencrypt_identity(upgraded, org, "email", down=True)
ok(back and crypto._open(back, crypto._legacy_aad(org, "email")) == "pat@example.com", "the down direction restores the organization-bound form")

# the script, on real rows
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("UPDATE users SET email_enc=%s WHERE id=%s", (crypto._seal("officer@access-check.example.com", crypto._legacy_aad(org, "email")), admin_id))
    s.execute("UPDATE users SET name_enc=%s WHERE id=%s", (crypto._seal("Pat Owner", crypto._legacy_aad(None, "name")), owner_id))
env = {**os.environ}
r = subprocess.run([sys.executable, "-m", "scripts.reencrypt_identity"], env=env, capture_output=True, text=True)
ok(r.returncode == 0 and "Re-encrypted 2 values" in r.stdout, f"scripts.reencrypt_identity upgrades the legacy values: {r.stdout.strip()[-60:] or r.stderr[-200:]}")
with psycopg.connect(SUPER, autocommit=True) as s:
    e, n = s.execute("SELECT (SELECT email_enc FROM users WHERE id=%s), (SELECT name_enc FROM users WHERE id=%s)", (admin_id, owner_id)).fetchone()
ok(crypto._open(e, b"user|email") == "officer@access-check.example.com" and crypto._open(n, b"user|name") == "Pat Owner", "the stored values are now per-user")
r = subprocess.run([sys.executable, "-m", "scripts.reencrypt_identity", "--down"], env=env, capture_output=True, text=True)
with psycopg.connect(SUPER, autocommit=True) as s:
    rows = s.execute("SELECT org_id, email_enc FROM users WHERE id=%s", (admin_id,)).fetchone()
ok(r.returncode == 0 and crypto._open(rows[1], crypto._legacy_aad(rows[0], "email")) == "officer@access-check.example.com", "--down moves it back to organization-bound")
subprocess.run([sys.executable, "-m", "scripts.reencrypt_identity"], env=env, capture_output=True, text=True)
