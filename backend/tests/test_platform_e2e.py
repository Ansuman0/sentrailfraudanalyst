"""Platform console tests: platform staff, roles by login type, plans, security baseline, support access.
Needs a fresh migrated database. Run: PYTHONPATH=. AUTH_MODE=local python tests/test_platform_e2e.py"""
import os, re, time
os.environ.setdefault("AUTH_MODE", "local")
import psycopg, pyotp
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app import pg
from app.security import crypto, passwords, mfa
from app.security.middleware import limiter
import app.admin_api as api

SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
app = FastAPI(); app.state.limiter = limiter; app.include_router(api.router); limiter.enabled = False
c = TestClient(app, base_url="https://testserver")
code = lambda s: pyotp.TOTP(s).at(int(time.time()) // 30 * 30)

def login(email, pw, secret, wait=False):
    if wait: time.sleep(31 - time.time() % 30)
    t = c.post("/auth/login", json={"email": email, "password": pw}).json()["mfa_token"]
    r = c.post("/auth/mfa", json={"mfa_token": t, "code": code(secret)}); assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}

def enroll(link, email, name, pw):
    """Accept the invitation, sign in with the password, then turn two-factor on (required for these roles)."""
    tok = link.split("#", 1)[1]
    r = c.post("/invitations/accept", json={"token": tok, "full_name": name, "password": pw}); assert r.status_code == 200, r.text
    H = {"Authorization": "Bearer " + c.post("/auth/login", json={"email": email, "password": pw}).json()["access_token"]}
    if email.endswith("@sentrail.io"):      # platform staff (organization users are optional unless their org insists)
        ok(c.get("/me", headers=H).json()["mfa_setup"] == "required", f"platform staff {email} must set up two-factor (owner may skip)")
    sec = c.post("/me/mfa/setup", headers=H).json()["secret"]
    assert c.post("/me/mfa/confirm", headers=H, json={"code": code(sec)}).status_code == 200
    return sec

# master login = platform owner (as scripts/seed.py creates it)
owner_secret = mfa.new_secret()
with pg.tx(platform=True) as cur:
    cur.execute("""INSERT INTO users (org_id, role_id, email_enc, email_bidx, name_enc, password_hash, totp_secret_enc, mfa_enabled, status)
                   VALUES (NULL,%s,%s,%s,%s,%s,%s,true,'active')""", (api.PLATFORM_OWNER_ROLE,
                crypto.encrypt("owner@sentrail.dev", None, "email"), crypto.blind_index("owner@sentrail.dev"),
                crypto.encrypt("Platform Owner", None, "name"), passwords.hash_password("north ridge copper window"),
                crypto.encrypt(owner_secret, None, "totp")))
O = login("owner@sentrail.dev", "north ridge copper window", owner_secret)
ok(c.get("/me", headers=O).json()["tenant"]["name"] == "Platform console", "master login lands in the platform console")

# --- roles seeded by login type ---
pr = c.get("/platform/roles", headers=O).json()
names = {r["name"]: r for r in pr["roles"]}
ok(set(names) == {"Platform owner", "Platform support", "Platform auditor"}
   and all(p["key"] == "orgs.manage" or p["key"].startswith("platform.") for p in pr["permissions"]),
   "platform console has its own seeded roles and only platform permissions")
with psycopg.connect(SUPER) as s:
    tmpl = dict(s.execute("SELECT scope, count(*) FROM role_templates GROUP BY scope").fetchall())
ok(tmpl == {"platform": 3, "tenant": 4}, "role templates are seed data in the database: 3 platform, 4 tenant")

# --- platform team ---
# The former Platform admin role is merged into Platform owner; an operator-style custom role keeps the old admin checks meaningful.
r = c.post("/platform/roles", headers=O, json={"name": "Platform operator", "perms": [
    "platform.tenants.manage", "platform.support", "platform.users.manage", "platform.plans.manage", "platform.audit.view"]})
ok(r.status_code == 200, "an owner can create a custom platform role")
names["Platform operator"] = {"id": r.json()["id"]}
r = c.post("/platform/invitations", headers=O, json={"email": "dev.k@sentrail.io", "role_id": names["Platform operator"]["id"]})
dev_s = enroll(r.json()["dev_link"], "dev.k@sentrail.io", "Dev Kapoor", "amber valley piano sixty")
r = c.post("/platform/invitations", headers=O, json={"email": "priya.n@sentrail.io", "role_id": names["Platform support"]["id"]})
pri_s = enroll(r.json()["dev_link"], "priya.n@sentrail.io", "Priya Nair", "silver canyon kettle nine")
r = c.post("/platform/invitations", headers=O, json={"email": "omar.f@sentrail.io", "role_id": names["Platform auditor"]["id"]})
oma_s = enroll(r.json()["dev_link"], "omar.f@sentrail.io", "Omar Farah", "maple drift harbour ten")
staff = c.get("/platform/users", headers=O).json()
ok(len(staff) == 4 and all("•••@" in u["email"] for u in staff), "platform owner sees the platform team with emails masked")
D = login("dev.k@sentrail.io", "amber valley piano sixty", dev_s, wait=True)
r = c.post("/platform/invitations", headers=D, json={"email": "x@sentrail.io", "role_id": api.PLATFORM_OWNER_ROLE})
ok(r.status_code == 403, "a platform operator can't create a platform owner")
owner_id = [u for u in staff if u["role"] == "Platform owner"][0]["id"]
ok(c.patch(f"/platform/users/{owner_id}", headers=D, json={"status": "suspended"}).status_code == 403, "a platform operator can't suspend the owner")
ok(c.patch(f"/platform/users/{owner_id}", headers=O, json={"status": "suspended"}).status_code == 403, "the owner can't suspend themselves")

# --- platform roles can never touch customer data ---
r = c.put(f"/platform/roles/{names['Platform support']['id']}", headers=O, json={"name": "Platform support", "perms": ["platform.support", "cases.view"]})
ok(r.status_code == 422, "API refuses to give a platform role a customer-data permission")
try:
    with pg.tx(platform=True) as cur:
        cur.execute("INSERT INTO role_permissions VALUES (%s,'cases.view')", (names["Platform support"]["id"],))
    ok(False, "database blocks platform role + customer permission")
except psycopg.Error:
    ok(True, "database trigger also blocks it, even if the API had a bug")
ok(c.put(f"/platform/roles/{names['Platform owner']['id']}", headers=O, json={"name": "Platform owner", "perms": []}).status_code == 409,
   "the platform owner role can't be stripped")

# --- tenants, plans ---
org = c.post("/platform/orgs", headers=D, json={"legal_name": "Maple Ridge", "business_type": "MSB", "registration": "M24567810",
             "plan": "professional", "admin_email": "amir@mapleridge.ca"}).json()
oid = org["org_id"]
a_s = enroll(org["dev_link"], "amir@mapleridge.ca", "Amir Haddad", "violet harbour tram sixteen")
A = login("amir@mapleridge.ca", "violet harbour tram sixteen", a_s, wait=True)
feats = {f["feature"]: f for f in c.get("/admin/features", headers=A).json()}
ok(feats["ai"]["in_plan"] and not feats["export"]["in_plan"], "new tenant gets its plan's features (Professional: no export)")
try:
    with pg.tx(oid) as cur:
        rid = [r for r in c.get("/admin/roles", headers=A).json()["roles"] if r["name"] == "Compliance analyst"][0]["id"]
        cur.execute("INSERT INTO role_permissions VALUES (%s,'platform.support')", (rid,))
    ok(False, "database blocks tenant role + platform permission")
except psycopg.Error:
    ok(True, "a tenant role can't hold a platform permission (database trigger)")
c.put("/platform/plans/professional", headers=D, json={"features": ["screening", "alerts", "trace", "statements"]})
feats = {f["feature"]: f for f in c.get("/admin/features", headers=A).json()}
ok(not feats["ai"]["in_plan"] and not feats["ai"]["enabled"], "removing a feature from a plan switches it off for every tenant on that plan")
c.put(f"/platform/orgs/{oid}/plan", headers=D, json={"plan": "enterprise"})
feats = {f["feature"]: f for f in c.get("/admin/features", headers=A).json()}
ok(feats["export"]["in_plan"] and feats["export"]["enabled"] and feats["ai"]["enabled"], "upgrading a tenant's plan switches on the new features")

# --- security baseline ---
P = login("priya.n@sentrail.io", "silver canyon kettle nine", pri_s, wait=False)
ok(c.put("/platform/security", headers=D, json={"min_password_len_floor": 16}).status_code == 403, "a platform operator can't change the security baseline (owner only by default)")
r = c.put("/platform/security", headers=O, json={"min_password_len_floor": 16, "max_idle_timeout_min": 20})
sec = c.get("/admin/security", headers=A).json()
ok(r.status_code == 200 and sec["min_password_len"] == 16 and sec["idle_timeout_min"] <= 20, "raising the baseline raises every tenant that was below it")
ok(c.put("/admin/security", headers=A, json={"min_password_len": 14}).status_code == 422, "a tenant can't go below the platform baseline")
ok(c.get("/admin/security", headers=A).json()["mfa_required"] is False, "two-factor is optional for a new organization's users by default")
c.put("/admin/security", headers=A, json={"min_password_len": 18, "idle_timeout_min": 10, "mfa_required": True})
sec = c.get("/admin/security", headers=A).json()
ok(sec["min_password_len"] == 18 and sec["mfa_required"] is True, "a tenant can be stricter, including making two-factor mandatory")

# --- support access ---
ok(c.get("/platform/orgs", headers=P).status_code == 200, "platform support can list organizations")
ok(c.post("/platform/orgs", headers=P, json={"legal_name": "X Ltd", "business_type": "MSB", "registration": "M1", "admin_email": "a@x.ca"}).status_code == 403,
   "platform support can't create organizations")
ok(c.get(f"/platform/orgs/{oid}/users?reason=no", headers=P).status_code == 422, "support access needs a real reason")
u = c.get(f"/platform/orgs/{oid}/users?reason=Ticket 4821: admin locked out", headers=P).json()
ok(len(u) == 1 and u[0]["email"] == "a•••@mapleridge.ca" and "name" not in u[0], "support sees masked user metadata only, no names")
ok(c.get("/admin/users", headers=P).status_code == 403, "support can't use a tenant's admin screens")
tenant_audit = [e["action"] for e in c.get("/admin/audit", headers=A).json()]
ok("support_viewed_users" in tenant_audit, "the tenant sees platform support access in its own audit log")

# --- platform auditor ---
X = login("omar.f@sentrail.io", "maple drift harbour ten", oma_s, wait=False)
ok(c.get("/admin/audit", headers=X).status_code == 200 and c.get("/admin/audit/verify", headers=X).json()["ok"],
   "platform auditor reads and verifies the platform audit log")
ok(c.get("/platform/users", headers=X).status_code == 403 and c.get("/platform/orgs", headers=X).status_code == 403,
   "platform auditor can't manage staff or see the organization list")
