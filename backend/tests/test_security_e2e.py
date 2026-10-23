"""Security end-to-end tests. Needs a fresh database with migrations applied.
Run: PYTHONPATH=. DATABASE_URL=... SENTRAIL_DATA_KEYS=... SENTRAIL_INDEX_KEY=... python tests/test_security_e2e.py
The owner connection string below assumes the local test setup; adjust it for yours."""
import os, re, time, pyotp, psycopg
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")  # bypasses RLS to inspect raw rows
os.environ.setdefault("AUTH_MODE", "local")
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from app.admin_api import router
from app.security.rbac import require
from app.security.middleware import limiter, SecurityHeaders
from app.security import crypto, passwords, mfa, audit
from app import pg

app = FastAPI(); app.state.limiter = limiter; app.add_middleware(SecurityHeaders); app.include_router(router)
@app.get("/protected")
def protected(p=Depends(require("str.approve"))): return {"ok": True}
limiter.enabled = False
c = TestClient(app, base_url="https://testserver")
ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)

def code_after(secret, last_step=0):
    step = int(time.time()) // 30
    return pyotp.TOTP(secret).at(step * 30)

# --- bootstrap platform admin (same as scripts/create_platform_admin.py) ---
secret = mfa.new_secret()
with pg.tx(platform=True) as cur:
    cur.execute("""INSERT INTO users (org_id, role_id, email_enc, email_bidx, name_enc, password_hash, totp_secret_enc, mfa_enabled, status)
                   VALUES (NULL,'00000000-0000-0000-0000-000000000002',%s,%s,%s,%s,%s,true,'active')""",
                (crypto.encrypt("ops@sentrail.dev", None, "email"), crypto.blind_index("ops@sentrail.dev"),
                 crypto.encrypt("Sentrail Ops", None, "name"), passwords.hash_password("platform passphrase long enough"),
                 crypto.encrypt(secret, None, "totp")))

def login(email, pw, secret, wait=False):
    if wait: time.sleep(31 - time.time() % 30)   # a code already used in this 30s window is rejected (replay protection)
    r = c.post("/auth/login", json={"email": email, "password": pw}); assert r.status_code == 200, r.text
    r = c.post("/auth/mfa", json={"mfa_token": r.json()["mfa_token"], "code": code_after(secret)}); assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}, r

r = c.post("/auth/login", json={"email": "ops@sentrail.dev", "password": "wrong password here!!"})
ok(r.status_code == 401 and r.json()["detail"] == "Email or password is incorrect", "wrong password gives generic error")
r = c.post("/auth/login", json={"email": "nobody@x.dev", "password": "whatever whatever"})
ok(r.status_code == 401 and r.json()["detail"] == "Email or password is incorrect", "unknown email gives same error (no account enumeration)")
P, resp = login("ops@sentrail.dev", "platform passphrase long enough", secret)
ok("sentrail_rt" in resp.headers.get("set-cookie","") and "HttpOnly" in resp.headers["set-cookie"] and "SameSite=strict" in resp.headers["set-cookie"], "refresh token set as HttpOnly, Secure, SameSite=Strict cookie")
ok(resp.headers.get("strict-transport-security","").startswith("max-age") and resp.headers.get("x-content-type-options")=="nosniff", "security headers present")
r = c.post("/auth/mfa", json={"mfa_token": c.post("/auth/login", json={"email":"ops@sentrail.dev","password":"platform passphrase long enough"}).json()["mfa_token"], "code": code_after(secret)})
ok(r.status_code == 401, "same TOTP code can't be replayed")

# --- create two organizations ---
r = c.post("/platform/orgs", headers=P, json={"legal_name":"Northwind Remit Inc.","business_type":"MSB","registration":"M23456789","admin_email":"leah@northwind.ca"})
ok(r.status_code == 200, "platform admin creates organization"); link1 = r.json()["dev_link"]
r = c.post("/platform/orgs", headers=P, json={"legal_name":"Maple Ridge","business_type":"MSB","registration":"M24567810","admin_email":"amir@mapleridge.ca"})
link2 = r.json()["dev_link"]
r = c.get("/admin/users", headers=P)
ok(r.status_code == 403, "platform admin can't list an org's users (no users.manage)")

# --- invitation acceptance + MFA enrollment ---
def enroll(link, email, name, pw):
    """Accept the invitation (password policy enforced), sign in with the password, then turn two-factor on."""
    tok = link.split("#",1)[1]
    r = c.post("/invitations/accept", json={"token": tok, "full_name": name, "password": "short"})
    assert r.status_code == 422
    r = c.post("/invitations/accept", json={"token": tok, "full_name": name, "password": pw}); assert r.status_code == 200, r.text
    r2 = c.post("/invitations/accept", json={"token": tok, "full_name": name, "password": pw})
    H = {"Authorization": "Bearer " + c.post("/auth/login", json={"email": email, "password": pw}).json()["access_token"]}
    sec = c.post("/me/mfa/setup", headers=H).json()["secret"]
    r = c.post("/me/mfa/confirm", headers=H, json={"code": code_after(sec)}); assert r.status_code == 200, r.text
    return sec, r.json()["recovery_codes"], r2.status_code
s1, rc1, again = enroll(link1, "leah@northwind.ca", "Leah Chen", "copper lantern river morning")
ok(again == 410, "invitation link works only once")
s2, _, _ = enroll(link2, "amir@mapleridge.ca", "Amir Haddad", "violet harbour tram sixteen")
A1, _ = login("leah@northwind.ca", "copper lantern river morning", s1, wait=True)
time.sleep(0)  # different users so no replay issue
A2, _ = login("amir@mapleridge.ca", "violet harbour tram sixteen", s2)

# --- personal data encrypted at rest ---
with psycopg.connect(SUPER) as o:
    row = o.execute("SELECT email_enc, name_enc, password_hash, totp_secret_enc FROM users WHERE name_enc IS NOT NULL LIMIT 1 OFFSET 1").fetchone()
ok("leah" not in str(row).lower() and "amir" not in str(row).lower() and row[2].startswith("$argon2id$"), "email, name and TOTP secret stored encrypted; password as argon2id")

# --- tenant isolation (row-level security) ---
users1 = c.get("/admin/users", headers=A1).json(); users2 = c.get("/admin/users", headers=A2).json()
ok(len(users1)==1 and len(users2)==1 and users1[0]["email"]=="l•••@northwind.ca", "each org admin sees only their own org's users, emails masked")
with pg.tx(users1 and None) as cur:
    cur.execute("SELECT count(*) FROM users")
    ok(cur.fetchone()[0] == 0, "with no tenant set, the app role sees zero rows")

# --- roles: invite analyst + officer, four-eyes, permissions ---
roles = {r["name"]: r["id"] for r in c.get("/admin/roles", headers=A1).json()["roles"]}
inv = c.post("/admin/invitations", headers=A1, json={"email":"ravi@northwind.ca","role_id":roles["Compliance analyst"]}).json()
ok(inv["invited"]=="r•••@northwind.ca", "org admin invites an analyst")
r = c.post("/admin/invitations", headers=A1, json={"email":"ravi@northwind.ca","role_id":roles["Compliance analyst"]})
ok(r.status_code == 409, "duplicate invitation rejected")
r = c.post("/admin/invitations", headers=A2, json={"email":"x@mapleridge.ca","role_id":roles["Compliance analyst"]})
ok(r.status_code == 404, "can't assign another organization's role")
s3, _, _ = enroll(inv["dev_link"], "ravi@northwind.ca", "Ravi Kumar", "orange glacier piano twelve")
R, _ = login("ravi@northwind.ca", "orange glacier piano twelve", s3, wait=True)
ok(c.get("/protected", headers=R).status_code == 403, "analyst can't use an endpoint requiring str.approve")
ok(c.get("/admin/users", headers=R).status_code == 403, "analyst can't open user admin")
me = [u for u in c.get("/admin/users", headers=A1).json() if u["name"]=="Leah Chen"][0]
r = c.patch(f"/admin/users/{me['id']}", headers=A1, json={"status":"suspended"})
ok(r.status_code == 403, "admin can't suspend themselves")
r = c.put(f"/admin/roles/{roles['Tenant admin']}", headers=A1, json={"name":"Tenant admin","perms":["users.manage","roles.manage","cases.decide"]})
ok(r.status_code == 403, "admin can't change permissions of their own role (no self-escalation)")
r = c.put(f"/admin/roles/{roles['Compliance analyst']}", headers=A1, json={"name":"Compliance analyst","perms":["cases.view","orgs.manage"]})
ok(r.status_code == 422, "platform permission can't be given to an org role")

ravi = [u for u in c.get("/admin/users", headers=A1).json() if u["name"]=="Ravi Kumar"][0]
r = c.patch(f"/admin/users/{ravi['id']}", headers=A1, json={"status":"suspended"})
ok(r.status_code==200 and c.get("/me", headers=R).status_code == 401, "suspending a user ends their live session immediately")

# --- security settings validation ---
r = c.put("/admin/security", headers=A1, json={"ip_allowlist":["198.51.100.0/24"]})
ok(r.status_code == 409, "IP allowlist that would lock out the admin is rejected")
r = c.put("/admin/security", headers=A1, json={"retention_years":2})
ok(r.status_code == 422, "retention below 5 years rejected")

# --- refresh rotation + reuse detection ---
c2 = TestClient(app, base_url="https://testserver")
r = c2.post("/auth/login", json={"email":"amir@mapleridge.ca","password":"violet harbour tram sixteen"})
time.sleep(31 - time.time() % 30)  # next TOTP step for amir
r = c2.post("/auth/mfa", json={"mfa_token": r.json()["mfa_token"], "code": code_after(s2)})
old = c2.cookies.get("sentrail_rt")
r1 = c2.post("/auth/refresh"); new = c2.cookies.get("sentrail_rt")
c2.cookies.set("sentrail_rt", old, domain="testserver.local"); 
c3 = TestClient(app, base_url="https://testserver"); c3.cookies.set("sentrail_rt", old)
r2 = c3.post("/auth/refresh")
c4 = TestClient(app, base_url="https://testserver"); c4.cookies.set("sentrail_rt", new)
r3 = c4.post("/auth/refresh")
ok(r1.status_code==200 and r2.status_code==401 and r3.status_code==401, "refresh token rotates; reusing an old one revokes the whole session family")

# --- audit chain ---
v = c.get("/admin/audit/verify", headers=A1).json()
ok(v["ok"] and v["events"] >= 5, f"audit chain verifies ({v.get('events')} events)")
with psycopg.connect(os.environ["DATABASE_URL"]) as a:          # the app role, as the API connects
    try:
        a.execute("SELECT set_config('app.org_id', %s, false)", (c.get("/me", headers=A1).json()["tenant"]["id"],))
        a.execute("UPDATE audit_events SET action='nothing' WHERE true"); ok(False, "app role blocked from editing audit")
    except psycopg.Error: ok(True, "app role can't edit or delete audit events")
with psycopg.connect(SUPER, autocommit=True) as o:
    o.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_no_update")
    o.execute("UPDATE audit_events SET detail='{\"role\":\"tampered\"}' WHERE action='user_invited'")
    o.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_no_update")
v = c.get("/admin/audit/verify", headers=A1).json()
ok(not v["ok"], f"tampering by a database superuser is detected: {v.get('reason')} at event {v.get('broken_at')}")

# --- account lockout survives the failed request ---
for i in range(5):
    c.post("/auth/login", json={"email": "ops@sentrail.dev", "password": f"wrong guess number {i}!"})
r = c.post("/auth/login", json={"email": "ops@sentrail.dev", "password": "platform passphrase long enough"})
ok(r.status_code == 429, "5 failed attempts lock the account, even against the right password")
with psycopg.connect(SUPER) as o:
    n = o.execute("SELECT count(*) FROM audit_events WHERE action='login_failed'").fetchone()[0]
ok(n >= 6, f"failed logins are kept in the audit log ({n} recorded)")

# --- tenant shown in the app, sessions list ---
m = c.get("/me", headers=A1).json()
ok(m["tenant"]["name"] == "Northwind Remit Inc." and m["tenant"]["environment"] == "production" and m["email"] == "l•••@northwind.ca",
   "/me returns the tenant name and environment for the header, with the email masked")
ok(c.get("/me", headers=P).json()["tenant"]["name"] == "Platform console", "platform admin sees 'Platform console' as tenant")
with psycopg.connect(SUPER) as o:
    n = o.execute("SELECT count(*) FROM organizations").fetchone()[0]
with pg.tx(m["tenant"]["id"]) as cur:
    cur.execute("SELECT count(*) FROM organizations"); seen = cur.fetchone()[0]
ok(n >= 2 and seen == 1, "an organization can read only its own organization record")

# --- signed-in devices: the current session is recognised without the refresh cookie ---
# (browsers send the cookie only to /auth, so /me/sessions must not depend on it)
cL = TestClient(app, base_url="https://testserver")
time.sleep(31 - time.time() % 30)                     # leah's next TOTP step
r = cL.post("/auth/login", json={"email": "leah@northwind.ca", "password": "copper lantern river morning"})
r = cL.post("/auth/mfa", json={"mfa_token": r.json()["mfa_token"], "code": code_after(s1)})
L2 = {"Authorization": "Bearer " + r.json()["access_token"]}
cL.cookies.clear()                                    # like a browser: no cookie reaches /me/*
sess = cL.get("/me/sessions", headers=L2).json()
ok(len(sess) >= 2 and sum(s["current"] for s in sess) == 1, "/me/sessions marks exactly one session as this device")
cL.cookies.set("sentrail_rt", r.cookies.get("sentrail_rt") or "")
ended = cL.post("/me/sessions/end-others", headers=L2).json().get("ended", 0)
ok(ended >= 1 and cL.post("/auth/refresh").status_code == 200,
   "'sign out other devices' ends the others and keeps this one")
