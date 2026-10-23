"""Access model v2, phase 2: one sign-in with routing, tenant switching, sessions bound to one tenant, step-up, credential
protection, session hardening (cookies, CSRF, sign-out) and security notifications. Real app, real database.
Needs a fresh migrated database. Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_signin_session_e2e.py"""
import logging
import os
import time
import uuid
import jwt
import psycopg
import pyotp
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from fastapi.testclient import TestClient
from app import config, pg
from app.main import app
from app.access import catalogue as cat
from app.security import crypto, passwords, rbac
from app.security.middleware import limiter
import app.admin_api as api

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
CSRF = {"X-Sentrail-CSRF": "1"}
PW = "violet harbour tram sixteen"
c = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)
claims = lambda tok: jwt.decode(tok, options={"verify_signature": False})
bearer = lambda tok: {"Authorization": "Bearer " + tok}
code_at = lambda secret, offset: pyotp.TOTP(secret).at((int(time.time()) // 30 + offset) * 30)

records = []
class Capture(logging.Handler):
    def emit(self, record): records.append(record)
for name in ("sentrail.notify", "sentrail.access"):
    logging.getLogger(name).addHandler(Capture()); logging.getLogger(name).setLevel(logging.INFO)
notices = lambda kind: [r for r in records if getattr(r, "kind", None) == kind]


def add_user(org, role_id, email, secret=None, status="active"):
    with pg.tx(org, platform=org is None) as cur:
        cur.execute("""INSERT INTO users (org_id, role_id, email_enc, email_bidx, name_enc, password_hash, mfa_enabled, totp_secret_enc, status)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                    (org, role_id, crypto.encrypt(email, org, "email"), crypto.blind_index(email),
                     crypto.encrypt(email.split("@")[0], org, "name"), passwords.hash_password(PW), secret is not None,
                     crypto.encrypt(secret, org, "totp") if secret else None, status))
        return str(cur.fetchone()[0])


def password_login(email, client=c):
    return client.post("/auth/login", json={"email": email, "password": PW})


def two_factor_login(email, secret, offset=-1, client=c):
    r = password_login(email, client)
    assert r.status_code == 200 and "mfa_token" in r.json(), r.text
    r = client.post("/auth/mfa", json={"mfa_token": r.json()["mfa_token"], "code": code_at(secret, offset)})
    assert r.status_code == 200, r.text
    return r


with pg.tx(platform=True) as cur:
    alpha, ar = api.provision_org(cur, "Alpha Remit", "MSB", "M8000001")
    beta, br = api.provision_org(cur, "Beta Digital", "MSB", "M8000002")
D = "@phase2.example.com"
solo = add_user(alpha, ar["Compliance officer"], "solo" + D)
multi = add_user(alpha, ar["Compliance officer"], "multi" + D)
nobody = add_user(alpha, ar["Compliance analyst"], "nobody" + D)
staff = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "staff" + D)
sec = pyotp.random_base32()
twofa = add_user(alpha, ar["Compliance officer"], "twofa" + D, secret=sec)
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("INSERT INTO tenant_memberships (user_id, tenant_id, role_id) VALUES (%s,%s,%s)", (multi, beta, br["Auditor (read-only)"]))
    s.execute("UPDATE tenant_memberships SET status='active' WHERE user_id=%s", (multi,))
    s.execute("DELETE FROM tenant_memberships WHERE user_id=%s", (nobody,))
    s.execute("INSERT INTO tenant_memberships (user_id, tenant_id, role_id, status) VALUES (%s,%s,%s,'active')",
              (staff, alpha, ar["Compliance analyst"]))
    s.execute("""INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel)
                 VALUES ('A-BETA-1', %s, 'C-9', 70, 'high', '[]', 'bank')""", (beta,))


def audit_actions(org):
    with psycopg.connect(SUPER) as conn:
        return [r[0] for r in conn.execute("SELECT action FROM audit_events WHERE org_id IS NOT DISTINCT FROM %s ORDER BY seq", (org,)).fetchall()]


# ======================= sign-in routing (old model, flag off) =======================
config.ACCESS_MODEL_V2 = False
r = password_login("solo" + D).json()
ok(r["route"] == "tenant" and claims(r["access_token"])["tid"] == str(alpha) and claims(r["access_token"])["scp"] == "tenant",
   "flag off: a tenant user lands in their tenant")
ok(password_login("staff" + D).json()["route"] == "console", "flag off: platform staff land in the console")
ok(c.post("/session/tenant", headers=bearer(r["access_token"]), json={"tenant_id": str(beta)}).status_code == 403,
   "flag off: switching tenants isn't available")

# ======================= routing (new model) =======================
config.ACCESS_MODEL_V2 = True
r = password_login("solo" + D).json()
ok(r["route"] == "tenant" and r["tenants"][0]["name"] == "Alpha Remit", "one membership: straight into that tenant")
tok = r["access_token"]
k = claims(tok)
ok(k["tid"] == str(alpha) == k["org"] and k["scp"] == "tenant" and k["sv"] >= 1 and k["sid"] and k["rid"] and "lmfa" in k and "prid" in k and "asid" in k,
   "session claims: user, active tenant, role, platform role, access session, session version, last two-factor time")
ok(c.get("/me", headers=bearer(tok)).json()["tenant"]["name"] == "Alpha Remit", "the session works inside that tenant")

r = password_login("multi" + D).json()
ok(r["route"] == "picker" and len(r["tenants"]) == 2 and claims(r["access_token"])["scp"] == "select" and claims(r["access_token"])["tid"] is None,
   "several memberships: the tenant picker, in a session with no tenant yet")
sel = r["access_token"]
m = c.get("/me", headers=bearer(sel)).json()
ok(m["selecting"] and m["tenant"] is None and m["permissions"] == [] and len(m["tenants"]) == 2, "/me while choosing shows the choices and no permissions")
ok(c.get("/alerts", headers=bearer(sel)).status_code == 403 and c.get("/admin/users", headers=bearer(sel)).status_code == 403,
   "nothing else works until a tenant is chosen")
ok(len(c.get("/me/tenants", headers=bearer(sel)).json()["tenants"]) == 2, "GET /me/tenants lists the tenants")

nb = password_login("nobody" + D).json()
ok(nb["route"] == "no_access" and nb["tenants"] == [] and c.get("/me", headers=bearer(nb["access_token"])).json()["selecting"],
   "no membership and no platform role: the no-access page")
with psycopg.connect(SUPER) as conn:
    gone = conn.execute("SELECT count(*) FROM tenant_memberships WHERE user_id=%s", (nobody,)).fetchone()[0]
ok(gone == 0 and c.get("/me", headers=bearer(nb["access_token"])).json()["tenants"] == [],
   "signing in does not bring a removed membership back (the old-model sync only copies real role or status changes)")

st = password_login("staff" + D).json()
ok(st["route"] == "console" and claims(st["access_token"])["scp"] == "platform" and claims(st["access_token"])["tid"] is None,
   "platform staff go to the console, even with a tenant membership")
ok(any(t["kind"] == "platform" for t in c.get("/me/tenants", headers=bearer(st["access_token"])).json()["tenants"]), "the console is one of their places")

# ======================= tenant switching =======================
t_old = claims(sel)["sid"]
r = c.post("/session/tenant", headers=bearer(sel), json={"tenant_id": str(alpha)})
ok(r.status_code == 200, "choosing a tenant starts a session in it")
a_tok = r.json()["access_token"]
ok(claims(a_tok)["tid"] == str(alpha) and claims(a_tok)["sid"] != t_old, "the new session has a new session id")
ok(c.get("/me", headers=bearer(sel)).status_code == 401, "the old session ends at once (its access token no longer works)")
me = c.get("/me", headers=bearer(a_tok)).json()
ok(me["tenant"]["id"] == str(alpha) and me["role"] == "Compliance officer", "in Alpha the user holds their Alpha role")
ok(c.get("/cases/A-BETA-1", headers=bearer(a_tok)).status_code == 404, "a two-tenant user sees only the active tenant: Beta's case is invisible from Alpha")
r = c.post("/session/tenant", headers=bearer(a_tok), json={"tenant_id": str(beta)})
b_tok = r.json()["access_token"]
me = c.get("/me", headers=bearer(b_tok)).json()
ok(me["tenant"]["id"] == str(beta) and me["role"] == "Auditor (read-only)" and "str.approve" not in me["permissions"],
   "switching to Beta gives the Beta role and permissions, nothing carried over from Alpha")
ok(c.get("/cases/A-BETA-1", headers=bearer(b_tok)).status_code == 200, "and Beta's case is visible there")
ok(c.get("/me", headers=bearer(a_tok)).status_code == 401, "the Alpha session ended when they switched")
ok("auth.tenant_switch" in audit_actions(alpha) and "auth.tenant_switch" in audit_actions(beta), "switching is audited in both tenants' logs")
ok(c.post("/session/tenant", headers=bearer(b_tok), json={"tenant_id": str(uuid.uuid4())}).status_code == 403,
   "a tenant the user isn't a member of is refused")
ok(c.post("/session/tenant", headers=bearer(b_tok), json={"tenant_id": None}).status_code == 403, "the console is refused to someone who isn't platform staff")
sw = c.post("/session/tenant", headers=bearer(st["access_token"]), json={"tenant_id": str(alpha)})
ok(sw.status_code == 200 and c.get("/me", headers=bearer(sw.json()["access_token"])).json()["role"] == "Compliance analyst",
   "platform staff can enter a tenant they are a member of")
back = c.post("/session/tenant", headers=bearer(sw.json()["access_token"]), json={"tenant_id": None})
ok(back.status_code == 200 and c.get("/me", headers=bearer(back.json()["access_token"])).json()["tenant"]["name"] == "Platform console",
   "and return to the console")

# ======================= tenant status, membership status =======================
tok = password_login("solo" + D).json()["access_token"]
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("UPDATE organizations SET status='suspended' WHERE id=%s", (alpha,))
ok(c.get("/me", headers=bearer(tok)).status_code == 403, "a suspended tenant refuses every request, even with a live token")
ok(password_login("solo" + D).json()["route"] == "no_access", "and signing in to it leads nowhere")
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("UPDATE organizations SET status='active' WHERE id=%s", (alpha,))
tok = password_login("solo" + D).json()["access_token"]
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("UPDATE tenant_memberships SET status='suspended' WHERE user_id=%s", (solo,))
ok(c.get("/me", headers=bearer(tok)).status_code == 401, "a suspended membership ends the session")
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("UPDATE tenant_memberships SET status='active' WHERE user_id=%s", (solo,))
cx = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)
password_login("solo" + D, cx)
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("UPDATE tenant_memberships SET status='suspended' WHERE user_id=%s", (solo,))
ok(cx.post("/auth/refresh").status_code == 401, "a suspended membership can't renew its session")
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("UPDATE tenant_memberships SET status='active' WHERE user_id=%s", (solo,))
config.ACCESS_MODEL_V2 = False

# ======================= step-up (G8) =======================
r = two_factor_login("twofa" + D, sec, offset=-1).json()
T = r["access_token"]
ok(claims(T)["lmfa"] is not None and abs(claims(T)["lmfa"] - time.time()) < 5, "a two-factor sign-in records last_mfa_at")
POLICY = {"hold_at": 40, "block_at": 75, "travel_rule_threshold": 1000, "self_hosted_proof_above": 1000, "always_block_sanctions": True}
ok(c.put("/policy", headers=bearer(T), json=POLICY).status_code == 200, "inside the step-up window a step-up permission works")
rbac.STEP_UP_WINDOW_SECONDS = -1                       # now every second-factor check counts as old
r = c.put("/policy", headers=bearer(T), json=POLICY)
ok(r.status_code == 401 and r.json() == {"error": "step_up_required"}, "a stale second factor gets HTTP 401 {\"error\": \"step_up_required\"}")
ok(c.get("/policy", headers=bearer(T)).status_code == 200, "and plain reads are unaffected")
bad = c.post("/session/step-up", headers=bearer(T), json={"code": "000000"})
ok(bad.status_code == 401 and "auth.step_up_failed" in audit_actions(alpha), "a wrong code is refused and audited")
good = c.post("/session/step-up", headers=bearer(T), json={"code": code_at(sec, 0)})
ok(good.status_code == 200 and "auth.step_up" in audit_actions(alpha), "the right code is accepted and audited (auth.step_up)")
T2 = good.json()["access_token"]
ok(claims(T2)["lmfa"] >= claims(T)["lmfa"] and claims(T2)["sid"] == claims(T)["sid"], "the new token has a fresh last_mfa_at in the same session")
rbac.STEP_UP_WINDOW_SECONDS = 600
ok(c.put("/policy", headers=bearer(T2), json=POLICY).status_code == 200, "after the step-up the action goes through")
replay = c.post("/session/step-up", headers=bearer(T2), json={"code": code_at(sec, 0)})
ok(replay.status_code == 401, "the same code can't be used twice")
rbac.STEP_UP_WINDOW_SECONDS = -1
ref = c.post("/auth/refresh")
ok(ref.status_code == 200 and claims(ref.json()["access_token"])["lmfa"] == claims(T2)["lmfa"],
   "renewing a session keeps its step-up clock as it was (a refresh can't refresh it)")
rbac.STEP_UP_WINDOW_SECONDS = 600
ok(c.post("/session/step-up", headers=bearer(ref.json()["access_token"]), json={"recovery_code": "NOPE-NOPE"}).status_code == 401, "a wrong recovery code is refused")

# ======================= credential protection (I1) =======================
slept = []
real_sleep, api.LOGIN_DELAY_STEP = time.sleep, 0.2
time.sleep = lambda s: slept.append(s)
api._progressive_delay(1); api._progressive_delay(2)
none_yet = list(slept)
api._progressive_delay(3); api._progressive_delay(30)
time.sleep, api.LOGIN_DELAY_STEP = real_sleep, 0.0
ok(none_yet == [] and slept == [0.2, 1.0], "progressive delay: none for the first two failures, then longer, capped at 1 second")

lock_client = TestClient(app, headers=CSRF, base_url="https://testserver", client=("203.0.113.77", 4000), raise_server_exceptions=False)
for i in range(9):
    lock_client.post("/auth/login", json={"email": "multi" + D, "password": f"wrong guess {i} xx"})
ok(password_login("multi" + D, lock_client).status_code == 200, "nine failures don't lock")
for i in range(10):
    lock_client.post("/auth/login", json={"email": "multi" + D, "password": f"wrong guess {i} yy"})
ok(password_login("multi" + D, lock_client).status_code == 429, "ten failures within 15 minutes lock the account from that network, even for the right password")
ok(password_login("multi" + D).status_code == 200, "but the real user, from their own network, still signs in")
ok("auth.locked" in audit_actions(alpha), "the lock is audited (auth.locked)")
ok(audit_actions(alpha).count("auth.signin_failed") >= 19, "failed sign-ins are audited (auth.signin_failed)")
with psycopg.connect(SUPER, autocommit=True) as s:      # failures from many networks add up per account: a high cap locks everyone
    s.execute("INSERT INTO login_throttle (key_hash, ip, failed, updated_at) VALUES (%s,'',49,now()) ON CONFLICT (key_hash, ip) DO UPDATE SET failed=49, locked_until=NULL, updated_at=now()",
              (crypto.blind_index("solo" + D),))
other = TestClient(app, headers=CSRF, base_url="https://testserver", client=("203.0.113.88", 4000), raise_server_exceptions=False)
other.post("/auth/login", json={"email": "solo" + D, "password": "wrong guess zz zz"})
ok(password_login("solo" + D).status_code == 429, "past 50 failures from all networks the account is locked for everyone")
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("DELETE FROM login_throttle")
with psycopg.connect(SUPER, autocommit=True) as s:      # the window: old failures don't count
    s.execute("INSERT INTO login_throttle (key_hash, ip, failed, updated_at) VALUES (%s,'',9,now() - interval '20 minutes')", (crypto.blind_index("solo" + D),))
other.post("/auth/login", json={"email": "solo" + D, "password": "wrong guess one"})
with psycopg.connect(SUPER, autocommit=True) as s:
    n = s.execute("SELECT failed FROM login_throttle WHERE key_hash=%s AND ip=''", (crypto.blind_index("solo" + D),)).fetchone()[0]
ok(n == 1, "failures older than 15 minutes no longer count")
with psycopg.connect(SUPER, autocommit=True) as s:
    s.execute("DELETE FROM login_throttle")

# ======================= session hardening (I2) =======================
r = password_login("solo" + D)
cookies = r.headers.get_list("set-cookie")
rt = next(x for x in cookies if x.startswith("sentrail_rt="))
ok(all(f in rt for f in ("HttpOnly", "Secure", "Path=/auth")) and "samesite=strict" in rt.lower(), "refresh cookie: HttpOnly, Secure, SameSite=Strict, scoped to /auth")
dv = next((x for x in cookies if x.startswith("sentrail_dv=")), "")
ok("HttpOnly" in dv and "Secure" in dv and "samesite=strict" in dv.lower(), "device cookie: HttpOnly, Secure, SameSite=Strict")
plain = TestClient(app, base_url="https://testserver", raise_server_exceptions=False)         # no CSRF header
ok(plain.post("/auth/refresh").status_code == 403 and plain.post("/auth/logout").status_code == 403, "cookie-authenticated writes without the CSRF header are refused")
ok(plain.post("/auth/refresh", headers={**CSRF, "Origin": "https://evil.example"}).status_code == 403, "a cross-site Origin is refused")
ok(plain.post("/auth/refresh", headers={**CSRF, "Origin": "https://testserver"}).status_code == 401, "the app's own origin passes the CSRF check (then fails only for lack of a session)")
tok1 = r.json()["access_token"]
ref = c.post("/auth/refresh")
ok(ref.status_code == 200 and claims(ref.json()["access_token"])["sid"] == claims(tok1)["sid"], "refresh keeps the session id (rotation keeps the family)")
ok(claims(password_login("solo" + D, TestClient(app, headers=CSRF, base_url="https://testserver")).json()["access_token"])["sid"] != claims(tok1)["sid"],
   "every sign-in is a new session id")
out = c.post("/auth/logout")
ok(out.status_code == 200 and c.get("/me", headers=bearer(tok1)).status_code == 401 and c.get("/me", headers=bearer(ref.json()["access_token"])).status_code == 401,
   "signing out ends the session at once: its access tokens stop working")
ok("auth.signout" in audit_actions(alpha), "sign-out is audited (auth.signout)")
ok("auth.signin" in audit_actions(alpha), "sign-in is audited (auth.signin)")

# ======================= security notifications (I6) =======================
records.clear()
browser = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)
password_login("solo" + D, browser)                       # this browser is new to solo (they have signed in elsewhere before)
ok(len(notices("new_device")) == 1 and "•••@" in notices("new_device")[0].to,
   "a sign-in from a browser this person hasn't used before sends a new-device notice (masked address in the log)")
records.clear()
password_login("solo" + D, browser)
ok(not notices("new_device"), "the same browser (device cookie) is not a new device the second time")
first = add_user(alpha, ar["Compliance analyst"], "firsttime" + D)
records.clear()
password_login("firsttime" + D, TestClient(app, headers=CSRF, base_url="https://testserver"))
ok(not notices("new_device"), "a person's very first sign-in is not reported as a new device")
records.clear()
t = password_login("firsttime" + D).json()["access_token"]
setup = c.post("/me/mfa/setup", headers=bearer(t)).json()
confirm = c.post("/me/mfa/confirm", headers=bearer(t), json={"code": code_at(setup["secret"], 0)})
ok(confirm.status_code == 200 and len(notices("mfa_enabled")) == 1, "turning on two-factor notifies the person")
boss_secret = pyotp.random_base32()
admin = add_user(alpha, ar[cat.TENANT_ADMIN], "boss" + D, secret=boss_secret)
A = bearer(two_factor_login("boss" + D, boss_secret, offset=0).json()["access_token"])
records.clear()
r = c.post(f"/admin/users/{first}/reset-mfa", headers=A, json={"reason": "lost phone, ticket 77"})
ok(r.status_code == 200 and len(notices("mfa_reset")) == 1, "an admin resetting someone's two-factor notifies them")
records.clear()
r = c.patch(f"/admin/users/{first}", headers=A, json={"role_id": str(ar["Auditor (read-only)"])})
ok(r.status_code == 200 and len(notices("role_changed")) == 1, "a role change notifies the person")
ok(all("password" not in str(x.__dict__).lower() for x in records), "notifications carry no secrets")
