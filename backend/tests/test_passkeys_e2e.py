"""Passkeys (G7): registration, sign-in as a second factor, owners passkey-only, platform setting enforcement, step-up with a passkey,
and mandatory two-factor for every Tenant admin. Real app and database; the browser's authenticator is simulated (soft_authenticator.py)
and the server's real WebAuthn verification runs. Needs a fresh migrated database.
Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_passkeys_e2e.py"""
import os
import pyotp
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from fastapi.testclient import TestClient
from app import pg
from app.main import app
from app.access import catalogue as cat
from app.admin_api import provision_org
from app.security import passkeys, rbac
from app.security.middleware import limiter
from helpers_access import CSRF, PW, add_user, bearer, claims, code_at, password_login, password_token, sql, two_factor_token
from soft_authenticator import SoftAuthenticator

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)
RP, ORIGINS = passkeys.relying_party()
new_auth = lambda: SoftAuthenticator(RP, ORIGINS[0])

with pg.tx(platform=True) as cur:
    T, tr = provision_org(cur, "Passkey Co", "MSB", "M1000001", plan="enterprise")
S = {n: pyotp.random_base32() for n in ("owner", "admin")}
analyst = add_user(T, tr["Compliance analyst"], "analyst@pk.example.com")
admin = add_user(T, tr[cat.TENANT_ADMIN], "admin@pk.example.com", secret=S["admin"])
owner = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "owner@pk.example.com", secret=S["owner"])
owner2 = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "owner2@pk.example.com")
bgu = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "bg@pk.example.com")
sql(SUPER, "UPDATE users SET break_glass=true WHERE id=%s", bgu)


def register(token, authenticator, name="My phone"):
    o = c.post("/me/passkeys/options", headers=bearer(token)).json()
    r = c.post("/me/passkeys", headers=bearer(token), json={"credential": authenticator.create(o), "name": name})
    return r


def passkey_login(email, authenticator, tamper=False, client=c):
    r = password_login(client, email)
    body = r.json()
    assert "mfa_token" in body and "passkey_options" in body, r.text
    return client.post("/auth/passkey", json={"mfa_token": body["mfa_token"], "credential": authenticator.get(body["passkey_options"], tamper=tamper)}), body


# ======================= registration =======================
print("# registration")
tok = password_token(c, "analyst@pk.example.com")
o = c.post("/me/passkeys/options", headers=bearer(tok))
ok(o.status_code == 200 and o.json()["rp"]["id"] == RP and o.json()["challenge"] and o.json()["authenticatorSelection"]["userVerification"] == "required",
   "registration options name the relying party and require user verification")
ok(c.post("/me/passkeys/options").status_code == 401, "no sign-in, no passkeys")
auth1 = new_auth()
r = c.post("/me/passkeys", headers=bearer(tok), json={"credential": auth1.create(o.json()), "name": "Work laptop"})
ok(r.status_code == 200 and r.json()["name"] == "Work laptop", "a passkey is registered")
ok("hwk" in claims(r.json()["session"]["access_token"])["amr"] and c.get("/me", headers=bearer(tok)).status_code == 401,
   "as a first second factor it ends the password-only session and answers with a new passkey session")
tok = r.json()["session"]["access_token"]
r2 = c.post("/me/passkeys", headers=bearer(tok), json={"credential": auth1.create(o.json()), "name": "again"})
ok(r2.status_code == 422, "a challenge can only be used once")
rb = c.post("/me/passkeys/options", headers=bearer(tok))
bad = rb.json()
ok(c.post("/me/passkeys", headers=bearer(tok), json={"credential": new_auth().create(bad, origin="https://evil.example"), "name": "phish"}).status_code == 422,
   "a credential made for another website (origin) is refused: that is the phishing protection")
ok(c.post("/me/passkeys", headers=bearer(tok), json={"credential": {"id": "x"}, "name": "junk"}).status_code == 422, "junk is refused cleanly")
listed = c.get("/me/passkeys", headers=bearer(tok)).json()
ok(len(listed["passkeys"]) == 1 and "public_key" not in str(listed) and listed["allowed"], "the list shows names and dates, never key material")
second = c.post("/me/passkeys/options", headers=bearer(tok)).json()
ok(len(second.get("excludeCredentials", [])) == 1, "a second registration excludes the passkey you already have")
ok("auth.passkey_registered" in [a[0] for a in sql(SUPER, "SELECT action FROM audit_events WHERE org_id=%s", T)], "registering is audited")
sql(SUPER, """INSERT INTO user_passkeys (user_id, credential_id, public_key, name) SELECT %s, gen_random_bytes(16), 'x'::bytea, 'filler' FROM generate_series(1, 9)""", analyst)
ok(c.post("/me/passkeys/options", headers=bearer(tok)).status_code == 409, "at most 10 passkeys per person")
sql(SUPER, "DELETE FROM user_passkeys WHERE name='filler'")

# ======================= sign in with a passkey =======================
print("# sign-in")
r, body = passkey_login("analyst@pk.example.com", auth1)
ok(r.status_code == 200 and r.json()["route"] == "tenant", "a passkey completes the sign-in")
ok(body["methods"] == ["passkey"], "the sign-in offers the passkey (no authenticator app is set up)")
tokp = r.json()["access_token"]
k = claims(tokp)
ok("hwk" in k["amr"] and "otp" not in k["amr"] and k["lmfa"], "the session records that a passkey was the second factor and when")
me = c.get("/me", headers=bearer(tokp)).json()
ok(me["session_mfa"] and me["mfa_enabled"] and me["passkeys"] == 1, "/me shows two-factor on, through the passkey")
ok(sql(SUPER, "SELECT sign_count >= 1 AND last_used_at IS NOT NULL FROM user_passkeys WHERE user_id=%s", analyst)[0][0], "the passkey's counter and last use are updated")
login_body = password_login(c, "analyst@pk.example.com").json()
ok("mfa_token" in login_body and "access_token" not in login_body, "once a passkey exists, a password alone no longer signs anyone in")
stale = c.post("/auth/passkey", json={"mfa_token": login_body["mfa_token"], "credential": auth1.get(login_body["passkey_options"], tamper=True)})
ok(stale.status_code == 401, "a tampered signature is refused")
again = c.post("/auth/passkey", json={"mfa_token": login_body["mfa_token"], "credential": auth1.get(login_body["passkey_options"])})
ok(again.status_code == 401, "and the challenge is gone after a failed try (one attempt per challenge)")
body = password_login(c, "analyst@pk.example.com").json()
other = c.post("/auth/passkey", json={"mfa_token": body["mfa_token"], "credential": new_auth().get(body["passkey_options"])})
ok(other.status_code == 401, "a passkey that isn't registered for this account is refused")
body = password_login(c, "analyst@pk.example.com").json()
cred = auth1.get(body["passkey_options"])
first = c.post("/auth/passkey", json={"mfa_token": body["mfa_token"], "credential": cred})
replay = c.post("/auth/passkey", json={"mfa_token": body["mfa_token"], "credential": cred})
ok(first.status_code == 200 and replay.status_code == 401, "an assertion can't be replayed")
body = password_login(c, "analyst@pk.example.com").json()
wrong_origin = c.post("/auth/passkey", json={"mfa_token": body["mfa_token"], "credential": auth1.get(body["passkey_options"], origin="https://evil.example")})
ok(wrong_origin.status_code == 401, "an assertion for another website is refused")
ok(c.post("/auth/passkey", json={"mfa_token": "garbage", "credential": {}}).status_code == 401, "a garbage sign-in token is a clean 401")
ok("auth.signin_failed" in [a[0] for a in sql(SUPER, "SELECT action FROM audit_events WHERE org_id=%s", T)], "failures are audited")

# ======================= every Tenant admin has two-factor =======================
print("# Tenant admins")
nomfa = add_user(T, tr[cat.TENANT_ADMIN], "nomfa-admin@pk.example.com")
t_nomfa = password_token(c, "nomfa-admin@pk.example.com")
r = c.get("/admin/users", headers=bearer(t_nomfa))
ok(r.status_code == 403 and "two-factor" in r.json()["detail"].lower() and c.get("/me", headers=bearer(t_nomfa)).json()["mfa_setup"] == "required",
   "a Tenant admin without two-factor can do nothing but set it up (the role holds every tenant permission)")
adm = new_auth()
rr = register(t_nomfa, adm, "admin key")
ok(rr.status_code == 200 and c.get("/admin/users", headers=bearer(rr.json()["session"]["access_token"])).status_code == 200, "a passkey is enough to set up two-factor: the admin works at once")
r, _ = passkey_login("nomfa-admin@pk.example.com", adm)
ok(r.status_code == 200 and c.get("/admin/users", headers=bearer(r.json()["access_token"])).status_code == 200, "and with it the admin works normally")

# ======================= step-up with a passkey =======================
print("# step-up")
admin_auth = new_auth()
t_admin = two_factor_token(c, "admin@pk.example.com", S["admin"])
register(t_admin, admin_auth, "admin phone")
r, body = passkey_login("admin@pk.example.com", admin_auth)
A = bearer(r.json()["access_token"])
POLICY = {"hold_at": 40, "block_at": 75, "travel_rule_threshold": 1000, "self_hosted_proof_above": 1000, "always_block_sanctions": True}
ok(c.put("/policy", headers=A, json=POLICY).status_code == 200, "fresh from a passkey sign-in, a sensitive action goes through")
rbac.STEP_UP_WINDOW_SECONDS = -1
ok(c.put("/policy", headers=A, json=POLICY).json() == {"error": "step_up_required"}, "later it asks for step-up")
opts = c.post("/session/step-up/options", headers=A)
ok(opts.status_code == 200 and opts.json()["challenge"], "the challenge for a passkey confirmation")
bad = c.post("/session/step-up", headers=A, json={"credential": admin_auth.get(opts.json(), tamper=True)})
ok(bad.status_code == 401, "a bad assertion is refused")
opts = c.post("/session/step-up/options", headers=A).json()
good = c.post("/session/step-up", headers=A, json={"credential": admin_auth.get(opts)})
ok(good.status_code == 200 and "hwk" in claims(good.json()["access_token"])["amr"], "a passkey assertion confirms it")
rbac.STEP_UP_WINDOW_SECONDS = 600
ok(c.put("/policy", headers=bearer(good.json()["access_token"]), json=POLICY).status_code == 200, "and the action goes through")
methods = [d.get("method") for _, d in sql(SUPER, "SELECT action, detail FROM audit_events WHERE org_id=%s AND action='auth.step_up'", T)]
ok("passkey" in methods, "the step-up is audited as a passkey")
ok(c.post("/session/step-up/options", headers=bearer(password_token(c, "bg@pk.example.com"))).status_code == 409, "(someone without a passkey has no challenge to answer)")

# ======================= Platform owners =======================
print("# owners")
owner_auth = new_auth()
t_owner = two_factor_token(c, "owner@pk.example.com", S["owner"])
ok(register(t_owner, owner_auth, "owner key").status_code == 200, "an owner registers a passkey")
body = password_login(c, "owner@pk.example.com").json()
ok(body["methods"] == ["passkey"], "from then on the owner is offered the passkey only")
r = c.post("/auth/mfa", json={"mfa_token": body["mfa_token"], "code": code_at(S["owner"], 1)})
ok(r.status_code == 403 and "passkey" in r.json()["detail"], "an authenticator code is refused for an owner who has a passkey")
r = c.post("/auth/passkey", json={"mfa_token": body["mfa_token"], "credential": owner_auth.get(body["passkey_options"])})
O = bearer(r.json()["access_token"])
ok(r.status_code == 200 and c.get("/platform/orgs", headers=O).status_code == 200, "the owner signs in with the passkey")
opts = c.post("/session/step-up/options", headers=O).json()
ok(c.post("/session/step-up", headers=O, json={"code": code_at(S["owner"], 1)}).status_code == 403, "an owner can't confirm with a code either")
ok(c.post("/session/step-up", headers=O, json={"credential": owner_auth.get(opts)}).status_code == 200, "an owner confirms with the passkey")

# platform_staff_passkey_only
sql(SUPER, "UPDATE platform_settings SET platform_staff_passkey_only=true")
t_o2 = password_token(c, "owner2@pk.example.com")
me = c.get("/me", headers=bearer(t_o2)).json()
ok(me["must_enroll_passkey"] is True, "with the platform setting on, an owner without a passkey is told to register one")
r = c.get("/platform/orgs", headers=bearer(t_o2))
ok(r.status_code == 403 and "passkey" in r.json()["detail"].lower(), "and can do nothing else")
o2_auth = new_auth()
r = register(t_o2, o2_auth, "owner2 key")
ok(r.status_code == 200, "registering is allowed")
ok(c.get("/platform/orgs", headers=bearer(t_o2)).status_code == 401, "the password-only session ends")
ok(c.get("/platform/orgs", headers=bearer(r.json()["session"]["access_token"])).status_code == 200, "and the new passkey session works at once")
r, _ = passkey_login("owner2@pk.example.com", o2_auth)
ok(c.get("/platform/orgs", headers=bearer(r.json()["access_token"])).status_code == 200, "as does signing in with the passkey")
ok(c.post("/auth/login", json={"email": "bg@pk.example.com", "password": PW}).json().get("access_token") is not None, "the sealed break-glass account is exempt (password only)")
p_o = c.get("/me/passkeys", headers=O).json()["passkeys"][0]["id"]
ok(c.delete(f"/me/passkeys/{p_o}", headers=O).status_code == 409, "an owner can't remove their last passkey while the platform requires them")
sql(SUPER, "UPDATE platform_settings SET platform_staff_passkey_only=false")
ok(c.delete(f"/me/passkeys/{p_o}", headers=O).status_code == 200, "with the setting off they can")
ok(c.get("/me/passkeys", headers=O).json()["passkeys"] == [], "and it is gone")
ok(c.delete(f"/me/passkeys/{p_o}", headers=O).status_code == 404, "removing it twice is a 404")
other_pk = sql(SUPER, "SELECT id::text FROM user_passkeys WHERE user_id=%s LIMIT 1", analyst)[0][0]
ok(c.delete(f"/me/passkeys/{other_pk}", headers=O).status_code == 404, "nobody can remove someone else's passkey")

# passkeys switched off for the platform
sql(SUPER, "UPDATE platform_settings SET passkeys_allowed=false")
ok(c.post("/me/passkeys/options", headers=O).status_code == 403, "with passkeys switched off, registration is refused")
body = password_login(c, "analyst@pk.example.com").json()
ok("passkey_options" not in body, "and sign-in no longer offers them")
sql(SUPER, "UPDATE platform_settings SET passkeys_allowed=true")
