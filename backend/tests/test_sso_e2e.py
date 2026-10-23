"""Company sign-in (G6): enforcement, the passkey-only emergency login, and just-in-time membership. Real app and database; the identity
provider (Keycloak, which brokers OIDC and SAML companies alike) is simulated with real signed ID tokens, as in test_oidc_e2e.py.
Needs a fresh migrated database. Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_sso_e2e.py"""
import os
import time
import uuid
from urllib.parse import parse_qs, urlparse
os.environ["AUTH_MODE"] = "local"
os.environ.setdefault("APP_URL", "https://app.sentrail.test")
import jwt
import pyotp
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from app import pg
from app.main import app
from app.access import catalogue as cat
from app.admin_api import provision_org
from app.security import oidc, passkeys
from app.security.middleware import limiter
from helpers_access import CSRF, PW, add_user, bearer, code_at, password_login, sql, two_factor_token
from soft_authenticator import SoftAuthenticator

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False, follow_redirects=False)
APP = os.environ["APP_URL"]

# ---- simulated identity provider ----
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
oidc.metadata = lambda: {"authorization_endpoint": f"{oidc.KC_URL}/auth", "token_endpoint": "x", "jwks_uri": "x", "end_session_endpoint": f"{oidc.KC_URL}/logout"}
class _K: key = KEY.public_key()
class _J:
    def get_signing_key_from_jwt(self, t): return _K()
oidc.jwks_client = lambda: _J()
NEXT = {}
def id_token(sub, email, nonce, verified=True, name=None):
    now = int(time.time())
    claims = {"sub": sub, "email": email, "email_verified": verified, "nonce": nonce, "aud": oidc.CLIENT_ID, "azp": oidc.CLIENT_ID,
              "iss": oidc.ISSUER, "iat": now, "exp": now + 300, "auth_time": now}
    if name:
        claims["name"] = name
    return jwt.encode(claims, KEY, algorithm="RS256")
oidc.exchange_code = lambda code, verifier: {"id_token": NEXT.pop(code)}


def company_login(email, sub, **kw):
    r = c.get("/auth/oidc/login?" + f"email={email}&idp=sso-idp")
    p = parse_qs(urlparse(r.headers["location"]).query)
    code = uuid.uuid4().hex
    NEXT[code] = id_token(sub, email, p["nonce"][0], **kw)
    return c.get(f"/auth/oidc/callback?code={code}&state={p['state'][0]}")


RP, ORIGINS = passkeys.relying_party()
with pg.tx(platform=True) as cur:
    T, tr = provision_org(cur, "Sso Co", "MSB", "M9100001", plan="professional")
    U, ur = provision_org(cur, "Plain Co", "MSB", "M9100002", plan="professional")
admin_secret = pyotp.random_base32()
admin = add_user(T, tr[cat.TENANT_ADMIN], "admin@sso.example.com", secret=admin_secret)
admin2 = add_user(T, tr[cat.TENANT_ADMIN], "admin2@sso.example.com", secret=pyotp.random_base32())
analyst = add_user(T, tr["Compliance analyst"], "analyst@sso.example.com")
plain = add_user(U, ur["Compliance analyst"], "analyst@plain.example.com")
A = bearer(two_factor_token(c, "admin@sso.example.com", admin_secret))

# ======================= configuration =======================
print("# configuration")
ok(c.put("/admin/sso", headers=A, json={"domain": "sso.example.com", "idp_alias": "sso-idp", "enforced": True, "protocol": "saml",
                                         "default_role_id": str(tr[cat.TENANT_ADMIN])}).status_code == 422,
   "the company sign-in default role can never be Tenant admin")
r = c.put("/admin/sso", headers=A, json={"domain": "sso.example.com", "idp_alias": "sso-idp", "enforced": True, "protocol": "saml",
                                          "default_role_id": str(tr["Compliance analyst"])})
ok(r.status_code == 200 and r.json()["txt_record"]["value"].startswith("sentrail-verify="), "an admin configures company sign-in (SAML through Keycloak) and gets the DNS record to publish")
cfg = c.get("/admin/sso", headers=A).json()
ok(cfg["protocol"] == "saml" and cfg["pending_domain"] == "sso.example.com" and cfg["domain"] is None and cfg["enforced"] is False,
   "until the domain is verified nothing is enforced")
ok(password_login(c, "analyst@sso.example.com").status_code == 200, "so passwords still work")
sql(SUPER, "UPDATE organizations SET sso_domain=sso_domain_pending, sso_domain_pending=NULL WHERE id=%s", T)      # what /admin/sso/verify does after the DNS check
cfg = c.get("/admin/sso", headers=A).json()
ok(cfg["enforced"] is True and cfg["domain"] == "sso.example.com", "once the domain is verified it is enforced")
ok(c.get("/admin/security", headers=A).json()["sso_enabled"] is True, "the security screen shows company sign-in as on (derived, not a second switch)")

# ======================= enforcement =======================
print("# enforcement")
r = password_login(c, "analyst@sso.example.com")
ok(r.status_code == 403 and "company sign-in" in r.json()["detail"] and "access_token" not in r.text, "a member of the company can't sign in with a password")
r = c.post("/auth/login", json={"email": "analyst@sso.example.com", "password": "not the password"})
ok(r.status_code == 401 and r.json()["detail"] == "Email or password is incorrect", "a wrong password still gets the generic answer (nothing is revealed without the right one)")
ok(password_login(c, "admin2@sso.example.com").status_code == 403, "Tenant admins are included")
ok(password_login(c, "analyst@plain.example.com").status_code == 200, "another company's people are unaffected")
d = c.post("/auth/discover", json={"email": "someone@sso.example.com"}).json()
ok(d["method"] == "sso" and d["enforced"] is True and "idp=sso-idp" in d["next"], "discovery tells the sign-in page to go to the company identity provider")
d2 = c.post("/auth/discover", json={"email": "someone@plain.example.com"}).json()
ok(d2["method"] == "keycloak" and "enforced" not in d2, "other domains are told nothing about it")
# a company sign-in still works
sub = str(uuid.uuid4())
sql(SUPER, "UPDATE users SET idp_subject=%s, auth_method='keycloak' WHERE id=%s", sub, analyst)
r = company_login("analyst@sso.example.com", sub)
ok(r.status_code == 302 and r.headers["location"] == APP + "/" and "sentrail_rt=" in r.headers.get("set-cookie", ""), "signing in through the company's identity provider works")

# ======================= emergency login =======================
print("# emergency login")
ok(c.put("/admin/sso/emergency", headers=A, json={"user_id": analyst}).status_code == 409, "only a Tenant admin can be the emergency login")
ok(c.put("/admin/sso/emergency", headers=A, json={"user_id": admin}).status_code == 409, "and only one who already has a passkey")
auth_admin = SoftAuthenticator(RP, ORIGINS[0])
o = c.post("/me/passkeys/options", headers=A).json()
rr = c.post("/me/passkeys", headers=A, json={"credential": auth_admin.create(o), "name": "admin key"})
ok(rr.status_code == 200, "the admin registers a passkey")
A = bearer(rr.json().get("session", {}).get("access_token") or A["Authorization"].split()[1])
ok(c.put("/admin/sso/emergency", headers=A, json={"user_id": admin}).status_code == 200 and c.get("/admin/sso", headers=A).json()["emergency_user_id"] == admin,
   "that admin becomes the emergency login")
body = password_login(c, "admin@sso.example.com").json()
ok(body["methods"] == ["passkey"] and "passkey_options" in body, "their password sign-in works but asks for the passkey only")
r = c.post("/auth/mfa", json={"mfa_token": body["mfa_token"], "code": code_at(admin_secret, 1)})
ok(r.status_code == 403 and "passkey" in r.json()["detail"], "an authenticator code is not accepted for the emergency login")
r = c.post("/auth/passkey", json={"mfa_token": body["mfa_token"], "credential": auth_admin.get(body["passkey_options"])})
ok(r.status_code == 200 and "access_token" in r.json(), "the passkey completes it")
ok(password_login(c, "admin2@sso.example.com").status_code == 403, "everyone else is still refused")
with pg.tx(T) as cur:
    cur.execute("SELECT count(*) FROM users WHERE org_id=%s AND sso_emergency", (T,))
    ok(cur.fetchone()[0] == 1, "there is exactly one emergency login")
ok(c.delete("/admin/sso/emergency", headers=A).status_code == 200 and password_login(c, "admin@sso.example.com").status_code == 403, "clearing it closes the password route again")
ok(c.delete("/admin/sso/emergency", headers=A).status_code == 404, "(and there is nothing left to clear)")

# ======================= just-in-time membership =======================
print("# just-in-time membership")
before = sql(SUPER, "SELECT count(*) FROM users WHERE org_id=%s", T)[0][0]
r = company_login("new.person@sso.example.com", str(uuid.uuid4()), name="New Person")
ok(r.status_code == 302 and "error" not in r.headers["location"] and "sentrail_rt=" in r.headers.get("set-cookie", ""), "someone nobody invited signs in through the company and gets an account")
row = sql(SUPER, "SELECT u.status, u.auth_method, r.name, m.status FROM users u JOIN roles r ON r.id=u.role_id JOIN tenant_memberships m ON m.user_id=u.id WHERE u.org_id=%s ORDER BY u.created_at DESC LIMIT 1", T)[0]
ok(row == ("active", "keycloak", "Compliance analyst", "active"), f"with the default role and an active membership: {row}")
ok(sql(SUPER, "SELECT count(*) FROM users WHERE org_id=%s", T)[0][0] == before + 1, "exactly one account was created")
ok("sso_jit_provisioned" in [a[0] for a in sql(SUPER, "SELECT action FROM audit_events WHERE org_id=%s", T)], "it is audited")
sub2 = str(uuid.uuid4())
r = company_login("unverified@sso.example.com", sub2, verified=False)
ok(r.headers["location"].endswith("error=invalid"), "an address the identity provider hasn't verified is refused at sign-in (no account is created)")
r = company_login("stranger@elsewhere.example.com", str(uuid.uuid4()))
ok(r.headers["location"].endswith("error=no_account"), "a domain that isn't the company's gets no account")
sql(SUPER, "UPDATE organizations SET sso_default_role_id=NULL WHERE id=%s", T)
r = company_login("norole@sso.example.com", str(uuid.uuid4()))
ok(r.headers["location"].endswith("error=no_account"), "with no default role configured nobody is created")
sql(SUPER, "UPDATE organizations SET sso_default_role_id=%s WHERE id=%s", tr["Compliance analyst"], T)
sql(SUPER, "UPDATE organizations SET sso_default_role_id=%s WHERE id=%s", tr[cat.TENANT_ADMIN], T)
r = company_login("sneaky@sso.example.com", str(uuid.uuid4()))
ok(r.headers["location"].endswith("error=no_account"), "even if the default were somehow the Tenant admin role, nobody is created with it")
sql(SUPER, "UPDATE organizations SET sso_default_role_id=%s WHERE id=%s", tr["Compliance analyst"], T)
# seats: Professional allows 25
sql(SUPER, "UPDATE plans SET max_users=%s WHERE key='professional'", sql(SUPER, "SELECT count(*) FROM tenant_memberships WHERE tenant_id=%s AND status='active'", T)[0][0])
r = company_login("late@sso.example.com", str(uuid.uuid4()))
ok(r.headers["location"].endswith("error=no_account"), "when the plan's seats are full nobody new is created")
sql(SUPER, "UPDATE plans SET max_users=25 WHERE key='professional'")
sql(SUPER, "UPDATE organizations SET status='suspended' WHERE id=%s", T)
r = company_login("suspended@sso.example.com", str(uuid.uuid4()))
ok(r.headers["location"].endswith("error=no_account"), "a suspended tenant provisions nobody")
sql(SUPER, "UPDATE organizations SET status='active' WHERE id=%s", T)

# ======================= turning enforcement off =======================
sql(SUPER, "UPDATE organizations SET sso_enforced=false WHERE id=%s", T)
ok(password_login(c, "admin2@sso.example.com").status_code == 200, "with enforcement off passwords work again")
