"""Keycloak (OIDC) sign-in tests with a simulated identity provider that signs real RS256 ID tokens.
Needs a fresh migrated database. Run: PYTHONPATH=. AUTH_MODE=keycloak python tests/test_oidc_e2e.py"""
import os, time, uuid
from urllib.parse import urlparse, parse_qs
os.environ["AUTH_MODE"] = "keycloak"
os.environ.setdefault("APP_URL", "https://app.sentrail.test")
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.security.rbac import install_handlers
CSRF = {"X-Sentrail-CSRF": "1"}

from app.access import members
from app import pg
from app.security import oidc, crypto, passwords, mfa
from app.security.middleware import limiter
import app.admin_api as api

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
APP = os.environ["APP_URL"]

# ---- simulated Keycloak ----
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
oidc.metadata = lambda: {"authorization_endpoint": f"{oidc.KC_URL}/realms/sentrail/protocol/openid-connect/auth",
                         "token_endpoint": "x", "jwks_uri": "x", "end_session_endpoint": f"{oidc.KC_URL}/logout"}
class _K: key = KEY.public_key()
class _J:
    def get_signing_key_from_jwt(self, t): return _K()
oidc.jwks_client = lambda: _J()
NEXT = {}
def id_token(sub, email, nonce, verified=True, aud=oidc.CLIENT_ID, iss=oidc.ISSUER, age=0):
    now = int(time.time())
    return jwt.encode({"sub": sub, "email": email, "email_verified": verified, "nonce": nonce, "aud": aud, "azp": aud,
                       "iss": iss, "iat": now - age, "exp": now + 300, "auth_time": now - age}, KEY, algorithm="RS256")
oidc.exchange_code = lambda code, verifier: {"id_token": NEXT.pop(code)}
PROVISIONED = []
class FakeKC:
    def create_user(self, email, org_id, **kw): PROVISIONED.append(email); return str(uuid.uuid4())
    def send_setup_email(self, sub): pass
    def set_enabled(self, sub, enabled): PROVISIONED.append(("enabled", enabled))
    def reset_second_factor(self, sub): pass
api.kc = lambda: FakeKC()

app = FastAPI(); app.state.limiter = limiter; app.include_router(api.router); install_handlers(app); limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver", follow_redirects=False)

# ---- data: org with company SSO + users ----
with pg.tx(platform=True) as cur:
    org, roles = api.provision_org(cur, "Northwind Remit Inc.", "MSB", "M23456789")
    cur.execute("UPDATE organizations SET sso_domain='northwindremit.ca', sso_idp_alias='northwind-entra', sso_enforced=true WHERE id=%s", (org,))
def add_user(email, role, status="active", sub=None):
    with pg.tx(org) as cur:
        return members.create_person(cur, org, roles[role], email_enc=crypto.encrypt(email, org, "email"), email_bidx=crypto.blind_index(email),
                                     name_enc=crypto.encrypt(email.split("@")[0], org, "name"), status=status,
                                     extra={"idp_subject": sub, "auth_method": "keycloak"})
analyst_sub = str(uuid.uuid4())
add_user("auditor@external-audit.ca", "Auditor (read-only)", sub=analyst_sub)
add_user("leah.chen@northwindremit.ca", "Tenant admin", status="invited")          # SSO user, not yet linked
susp_sub = str(uuid.uuid4()); add_user("gone@external-audit.ca", "Compliance analyst", status="suspended", sub=susp_sub)

def start(email=None, idp=None, return_to="/"):
    q = "&".join(f"{k}={v}" for k, v in {"email": email, "idp": idp, "return_to": return_to}.items() if v)
    r = c.get(f"/auth/oidc/login?{q}")
    loc = urlparse(r.headers["location"]); p = parse_qs(loc.query)
    return r, p
def finish(p, sub, email, **kw):
    code = uuid.uuid4().hex; NEXT[code] = id_token(sub, email, kw.pop("nonce", p["nonce"][0]), **kw)
    return c.get(f"/auth/oidc/callback?code={code}&state={p['state'][0]}")

# discovery
d1 = c.post("/auth/discover", json={"email": "leah.chen@northwindremit.ca"}).json()
d2 = c.post("/auth/discover", json={"email": "nobody@unknown.ca"}).json()
d3 = c.post("/auth/discover", json={"email": "auditor@external-audit.ca"}).json()
ok(d1["method"] == "sso" and "idp=northwind-entra" in d1["next"], "company domain is sent straight to its identity provider")
ok(d2["method"] == d3["method"] == "keycloak", "unknown and known non-SSO emails get the same answer (no account discovery)")

# authorize request
r, p = start("leah.chen@northwindremit.ca", "northwind-entra")
ok(r.status_code == 302 and p["code_challenge_method"] == ["S256"] and len(p["code_challenge"][0]) >= 43
   and p["kc_idp_hint"] == ["northwind-entra"] and p["prompt"] == ["login"], "redirect to Keycloak uses PKCE S256, state, nonce and the IdP hint")

# first SSO sign-in links invited user
leah_sub = str(uuid.uuid4())
r = finish(p, leah_sub, "leah.chen@northwindremit.ca")
ok(r.status_code == 302 and r.headers["location"] == APP + "/" and "sentrail_rt=" in r.headers.get("set-cookie", ""),
   "valid sign-in creates a Sentrail session and returns to the app")
with pg.tx(org) as cur:
    cur.execute("SELECT status, idp_subject FROM users WHERE idp_subject=%s", (leah_sub,)); st = cur.fetchone()
ok(st and st[0] == "active", "invited SSO user is linked to their identity on first sign-in and activated")
tok = c.post("/auth/refresh").json()["access_token"]
me = c.get("/me", headers={"Authorization": "Bearer " + tok}).json()
ok(me["tenant"]["name"] == "Northwind Remit Inc." and me["role"] == "Tenant admin", "the session knows its tenant and role")

# replayed state
code = uuid.uuid4().hex; NEXT[code] = id_token(leah_sub, "leah.chen@northwindremit.ca", p["nonce"][0])
r = c.get(f"/auth/oidc/callback?code={code}&state={p['state'][0]}")
ok(r.headers["location"].endswith("error=expired"), "a login state can't be used twice")

# wrong nonce, unverified email, wrong audience, old authentication
_, p = start(); ok(finish(p, analyst_sub, "auditor@external-audit.ca", nonce="attacker").headers["location"].endswith("error=invalid"), "ID token with the wrong nonce is rejected")
_, p = start(); ok(finish(p, analyst_sub, "auditor@external-audit.ca", verified=False).headers["location"].endswith("error=invalid"), "unverified email is rejected")
_, p = start(); ok(finish(p, analyst_sub, "auditor@external-audit.ca", aud="other-app").headers["location"].endswith("error=invalid"), "ID token for another client is rejected")
_, p = start(); ok(finish(p, analyst_sub, "auditor@external-audit.ca", iss="https://evil/realms/sentrail").headers["location"].endswith("error=invalid"), "ID token from another issuer is rejected")
_, p = start(); ok(finish(p, analyst_sub, "auditor@external-audit.ca", age=1200).headers["location"].endswith("error=invalid"), "stale authentication (over 10 minutes old) is rejected")

# no account, suspended, cross-domain linking attempt
_, p = start(); ok(finish(p, str(uuid.uuid4()), "stranger@gmail.com").headers["location"].endswith("error=no_account"), "a Keycloak identity with no Sentrail account can't sign in (no self-registration)")
_, p = start(); ok(finish(p, susp_sub, "gone@external-audit.ca").headers["location"].endswith("error=suspended"), "suspended user is blocked even with a valid identity")
add_user("ravi.k@northwindremit.ca", "Compliance analyst", status="invited")
_, p = start(); r = finish(p, str(uuid.uuid4()), "ravi.k@northwindremit.ca")
ok(r.headers["location"] == APP + "/", "invited user on the verified SSO domain links on first sign-in")
add_user("victim@external-audit.ca", "Compliance analyst", status="invited")
_, p = start(); r = finish(p, str(uuid.uuid4()), "victim@external-audit.ca")
ok(r.headers["location"].endswith("error=no_account"), "an identity can't claim an account by email outside the org's verified SSO domain")

# open redirect
_, p = start(return_to="//evil.example/steal")
ok(finish(p, analyst_sub, "auditor@external-audit.ca").headers["location"] == APP + "/", "return_to can't redirect to another site")

# local password sign-in only for the platform break-glass account
r = c.post("/auth/login", json={"email": "auditor@external-audit.ca", "password": "anything at all here"})
r_unknown = c.post("/auth/login", json={"email": "nobody-here@external-audit.ca", "password": "anything at all here"})
ok(r.status_code == 401 and r.json() == r_unknown.json(),
   "organization users can't use local password sign-in in Keycloak mode, and the answer is the same as for an unknown email")
secret = mfa.new_secret()
with pg.tx(platform=True) as cur:
    members.create_person(cur, None, '00000000-0000-0000-0000-000000000002', email_enc=crypto.encrypt("ops@sentrail.dev", None, "email"),
                          email_bidx=crypto.blind_index("ops@sentrail.dev"),
                          extra={"password_hash": passwords.hash_password("break glass passphrase here"),
                                 "totp_secret_enc": crypto.encrypt(secret, None, "totp"), "mfa_enabled": True})
r = c.post("/auth/login", json={"email": "ops@sentrail.dev", "password": "break glass passphrase here"})
ok(r.status_code == 200 and "mfa_token" in r.json(), "master break-glass login still works if Keycloak is down")

# suspension reaches Keycloak (signed in as the org admin)
_, p = start(); finish(p, leah_sub, "leah.chen@northwindremit.ca")
tokA = c.post("/auth/refresh").json()["access_token"]
with pg.tx(org) as cur:
    cur.execute("SELECT id FROM users WHERE idp_subject=%s", (analyst_sub,)); aid = cur.fetchone()[0]
r = c.patch(f"/admin/users/{aid}", headers={"Authorization": "Bearer " + tokA}, json={"status": "suspended"})
ok(r.status_code == 200 and ("enabled", False) in PROVISIONED, "suspending a user also disables them in Keycloak and ends their sessions there")
