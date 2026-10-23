"""Screening, cases, STR workflow and the review fixes, end to end against PostgreSQL.
Chain data and the OFAC list are simulated; everything else is the real app and database.
Run (fresh migrated database): PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_cases_e2e.py"""
import os, io, time, subprocess, sys, uuid, pyotp, psycopg
from datetime import datetime, timezone
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from fastapi.testclient import TestClient

from app import pg
from app.main import app
from app.admin_api import provision_org
from app.connectors import risk_lists
from app.security import crypto, passwords, mfa
from app.security.middleware import limiter
from app.services import screening, wallet_trace

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
c = TestClient(app, base_url="https://testserver", raise_server_exceptions=False)

# ---------------- simulated chain + sanctions list ----------------
CLEAN = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"
SANCTIONED = "TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE"
BTC = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
now = datetime.now(timezone.utc).isoformat()
async def fake_history(address):
    return "tron", [{"from": "TOld0000000000000000000000000000001", "to": address, "amount": 5.0,
                     "timestamp": "2020-01-01T00:00:00+00:00"}], True
screening.fetch_history = fake_history
OFAC = {SANCTIONED: {"label": "OFAC sanctioned address", "source": "OFAC SDN"}}
async def ofac_ok(): return dict(OFAC)
risk_lists._fetch_ofac = ofac_ok

# ---------------- two organizations, users inserted with known TOTP secrets ----------------
PW = "correct horse battery staple"
with pg.tx(platform=True) as cur:
    nw, nw_roles = provision_org(cur, "Northwind Remit Inc.", "MSB", "M23456789", plan="enterprise")
    mr, mr_roles = provision_org(cur, "Maple Ridge", "MSB", "M24567810", plan="starter")
H = passwords.hash_password(PW)
def add_user(org, role_id, email):
    secret = mfa.new_secret()
    with pg.tx(org) as cur:
        cur.execute("""INSERT INTO users (org_id, role_id, email_enc, email_bidx, name_enc, password_hash, totp_secret_enc, mfa_enabled, status)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,true,'active') RETURNING id""",
                    (org, role_id, crypto.encrypt(email, org, "email"), crypto.blind_index(email),
                     crypto.encrypt(email.split("@")[0], org, "name"), H, crypto.encrypt(secret, org, "totp")))
        return str(cur.fetchone()[0]), secret
U = {}
for name, org, roles, role in [("admin", nw, nw_roles, "Tenant admin"), ("officer1", nw, nw_roles, "Compliance officer"),
                               ("officer2", nw, nw_roles, "Compliance officer"), ("analyst", nw, nw_roles, "Compliance analyst"),
                               ("auditor", nw, nw_roles, "Auditor (read-only)"), ("maple_admin", mr, mr_roles, "Tenant admin"),
                               ("sess1", nw, nw_roles, "Compliance analyst"), ("sess2", nw, nw_roles, "Compliance analyst"),
                               ("maple", mr, mr_roles, "Compliance officer")]:
    U[name] = (f"{name}@{'northwind' if org == nw else 'maple'}.ca", *add_user(org, roles[role], f"{name}@{'northwind' if org == nw else 'maple'}.ca"))

def login(name, client=c):
    email, uid, secret = U[name]
    r = client.post("/auth/login", json={"email": email, "password": PW}); assert r.status_code == 200, r.text
    r = client.post("/auth/mfa", json={"mfa_token": r.json()["mfa_token"], "code": pyotp.TOTP(secret).now()}); assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}
A, O1, O2, AN, AU, MA, MO = (login(n) for n in ["admin", "officer1", "officer2", "analyst", "auditor", "maple_admin", "maple"])

# ---------------- API keys ----------------
r = c.post("/admin/api-keys", headers=A, json={"label": "Ramp production"})
KEY = r.json()["api_key"]; PREFIX = r.json()["prefix"]
K = {"Authorization": "Bearer " + KEY}
keys = c.get("/admin/api-keys", headers=A).json()
ok(r.status_code == 200 and keys[0]["prefix"] == PREFIX and keys[0]["label"] == "Ramp production" and keys[0]["active"],
   "API keys can be listed with their label (no listing existed before)")
ok(c.post("/admin/api-keys", headers=MA, json={}).status_code == 403, "an organization whose plan lacks screening can't create screening keys")

# ---------------- screening ----------------
def screen(**kw):
    body = {"direction": "deposit", "customer_id": "CUST-77", "address": CLEAN, "amount": 50, "asset": "USDT",
            "travel_rule_ok": True, "self_hosted": False, **kw}
    return c.post("/screen", headers=K, json=body)
r = screen()
ok(r.status_code == 200 and r.json()["decision"] == "release", "a clean stablecoin deposit is released")
r = screen(address=BTC, amount=0.5, asset="BTC", travel_rule_ok=False)
ok(r.status_code == 400 and "fiat_value" in r.json()["detail"], "a BTC transfer without fiat_value is refused (no more comparing coins to 1,000)")
r = screen(address=BTC, amount=0.5, asset="BTC", fiat_value=41000, travel_rule_ok=False, client_ref="ramp-tx-1")
held = r.json()
ok(r.status_code == 200 and held["decision"] == "hold" and "Travel rule" in held["reasons"][0],
   "0.5 BTC worth 41,000 without travel-rule info is held (it used to be released)")
r2 = screen(address=BTC, amount=0.5, asset="BTC", fiat_value=41000, travel_rule_ok=False, client_ref="ramp-tx-1")
with pg.tx(nw) as cur:
    cur.execute("SELECT count(*) FROM alerts WHERE screening_id=%s", (held["screening_id"],)); n_alerts = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM screenings WHERE client_ref='ramp-tx-1'"); n_scr = cur.fetchone()[0]
ok(r2.json()["screening_id"] == held["screening_id"] and r2.json().get("replayed") and n_alerts == 1 and n_scr == 1,
   "a retried request with the same client_ref returns the stored answer and creates no second alert")
r = screen(address=SANCTIONED)
ok(r.json()["decision"] == "block", "a sanctioned wallet is blocked")
async def ofac_down(): return None
risk_lists._fetch_ofac = ofac_down
risk_lists._state.update(ofac={}, ofac_loaded_at=0.0, next_refresh=0.0)
r = screen(address=CLEAN, client_ref="ramp-tx-2")
ok(r.json()["decision"] == "hold" and r.json()["checks_complete"] is False,
   "if the sanctions list can't be loaded, the transfer is held, not released")
risk_lists._fetch_ofac = ofac_ok
risk_lists._state.update(next_refresh=0.0)

# ---------------- a screening alert opens (it used to be a 500) ----------------
held_alert = f"A-{held['screening_id']}"
r = c.get(f"/cases/{held_alert}", headers=AN)
ok(r.status_code == 200 and r.json()["source"] == "screening" and r.json()["screening"]["fiat_value"] == 41000.0,
   "an alert raised by screening opens, showing the screening details (was a 500 KeyError)")

# ---------------- case lifecycle ----------------
r = c.post("/cases/A-DOES-NOT-EXIST/decision", headers=AN, json={"decision": "false_positive", "reason": "looks fine"})
with psycopg.connect(SUPER) as o:
    n = o.execute("SELECT count(*) FROM audit_events WHERE target='A-DOES-NOT-EXIST'").fetchone()[0]
ok(r.status_code == 404 and n == 0, "deciding a non-existent alert is a 404 and writes no audit row (was 200 + audit)")
r = c.post(f"/cases/{held_alert}/str/submit", headers=AN, json={"final_text": "x" * 60})
ok(r.status_code == 409 and "Escalate" in r.json()["detail"], "an STR can't be submitted before the alert is escalated")

blocked_alert = c.get("/alerts", headers=AN).json()
blocked_alert = [a for a in blocked_alert if a["band"] == "high"][0]["id"]
r = c.post(f"/cases/{blocked_alert}/decision", headers=AN, json={"decision": "false_positive", "reason": "known customer wallet"})
r2 = c.post(f"/cases/{blocked_alert}/decision", headers=AN, json={"decision": "escalate", "reason": "changed my mind"})
r3 = c.post(f"/cases/{blocked_alert}/str/submit", headers=AN, json={"final_text": "x" * 60})
ok(r.status_code == 200 and r2.status_code == 409 and r3.status_code == 409,
   "a closed alert can't be decided again or get an STR")

r = c.post(f"/cases/{held_alert}/decision", headers=AN, json={"decision": "request_info", "reason": "asked for source of funds"})
r2 = c.post(f"/cases/{held_alert}/decision", headers=AN, json={"decision": "escalate", "reason": "no credible answer"})
ok(r.json()["status"] == "pending_info" and r2.json()["status"] == "escalated", "pending info can still be escalated")
STR = "Customer CUST-77 attempted to deposit 0.5 BTC worth 41,000 from a self-hosted wallet without travel-rule data."
r = c.post(f"/cases/{held_alert}/str/submit", headers=AN, json={"final_text": STR})
ok(r.status_code == 200, "an analyst submits the STR for an escalated alert")
ok(c.post(f"/cases/{held_alert}/str/approve", headers=AN).status_code == 403, "an analyst can't approve STRs")
c.post(f"/cases/{held_alert}/str/submit", headers=O1, json={"final_text": STR + " Revised."})
ok(c.post(f"/cases/{held_alert}/str/approve", headers=O1).status_code == 409, "the officer who revised the STR can't approve it (four-eyes)")
r = c.post(f"/cases/{held_alert}/str/approve", headers=O2)
ok(r.status_code == 200 and r.json()["status"] == "str_filed", "a second officer approves and files it")
r = c.post(f"/cases/{held_alert}/decision", headers=AN, json={"decision": "false_positive", "reason": "reopen attempt"})
ok(r.status_code == 409, "a filed STR's alert can't be closed or reopened by a later decision (was allowed)")

# ---------------- override, assign, export ----------------
held2 = screen(address=BTC, amount=0.1, asset="BTC", fiat_value=8000, travel_rule_ok=False, client_ref="ramp-tx-3").json()
ok(c.post(f"/screenings/{held2['screening_id']}/override", headers=AN, json={"action": "release", "reason": "analysts may not"}).status_code == 403,
   "an analyst can't override a held transfer (screening.override left the analyst template in access model v2)")
r = c.post(f"/screenings/{held2['screening_id']}/override", headers=O1, json={"action": "release", "reason": "travel rule data arrived"})
r2 = c.post(f"/screenings/{held2['screening_id']}/override", headers=O1, json={"action": "block", "reason": "second thoughts"})
released = screen(client_ref="ramp-tx-4").json()
r3 = c.post(f"/screenings/{released['screening_id']}/override", headers=O1, json={"action": "block", "reason": "trying anyway"})
ok(r.status_code == 200 and r2.status_code == 409 and r3.status_code == 409,
   "an officer can release a held transfer once; released or blocked transfers can't be overridden")
ok(c.get(f"/screenings/{held2['screening_id']}", headers=AU).json()["override"] == "release", "the override is recorded on the screening")
r = c.post(f"/cases/A-{held2['screening_id']}/assign", headers=O1, json={"user_id": U["analyst"][1]})
r2 = c.post(f"/cases/A-{held2['screening_id']}/assign", headers=O1, json={"user_id": U["auditor"][1]})
ok(r.status_code == 200 and r2.status_code == 409, "cases can be assigned, but only to people who can work cases")
r = c.get(f"/cases/{held_alert}/export", headers=O1, params={"reason": "FINTRAC examination request"})
ok(r.status_code == 200 and r.json()["str"]["final_text"].endswith("Revised.") and r.json()["str"]["status"] == "approved",
   "an officer exports the filed case with the decrypted STR")
ok(c.get(f"/cases/{held_alert}/export", headers=AN, params={"reason": "curious"}).status_code == 403, "an analyst can't export")

# ---------------- tenant isolation of case data ----------------
ok(c.get(f"/cases/{held_alert}", headers=MO).status_code == 404, "another organization can't open this alert")
r = c.get("/search", headers=MO, params={"q": "C-2291", "reason": "test search"})
ok(r.status_code == 200 and r.json()["customers"] == [] and "No transaction history" in r.json()["note"],
   "an organization without its own data can't search customers from the shared demo dataset")

# ---------------- revoke ----------------
ok(c.delete(f"/admin/api-keys/{PREFIX}", headers=A).status_code == 200 and screen(client_ref="ramp-tx-5").status_code == 401,
   "a revoked API key stops working immediately (revocation didn't exist)")

# ---------------- input handling ----------------
ok(c.get("/admin/audit", headers=AU, params={"limit": -1}).status_code == 422, "audit limit=-1 is a 422 (was a database error 500)")
ok(c.get("/wallets/" + CLEAN + "/trace", headers=AN, params={"hops": 9}).status_code == 422, "trace hops above 3 are a 422")
r = c.post("/upload", headers=O1, params={"customer_id": "CUST-77"}, files={"file": ("s.csv", b"amount,direction\n100,in\n")})
ok(r.status_code == 400 and "timestamp" in r.json()["detail"], "a statement without a timestamp column is a 400 (was a 500)")
csv = b"timestamp,amount,direction,counterparty_id\n" + b"".join(
    f"2024-05-0{i+1} 10:00,9500,in,P{i}\n".encode() for i in range(4))
r = c.post("/upload", headers=O1, params={"customer_id": "CUST-77"}, files={"file": ("s.csv", csv)})
ok(r.status_code == 200 and any(h["rule"] == "Structuring" for h in r.json()["rule_hits"]), "a valid statement is scored (structuring found)")
r = c.post("/auth/discover", json={"email": "a+b@northwind.ca"})
ok("%2B" in r.json()["next"], "an email with '+' is URL-encoded in the sign-in link")
r = c.options("/me/sessions/x", headers={"Origin": os.environ.get("APP_URL", "http://localhost:5173"),
                                         "Access-Control-Request-Method": "DELETE"})
ok(r.status_code == 200 and "DELETE" in r.headers.get("access-control-allow-methods", ""), "the browser may call DELETE (ending a session)")

# ---------------- security settings: partial update keeps the rest ----------------
c.put("/admin/security", headers=A, json={"min_password_len": 20})
r = c.put("/admin/security", headers=A, json={"idle_timeout_min": 10})
s = c.get("/admin/security", headers=A).json()
ok(r.status_code == 200 and s["min_password_len"] == 20 and s["idle_timeout_min"] == 10,
   "changing one security setting no longer resets the others to defaults")

# ---------------- idle timeout and session length are enforced ----------------
c5 = TestClient(app, base_url="https://testserver")
login("sess1", c5)
with psycopg.connect(SUPER, autocommit=True) as o:
    o.execute("UPDATE refresh_tokens SET created_at = now() - interval '11 minutes' WHERE user_id=%s AND revoked_at IS NULL",
              (U["sess1"][1],))
ok(c5.post("/auth/refresh").status_code == 401, "a session idle longer than the organization's timeout (10 min) can't be refreshed")
c6 = TestClient(app, base_url="https://testserver")
login("sess2", c6)
ok(c6.post("/auth/refresh").status_code == 200, "an active session still refreshes")
with psycopg.connect(SUPER, autocommit=True) as o:
    o.execute("UPDATE refresh_tokens SET created_at = created_at - interval '13 hours' WHERE user_id=%s", (U["sess2"][1],))
    o.execute("UPDATE refresh_tokens SET created_at = now() WHERE user_id=%s AND revoked_at IS NULL", (U["sess2"][1],))
ok(c6.post("/auth/refresh").status_code == 401, "a session older than the platform maximum (12 h) ends even if active")

# ---------------- sign-in throttling ----------------
attacker = TestClient(app, base_url="https://testserver", client=("203.0.113.9", 4000))
for i in range(5):
    attacker.post("/auth/login", json={"email": "nobody@northwind.ca", "password": f"guess number {i} here"})
    attacker.post("/auth/login", json={"email": U["auditor"][0], "password": f"guess number {i} here"})
r_unknown = attacker.post("/auth/login", json={"email": "nobody@northwind.ca", "password": "guess again here"})
r_known = attacker.post("/auth/login", json={"email": U["auditor"][0], "password": PW})
ok(r_unknown.status_code == r_known.status_code == 429 and r_unknown.json() == r_known.json(),
   "unknown and real emails lock the same way, so a 429 doesn't reveal that an account exists")
owner = TestClient(app, base_url="https://testserver", client=("198.51.100.20", 4000))
r = owner.post("/auth/login", json={"email": U["auditor"][0], "password": PW})
ok(r.status_code == 200, "the real user, from their own network, can still sign in while the attacker is locked out")

# ---------------- audit chain still verifies after all of this ----------------
v = c.get("/admin/audit/verify", headers=AU).json()
ok(v["ok"] and v["events"] > 20, f"audit chain verifies ({v.get('events')} events)")

# ---------------- production is the default ----------------
# Blank rather than remove them: app/config.py loads .env, which would otherwise put a developer's ENV=dev back
# (python-dotenv never overrides a variable that is already set, even to an empty value).
env = {**os.environ, "ENV": "", "SENTRAIL_JWT_PRIVATE_KEY": ""}
out = subprocess.run([sys.executable, "-c", "from app import config; from app.security import tokens\n"
                      "print(config.IS_DEV)\ntry:\n    tokens._keys(); print('key')\nexcept RuntimeError: print('refused')"],
                     env={**env, "PYTHONPATH": os.getcwd()}, capture_output=True, text=True, cwd=os.getcwd()).stdout.split()
ok(out == ["False", "refused"], "with ENV unset the app runs as production and refuses to start without a signing key")

# ---------------- two-factor: optional per organization, set up after sign-in ----------------
def add_password_user(org, role_id, email):
    with pg.tx(org) as cur:
        cur.execute("""INSERT INTO users (org_id, role_id, email_enc, email_bidx, name_enc, password_hash, status)
                       VALUES (%s,%s,%s,%s,%s,%s,'active') RETURNING id""",
                    (org, role_id, crypto.encrypt(email, org, "email"), crypto.blind_index(email),
                     crypto.encrypt(email.split("@")[0], org, "name"), H))
        return str(cur.fetchone()[0])
add_password_user(nw, nw_roles["Compliance officer"], "nomfa@northwind.ca")
add_password_user(nw, nw_roles["Tenant admin"], "nomfa.admin@northwind.ca")
cm = TestClient(app, base_url="https://testserver", raise_server_exceptions=False)
r = cm.post("/auth/login", json={"email": "nomfa@northwind.ca", "password": PW})
ok(r.status_code == 200 and r.json().get("mfa_enabled") is False and "access_token" in r.json(),
   "a user without two-factor signs in with the password and is told two-factor isn't set up")
NM = {"Authorization": "Bearer " + r.json()["access_token"]}
me = cm.get("/me", headers=NM).json()
ok(me["mfa_enabled"] is False and me["mfa_setup"] == "optional" and me["session_mfa"] is False,
   "/me reports mfa_enabled=false and that setup is optional in this organization")
ok(cm.get("/alerts", headers=NM).status_code == 200, "while it's optional, the user can skip it and work their alerts")
r = cm.post("/cases/A-none/str/approve", headers=NM)
ok(r.status_code == 403 and "two-factor" in r.json()["detail"], "without two-factor, approving an STR is refused")
ok(cm.get("/cases/A-none/export", headers=NM, params={"reason": "examiner request"}).status_code == 403,
   "without two-factor, exporting a case is refused")
r = cm.post("/auth/refresh")
ok(r.status_code == 200 and cm.get("/me", headers={"Authorization": "Bearer " + r.json()["access_token"]}).json()["session_mfa"] is False,
   "refreshing a password-only session doesn't upgrade it to a two-factor session")
NM = {"Authorization": "Bearer " + r.json()["access_token"]}

ca = TestClient(app, base_url="https://testserver", raise_server_exceptions=False)
NA = {"Authorization": "Bearer " + ca.post("/auth/login", json={"email": "nomfa.admin@northwind.ca", "password": PW}).json()["access_token"]}
ok(ca.get("/me", headers=NA).json()["mfa_setup"] == "optional" and ca.get("/admin/users", headers=NA).status_code == 200,
   "nobody is forced: an organization admin without two-factor works normally while the organization hasn't made it mandatory")

ok(c.put("/admin/security", headers=A, json={"mfa_required": True}).status_code == 200, "the org admin makes two-factor mandatory")
r = cm.get("/alerts", headers=NM)
ok(r.status_code == 403 and r.json()["detail"] == "Set up two-factor authentication to continue",
   "the same password-only session is now stopped until two-factor is set up")
ok(cm.get("/me", headers=NM).json()["mfa_setup"] == "required", "/me now says setup is required")

s = cm.post("/me/mfa/setup", headers=NM).json()
ok(s["otpauth_uri"].startswith("otpauth://totp/") and s["secret"], "setup returns the authenticator URI and key")
ok(cm.post("/me/mfa/confirm", headers=NM, json={"code": "000000"}).status_code == 401, "a wrong code doesn't turn two-factor on")
r = cm.post("/me/mfa/confirm", headers=NM, json={"code": pyotp.TOTP(s["secret"]).now()})
ok(r.status_code == 200 and len(r.json()["recovery_codes"]) == 8, "a correct code turns two-factor on and returns 8 recovery codes")
NM2 = {"Authorization": "Bearer " + r.json()["access_token"]}
with psycopg.connect(SUPER) as o:
    flag = o.execute("SELECT mfa_enabled FROM users WHERE email_bidx=%s", (crypto.blind_index("nomfa@northwind.ca"),)).fetchone()
ok(flag and flag[0] is True, "users.mfa_enabled is stored as true in the database")
ok(cm.get("/alerts", headers=NM).status_code == 401, "turning two-factor on ends the old password-only session")
me = cm.get("/me", headers=NM2).json()
ok(cm.get("/alerts", headers=NM2).status_code == 200 and me["mfa_enabled"] and me["mfa_setup"] is None and me["session_mfa"],
   "the new session is a two-factor session")
ok(cm.post("/me/mfa/setup", headers=NM2).status_code == 409, "two-factor can't be set up twice")
r = cm.post("/auth/login", json={"email": "nomfa@northwind.ca", "password": PW})
ok(r.status_code == 200 and "mfa_token" in r.json() and "access_token" not in r.json(),
   "from now on the password alone isn't enough: sign-in asks for the code")

uid = next(u["id"] for u in c.get("/admin/users", headers=A).json() if u["email"].startswith("n•••") and u["role"] == "Compliance officer")
ok(c.post(f"/admin/users/{uid}/reset-mfa", headers=A, json={"reason": "lost phone, ticket 4411"}).status_code == 200, "an admin resets two-factor")
r = cm.post("/auth/login", json={"email": "nomfa@northwind.ca", "password": PW})
ok(r.status_code == 200 and r.json().get("mfa_enabled") is False, "after a reset the user is asked to set two-factor up again")
c.put("/admin/security", headers=A, json={"mfa_required": False})

# ---------------- two-factor is the person's choice, and the database records it ----------------
with psycopg.connect(SUPER) as o:
    row = o.execute("SELECT mfa_enabled, mfa_enabled_at, totp_secret_enc IS NULL FROM users WHERE email_bidx=%s",
                    (crypto.blind_index("nomfa.admin@northwind.ca"),)).fetchone()
ok(row == (False, None, True), "db: a user who never turned two-factor on has mfa_enabled=false, no date and no stored secret")
BIDX = crypto.blind_index("nomfa.admin@northwind.ca")
cw = TestClient(app, base_url="https://testserver", raise_server_exceptions=False)
NW = {"Authorization": "Bearer " + cw.post("/auth/login", json={"email": "nomfa.admin@northwind.ca", "password": PW}).json()["access_token"]}
sec = cw.post("/me/mfa/setup", headers=NW).json()
with psycopg.connect(SUPER) as o:
    row = o.execute("SELECT mfa_enabled, mfa_enabled_at, totp_secret_enc IS NOT NULL FROM users WHERE email_bidx=%s", (BIDX,)).fetchone()
ok(row == (False, None, True), "db: while setup is unconfirmed the flag stays false (a secret is stored, nothing is enabled yet)")
r = cw.post("/me/mfa/confirm", headers=NW, json={"code": pyotp.TOTP(sec["secret"]).now()})
ok(r.status_code == 200, "the admin confirms a code and two-factor turns on")
with psycopg.connect(SUPER) as o:
    row = o.execute("SELECT mfa_enabled, mfa_enabled_at IS NOT NULL FROM users WHERE email_bidx=%s", (BIDX,)).fetchone()
ok(row == (True, True), "db: after confirming a code, mfa_enabled=true and mfa_enabled_at is stamped")
users = {u["email"]: u for u in c.get("/admin/users", headers=A).json()}
ok(any(u["mfa"] and u["mfa_enabled_at"] for u in users.values()), "the user list shows who enabled two-factor and when")
with psycopg.connect(SUPER, autocommit=True) as o:
    before = o.execute("SELECT mfa_enabled_at FROM users WHERE email_bidx=%s", (BIDX,)).fetchone()[0]
    o.execute("UPDATE users SET last_login_at=now() WHERE email_bidx=%s", (BIDX,))
    after = o.execute("SELECT mfa_enabled_at FROM users WHERE email_bidx=%s", (BIDX,)).fetchone()[0]
    ok(before == after, "db: unrelated updates keep the original two-factor date")
    try:
        o.execute("UPDATE users SET totp_secret_enc=NULL WHERE email_bidx=%s", (BIDX,))
        rejected = False
    except psycopg.errors.CheckViolation:
        rejected = True
    ok(rejected, "db: two-factor can't be on without a stored authenticator secret")
    o.execute("UPDATE users SET mfa_enabled=false, totp_secret_enc=NULL WHERE email_bidx=%s", (BIDX,))
    cleared = o.execute("SELECT mfa_enabled_at FROM users WHERE email_bidx=%s", (BIDX,)).fetchone()[0]
    ok(cleared is None, "db: turning it off clears the date")

# ---------------- sign-in by people who aren't (or can't be) signed in ----------------
cx = TestClient(app, base_url="https://testserver", raise_server_exceptions=False)
unknown = cx.post("/auth/login", json={"email": "stranger@nowhere.example", "password": "whatever long enough pw"})
wrong = cx.post("/auth/login", json={"email": "nomfa.admin@northwind.ca", "password": "not the right password"})
ok(unknown.status_code == 401 and wrong.status_code == 401 and unknown.json() == wrong.json() == {"detail": "Email or password is incorrect"},
   "an unknown email and a wrong password get the identical 401, so nobody can tell whether an account exists")
r = cx.post("/auth/login", json={"email": "not-an-email", "password": "x"})
ok(r.status_code == 422, "a malformed email is a clean 422, not a server error")
ok(cx.post("/auth/login", json={"email": "a@b.example"}).status_code == 422, "a missing password is a clean 422")
ok(cx.post("/auth/login", content=b"not json", headers={"Content-Type": "application/json"}).status_code == 422, "a body that isn't JSON is a clean 422")
ok(cx.post("/auth/login", json={"email": "a@b.example", "password": "x" * 300}).status_code == 422, "an oversized password is refused before any hashing")
uid_susp = add_password_user(nw, nw_roles["Compliance officer"], "suspended.user@northwind.ca")
with pg.tx(nw) as cur:
    cur.execute("UPDATE users SET status='suspended' WHERE id=%s", (uid_susp,))
r = cx.post("/auth/login", json={"email": "suspended.user@northwind.ca", "password": PW})
ok(r.status_code == 401 and r.json() == {"detail": "Email or password is incorrect"} and "access_token" not in r.text,
   "a suspended user, even with the right password, gets the same generic 401")
r = cx.post("/auth/mfa", json={"mfa_token": "garbage", "code": "123456"})
ok(r.status_code == 401 and r.json()["detail"] == "Sign-in expired. Start again", "a garbage two-factor token is a clean 401")
from app.security import tokens as _tokens
stale = _tokens.issue_mfa_pending(uuid.uuid4())
r = cx.post("/auth/mfa", json={"mfa_token": stale, "code": "123456"})
ok(r.status_code == 401, "a two-factor token for a user that doesn't exist is a clean 401, not a crash")
stale = _tokens.issue_mfa_pending(uid_susp)
r = cx.post("/auth/mfa", json={"mfa_token": stale, "code": "123456"})
ok(r.status_code == 401, "a two-factor token for a user without two-factor is a clean 401, not a crash")
for _ in range(7):
    last = cx.post("/auth/login", json={"email": "stranger2@nowhere.example", "password": "whatever long enough pw"})
ok(last.status_code == 429, "repeated guesses at an unknown email are throttled too")
