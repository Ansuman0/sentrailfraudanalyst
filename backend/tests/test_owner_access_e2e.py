"""Owner access sessions, second-owner approvals and the break-glass account (phase 5). Real app, real database.
Needs a fresh migrated database. Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_owner_access_e2e.py"""
import logging
import os
import pyotp
import psycopg
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from fastapi.testclient import TestClient
from app import pg
from app.main import app
from app.access import catalogue as cat
from app.admin_api import provision_org
from app.security import crypto
from app.security.middleware import limiter
from helpers_access import CSRF, PW, add_user, bearer, claims, code_at, password_login, password_token, sql, two_factor_token

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)

records = []
class Capture(logging.Handler):
    def emit(self, record): records.append(record)
logging.getLogger("sentrail.notify").addHandler(Capture()); logging.getLogger("sentrail.notify").setLevel(logging.INFO)
notices = lambda kind: [r for r in records if getattr(r, "kind", None) == kind]


def chain(org):
    return sql(SUPER, "SELECT action, detail, actor_id::text FROM audit_events WHERE org_id IS NOT DISTINCT FROM %s ORDER BY seq", org)


with pg.tx(platform=True) as cur:
    A, ar = provision_org(cur, "Access Alpha", "MSB", "M3000001", plan="enterprise")
    B, br = provision_org(cur, "Access Beta", "MSB", "M3000002", plan="enterprise")
S = {n: pyotp.random_base32() for n in ("owner1", "admin_a", "support")}
owner1 = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "owner1@access5.example.com", secret=S["owner1"])
owner2 = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "owner2@access5.example.com")
add_user(None, cat.PLATFORM_SUPPORT_ROLE_ID, "support@access5.example.com", secret=S["support"])
admin_a = add_user(A, ar[cat.TENANT_ADMIN], "admin@access5.example.com", secret=S["admin_a"])
analyst_a = add_user(A, ar["Compliance analyst"], "analyst@access5.example.com")
add_user(B, br[cat.TENANT_ADMIN], "admin-b@access5.example.com")
with pg.tx(A) as cur:
    cur.execute("""INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel, status)
                   VALUES ('OA-1', %s, 'C-1', 70, 'high', '[]', 'bank', 'awaiting_approval')""", (A,))
    cur.execute("INSERT INTO str_drafts (org_id, alert_id, final_enc, drafted_by, status) VALUES (%s,'OA-1',NULL,%s,'awaiting_approval')", (A, owner1))
with pg.tx(B) as cur:
    cur.execute("""INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel) VALUES ('OB-1', %s, 'C-2', 70, 'high', '[]', 'bank')""", (B,))

O1 = bearer(two_factor_token(c, "owner1@access5.example.com", S["owner1"]))     # signed in once; the session moves between console and tenants
O2 = bearer(password_token(c, "owner2@access5.example.com"))
SUP = bearer(two_factor_token(c, "support@access5.example.com", S["support"]))
ADMIN = bearer(two_factor_token(c, "admin@access5.example.com", S["admin_a"]))
ANALYST = bearer(password_token(c, "analyst@access5.example.com"))
tok_state = {"o1": O1, "o2": O2}


def enter(org, who="o1"):
    """An owner moves from wherever they are into a tenant (or the console with None); returns the response."""
    r = c.post("/session/tenant", headers=tok_state[who], json={"tenant_id": str(org) if org else None})
    if r.status_code == 200:
        tok_state[who] = bearer(r.json()["access_token"])
    return r


def sessions(org=A):
    return sql(SUPER, "SELECT id::text, status, extended, legal_hold FROM tenant_access_sessions WHERE tenant_id=%s ORDER BY requested_at", org)


# ======================= mode: allow =======================
print("# owner access: allow")
ok(c.post(f"/platform/orgs/{A}/access", headers=SUP, json={"reason": "support wants in"}).status_code == 403, "platform support can't request tenant access")
ok(c.post(f"/platform/orgs/{A}/access", headers=O1, json={"reason": "x"}).status_code == 422, "a reason is required")
ok(c.post("/session/tenant", headers=tok_state["o1"], json={"tenant_id": str(A)}).status_code == 403, "without a session an owner can't enter a tenant")
r = c.post(f"/platform/orgs/{A}/access", headers=O1, json={"reason": "ticket 501: customer asked us to look at a stuck alert"})
ok(r.status_code == 200 and r.json()["status"] == "active", "owner_access defaults to 'allow': the session starts at once")
SID = r.json()["session_id"]
mins = float(sql(SUPER, "SELECT extract(epoch FROM (expires_at - started_at))/60 FROM tenant_access_sessions WHERE id=%s", SID)[0][0])
ok(abs(mins - 60) < 1, f"it lasts 60 minutes ({mins:.0f})")
ok(c.post(f"/platform/orgs/{A}/access", headers=O1, json={"reason": "again please"}).status_code == 409, "an owner has one open session per tenant")
ok(len(notices("owner_access_started")) == 1, "the tenant's admin is told when it starts")
ok("owner_access_started" in [a for a, _, _ in chain(A)] and "owner_access_started" in [a for a, _, _ in chain(None)], "audited in the tenant's log and the platform's")
r = enter(A)
ok(r.status_code == 200 and claims(r.json()["access_token"])["asid"] == SID and claims(r.json()["access_token"])["tid"] == str(A), "the owner enters; the token carries the access session id")
me = c.get("/me", headers=tok_state["o1"]).json()
ok(me["tenant"]["name"] == "Access Alpha" and me["role"] == "Tenant admin" and me["access_session"]["id"] == SID and set(cat.TENANT_PERMS) <= set(me["permissions"]),
   "inside, the owner acts with Tenant admin rights and /me shows the access session")
ok(c.get("/cases/OA-1", headers=tok_state["o1"]).status_code == 200, "they can open the tenant's cases")
ok(c.get("/cases/OB-1", headers=tok_state["o1"]).status_code == 404, "and only that tenant's: another tenant's case is invisible")
tagged = [d for a, d, _ in chain(A) if a == "case_viewed" and d.get("access_session_id") == SID]
mirrored = [d for a, d, _ in chain(None) if a == "tenant_action" and d.get("access_session_id") == SID and d.get("action") == "case_viewed"]
ok(tagged and mirrored, "what they do is tagged with the session id in the tenant's log and mirrored into the platform's")
r = c.post("/cases/OA-1/str/approve", headers=tok_state["o1"])
ok(r.status_code == 409, "an owner can't approve an STR they drafted, even with Tenant admin rights")
ok(c.put("/admin/security", headers=tok_state["o1"], json={"owner_access": "deny"}).status_code == 403, "inside a tenant an owner can't change who may enter it")
ok(c.get("/admin/access-requests", headers=tok_state["o1"]).status_code == 200 and c.post(f"/admin/access-requests/{SID}/approve", headers=tok_state["o1"]).status_code == 403,
   "nor decide on access requests")
ok(c.get("/platform/orgs", headers=tok_state["o1"]).status_code == 403, "while inside, platform routes are closed (the session is a tenant session)")

# extension: once
r = c.post(f"/platform/access/{SID}/extend", headers=O2)
ok(r.status_code == 404, "another owner can't extend it")
ok(enter(None).status_code == 200, "the owner returns to the console")
r = c.post(f"/platform/access/{SID}/extend", headers=tok_state["o1"])
mins2 = float(sql(SUPER, "SELECT extract(epoch FROM (expires_at - started_at))/60 FROM tenant_access_sessions WHERE id=%s", SID)[0][0])
ok(r.status_code == 200 and abs(mins2 - 120) < 1, "one extension adds 60 minutes")
ok(c.post(f"/platform/access/{SID}/extend", headers=tok_state["o1"]).status_code == 409, "a second extension is refused")
ok("owner_access_extended" in [a for a, _, _ in chain(A)], "the extension is audited")

# end early
r = c.delete(f"/platform/access/{SID}", headers=tok_state["o1"])
ok(r.status_code == 200 and len(notices("owner_access_ended")) == 1, "the owner ends it early and the tenant's admin is told")
ok(enter(A).status_code == 403, "a new entry needs a live session")
ok("owner_access_ended" in [a for a, _, _ in chain(None)], "the end is in the platform log too")
# a colleague can cut an owner off while they are inside
r = c.post(f"/platform/orgs/{A}/access", headers=tok_state["o2"], json={"reason": "ticket 510: second owner looks at billing data"})
SIDX = r.json()["session_id"]
ok(enter(A, "o2").status_code == 200 and c.get("/alerts", headers=tok_state["o2"]).status_code == 200, "owner 2 works inside the tenant")
r = c.delete(f"/platform/access/{SIDX}", headers=tok_state["o1"])
ok(r.status_code == 200, "owner 1 ends owner 2's session")
r = c.get("/alerts", headers=tok_state["o2"])
ok(r.status_code == 401, "owner 2 is out at their next request")
tok_state["o2"] = bearer(password_token(c, "owner2@access5.example.com"))
O2 = tok_state["o2"]

# expiry
r = c.post(f"/platform/orgs/{A}/access", headers=tok_state["o1"], json={"reason": "ticket 502: second look"})
SID2 = r.json()["session_id"]
enter(A)
ok(c.get("/alerts", headers=tok_state["o1"]).status_code == 200, "a fresh session works")
sql(SUPER, "UPDATE tenant_access_sessions SET expires_at = now() - interval '1 minute' WHERE id=%s", SID2)
ended_before = len(notices("owner_access_ended"))
r = c.get("/alerts", headers=tok_state["o1"])
ok(r.status_code == 401 and "access session" in r.json()["detail"], "when it expires, access is cut at the next request")
ok(sql(SUPER, "SELECT status, ended_reason FROM tenant_access_sessions WHERE id=%s", SID2)[0] == ("ended", "expired"), "and the session is recorded as expired")
ok(len(notices("owner_access_ended")) == ended_before + 1, "the tenant's admin is told it ended")

# ======================= mode: require_approval =======================
print("# owner access: require approval")
ADMIN_A = ADMIN
ok(c.put("/admin/security", headers=ADMIN_A, json={"owner_access": "require_approval"}).status_code == 200, "a Tenant admin sets the tenant to require approval")
ok("owner_access_setting_changed" in [a for a, _, _ in chain(A)], "the setting change is audited")
# the owner signs in fresh for each scenario below: restore a console session first
r = c.post("/auth/login", json={"email": "owner1@access5.example.com", "password": PW})
r = c.post("/auth/mfa", json={"mfa_token": r.json()["mfa_token"], "code": code_at(S["owner1"], 1)})
tok_state["o1"] = bearer(r.json()["access_token"])
r = c.post(f"/platform/orgs/{A}/access", headers=tok_state["o1"], json={"reason": "ticket 503: needs approval first"})
ok(r.status_code == 200 and r.json()["status"] == "requested", "now the request waits for the tenant")
SID3 = r.json()["session_id"]
ok(len(notices("owner_access_requested")) == 1, "the tenant's admin is told about the request")
ok(enter(A).status_code == 403, "the owner can't enter before it is approved")
ok(c.get("/admin/access-requests", headers=ANALYST).status_code == 403, "an analyst can't see requests")
reqs = c.get("/admin/access-requests", headers=ADMIN_A).json()
ok(any(x["id"] == SID3 and x["status"] == "requested" for x in reqs), "the Tenant admin sees it in the app's list")
r = c.post(f"/admin/access-requests/{SID3}/deny", headers=ADMIN_A, json={"reason": "not now, we are in the middle of an audit"})
ok(r.status_code == 200 and sessions()[-1][1] == "denied" and enter(A).status_code == 403, "denying it keeps the owner out")
r = c.post(f"/platform/orgs/{A}/access", headers=tok_state["o1"], json={"reason": "ticket 504: audit is over now"})
SID4 = r.json()["session_id"]
ok(c.post(f"/admin/access-requests/{SID4}/approve", headers=ADMIN_A).status_code == 200, "approving it starts the session")
ok(enter(A).status_code == 200 and c.get("/cases/OA-1", headers=tok_state["o1"]).status_code == 200, "the owner can then work in the tenant")
ok(c.post(f"/admin/access-requests/{SID4}/approve", headers=ADMIN_A).status_code == 409, "a request is decided once")
ok(enter(None).status_code == 200, "back to the console")
r = c.delete(f"/admin/access-requests/{SID4}", headers=ADMIN_A)
ok(r.status_code == 200 and sessions()[-1][1] == "ended", "the tenant can cut a live session short itself")
r = c.post(f"/platform/orgs/{A}/access", headers=tok_state["o1"], json={"reason": "ticket 505: nobody answers this one"})
SID5 = r.json()["session_id"]
sql(SUPER, "UPDATE tenant_access_sessions SET request_expires_at = now() - interval '1 minute' WHERE id=%s", SID5)
c.get("/platform/access", headers=tok_state["o1"])
ok(sessions()[-1][1] == "denied", "a request nobody answers within 24 hours lapses")

# ======================= mode: deny + legal hold =======================
print("# owner access: deny and legal hold")
c.put("/admin/security", headers=ADMIN_A, json={"owner_access": "deny"})
r = c.post(f"/platform/orgs/{A}/access", headers=tok_state["o1"], json={"reason": "ticket 506: please let us in"})
ok(r.status_code == 403 and "legal hold" in r.json()["detail"], "'deny' refuses owners outright")
r = c.post(f"/platform/orgs/{A}/legal-hold", headers=tok_state["o1"], json={"hold": True, "reason": "court order 2026-77, counsel confirmed"})
ok(r.status_code == 200 and r.json()["pending"], "a legal hold is requested, not applied")
AID = r.json()["approval_id"]
ok(c.post(f"/platform/approvals/{AID}/approve", headers=tok_state["o1"]).status_code == 403, "the requesting owner can't approve it")
ok(c.post(f"/platform/orgs/{A}/access", headers=tok_state["o1"], json={"reason": "ticket 507: hold not approved yet"}).status_code == 403, "until a second owner approves, it stays closed")
ok(c.post(f"/platform/approvals/{AID}/approve", headers=O2).status_code == 200, "a second owner approves the hold")
ok(sql(SUPER, "SELECT legal_hold FROM organizations WHERE id=%s", A)[0][0] and "legal_hold_placed" in [a for a, _, _ in chain(A)], "the hold is recorded and audited in the tenant's log")
r = c.post(f"/platform/orgs/{A}/access", headers=tok_state["o1"], json={"reason": "ticket 508: under the court order"})
ok(r.status_code == 200 and r.json()["status"] == "active" and sessions()[-1][3] is True, "under a recorded legal hold the owner is let in, flagged as such")
ok(c.get("/admin/security", headers=ADMIN_A).json()["legal_hold"] is True, "and the tenant can see its hold")
c.delete(f"/platform/access/{r.json()['session_id']}", headers=tok_state["o1"])
ok(c.post(f"/platform/orgs/{A}/legal-hold", headers=O2, json={"hold": False, "reason": "order withdrawn by the court"}).status_code == 200, "lifting a hold also needs a second owner")
sql(SUPER, "UPDATE organizations SET owner_access='allow' WHERE id=%s", A)

# ======================= suspended tenant =======================
sql(SUPER, "UPDATE organizations SET status='suspended' WHERE id=%s", B)
ok(c.post(f"/platform/orgs/{B}/access", headers=tok_state["o1"], json={"reason": "ticket 509: suspended tenant"}).status_code == 409, "a suspended tenant can't be entered")
sql(SUPER, "UPDATE organizations SET status='active' WHERE id=%s", B)

# ======================= second-owner approvals =======================
print("# approvals")
r = c.post("/platform/invitations", headers=tok_state["o1"], json={"email": "owner3@access5.example.com", "role_id": cat.PLATFORM_OWNER_ROLE_ID})
ok(r.status_code == 200 and r.json().get("pending") and "dev_link" not in r.json(), "adding an owner is parked for a second owner")
ok(sql(SUPER, "SELECT count(*) FROM users WHERE org_id IS NULL AND status='invited'")[0][0] == 0, "nobody was invited yet")
aid = r.json()["approval_id"]
ok("owner3@access5.example.com" not in str(c.get("/platform/approvals", headers=O2).json()), "the approvals list never shows the email")
ok(c.post(f"/platform/approvals/{aid}/approve", headers=tok_state["o1"]).status_code == 403, "the requester can't approve")
r = c.post(f"/platform/approvals/{aid}/approve", headers=O2)
ok(r.status_code == 200 and r.json()["executed"] == "owner.add" and r.json().get("dev_link"), "a second owner approves: the invitation goes out")
r3 = c.post("/invitations/accept", json={"token": r.json()["dev_link"].split("#", 1)[1], "full_name": "Owner Three", "password": PW})
ok(r3.status_code == 200, "the new owner can accept it")
owner3 = str(sql(SUPER, "SELECT id FROM users WHERE email_bidx=%s", crypto.blind_index("owner3@access5.example.com"))[0][0])
r = c.patch(f"/platform/users/{owner3}", headers=tok_state["o1"], json={"status": "suspended"})
ok(r.status_code == 200 and r.json().get("pending"), "suspending an owner is parked for a second owner")
aid2 = r.json()["approval_id"]
ok(sql(SUPER, "SELECT status FROM users WHERE id=%s", owner3)[0][0] == "active", "nothing changed yet")
ok(c.post(f"/platform/approvals/{aid2}/approve", headers=O2).status_code == 200 and sql(SUPER, "SELECT status FROM users WHERE id=%s", owner3)[0][0] == "suspended",
   "the second owner's approval applies it")
r = c.patch(f"/platform/users/{owner3}", headers=tok_state["o1"], json={"status": "active"})
aid3 = r.json()["approval_id"]
sql(SUPER, "UPDATE platform_approvals SET expires_at = now() - interval '1 minute' WHERE id=%s", aid3)
ok(c.post(f"/platform/approvals/{aid3}/approve", headers=O2).status_code == 410, "an approval older than 24 hours is refused")
# the security baseline
base = c.get("/platform/security", headers=tok_state["o1"]).json()
tighter = {k: base[k] for k in ("min_password_len_floor", "max_idle_timeout_min", "max_session_hours", "retention_years_floor",
                                "passkeys_allowed", "platform_staff_passkey_only", "allowed_regions")}
tighter["min_password_len_floor"] = base["min_password_len_floor"] + 1
r = c.put("/platform/security", headers=tok_state["o1"], json=tighter)
ok(r.status_code == 200 and r.json().get("ok"), "tightening the baseline applies at once")
looser = {**tighter, "min_password_len_floor": 12, "max_session_hours": 24}
r = c.put("/platform/security", headers=tok_state["o1"], json=looser)
ok(r.status_code == 200 and r.json().get("pending"), "loosening it is parked for a second owner")
ok(sql(SUPER, "SELECT min_password_len_floor FROM platform_settings")[0][0] == tighter["min_password_len_floor"], "the baseline is unchanged until then")
r = c.post(f"/platform/approvals/{r.json()['approval_id']}/approve", headers=O2)
ok(r.status_code == 200 and sql(SUPER, "SELECT min_password_len_floor, max_session_hours FROM platform_settings")[0] == (12, 24), "a second owner's approval applies the looser baseline")
ok(c.put("/platform/security", headers=tok_state["o1"], json=looser).status_code == 200, "(the same values again are not a change)")

# ======================= break-glass =======================
print("# break-glass")
bg = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "breakglass@access5.example.com")
sql(SUPER, "UPDATE users SET break_glass=true WHERE id=%s", bg)
try:
    other = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "bg2@access5.example.com")
    sql(SUPER, "UPDATE users SET break_glass=true WHERE id=%s", other)
    ok(False, "only one break-glass account")
except psycopg.errors.UniqueViolation:
    ok(True, "there can be only one break-glass account (database)")
try:
    sql(SUPER, "UPDATE users SET break_glass=true WHERE id=%s", admin_a)
    ok(False, "break-glass must be a platform account")
except psycopg.errors.CheckViolation:
    ok(True, "a tenant user can't be the break-glass account (database)")
records.clear()
r = c.post("/auth/login", json={"email": "breakglass@access5.example.com", "password": PW})
BG = bearer(r.json()["access_token"])
ok(r.status_code == 200, "the sealed account signs in with its password")
ok(len(notices("break_glass_used")) >= 2, f"every other owner is alerted ({len(notices('break_glass_used'))} notices)")
ok("break_glass_used" in [a for a, _, _ in chain(None)], "and it is in the platform audit log")
me = c.get("/me", headers=BG).json()
ok(me["must_rotate"] is True, "/me says the password must be rotated")
r = c.get("/platform/orgs", headers=BG)
ok(r.status_code == 403 and "password" in r.json()["detail"].lower(), "until it is, nothing else works")
r = c.post("/me/password", headers=BG, json={"current_password": PW, "new_password": "short"})
ok(r.status_code == 422, "a weak new password is refused")
r = c.post("/me/password", headers=BG, json={"current_password": "not the password", "new_password": "a brand new long passphrase 77"})
ok(r.status_code == 401, "the current password must be right")
r = c.post("/me/password", headers=BG, json={"current_password": PW, "new_password": PW})
ok(r.status_code == 422, "the new password must differ")
records.clear()
r = c.post("/me/password", headers=BG, json={"current_password": PW, "new_password": "a brand new long passphrase 77"})
ok(r.status_code == 200 and "access_token" in r.json(), "rotating the password gives a fresh session")
ok(c.get("/me", headers=BG).status_code == 401, "the old session ended")
BG2 = bearer(r.json()["access_token"])
ok(c.get("/platform/orgs", headers=BG2).status_code == 200 and c.get("/me", headers=BG2).json()["must_rotate"] is False, "the account works again")
ok(len(notices("password_changed")) == 1, "the password change is notified")
ok(password_login(c, "breakglass@access5.example.com").status_code == 401, "the old password no longer works")
ok("auth.password_changed" in [a for a, _, _ in chain(None)], "and it is audited")

# an ordinary person changes their password
tok = password_token(c, "analyst@access5.example.com")
other_session = password_token(TestClient(app, headers=CSRF, base_url="https://testserver"), "analyst@access5.example.com")
r = c.post("/me/password", headers=bearer(tok), json={"current_password": PW, "new_password": "another long passphrase 123"})
ok(r.status_code == 200, "anyone can change their own password")
ok(c.get("/me", headers=bearer(other_session)).status_code == 401, "all their other sessions end")
