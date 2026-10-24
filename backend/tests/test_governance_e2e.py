"""Governance and data controls (phase 7): dormant memberships, access reviews, signed audit export, export controls, anomaly alerts, audit
streaming, offboarding (data export and removal), and the job runner. Real app, real database. Needs a fresh migrated database.
Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_governance_e2e.py"""
import hashlib
import hmac
import json
import os
import subprocess
import sys
import threading
import pyotp
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
import psycopg
from fastapi.testclient import TestClient
from app.access import members
from app import governance, jobs as runner, pg
from app.access import catalogue as cat, jobs as registry
from app.admin_api import provision_org
from app.main import app
from app.security import audit, crypto
from app.security.middleware import limiter
from app.services import notify
from helpers_access import CSRF, PW, add_user, bearer, code_at, password_login, password_token, sql, two_factor_token

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
new_client = lambda **kw: TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=bool(os.environ.get("RAISE")), **kw)
c = new_client()

SENT = []
notify.security_event = lambda to, kind, detail=None: SENT.append((to, kind, (detail or {}).get("where")))
told = lambda kind: [s for s in SENT if s[1] == kind]

n = [0]


def tenant(plan="enterprise", name=None):
    n[0] += 1
    with pg.tx(platform=True) as cur:
        org, roles = provision_org(cur, name or f"Gov {n[0]}", "MSB", f"M9{n[0]:06d}", plan=plan)
    return org, roles


def admin(org, roles, tag):
    secret = pyotp.random_base32()
    email = f"{tag}@gov.example.com"
    uid = add_user(org, roles[cat.TENANT_ADMIN], email, secret=secret)
    return uid, email, secret, bearer(two_factor_token(c, email, secret))


def relogin(email, secret, offset=0):
    """A fresh session for someone whose first one ended (an unused authenticator step, so the code isn't a replay)."""
    r = password_login(c, email)
    r = c.post("/auth/mfa", json={"mfa_token": r.json()["mfa_token"], "code": code_at(secret, offset)})
    assert r.status_code == 200, r.text
    return bearer(r.json()["access_token"])


def age(org, uid, days):
    sql(SUPER, "UPDATE tenant_memberships SET last_active_at = now() - make_interval(days => %s), created_at = now() - make_interval(days => %s) "
               "WHERE tenant_id=%s AND user_id=%s", days, days + 1, org, uid)


def status_of(org, uid):
    return sql(SUPER, "SELECT status FROM tenant_memberships WHERE tenant_id=%s AND user_id=%s", org, uid)[0][0]


def events(org, action):
    return sql(SUPER, "SELECT count(*) FROM audit_events WHERE org_id=%s AND action=%s", org, action)[0][0]


T, tr = tenant()
A1, a1_email, s1, ADMIN = admin(T, tr, "admin1")
A2, a2_email, s2, ADMIN2 = admin(T, tr, "admin2")
analyst = add_user(T, tr["Compliance analyst"], "analyst@gov.example.com")
analyst2 = add_user(T, tr["Compliance analyst"], "analyst2@gov.example.com")
auditor = add_user(T, tr["Auditor (read-only)"], "auditor@gov.example.com")
tok_analyst = bearer(password_token(c, "analyst@gov.example.com"))
tok_auditor = bearer(password_token(c, "auditor@gov.example.com"))
ok(c.get("/me", headers=tok_analyst).status_code == 200, "setup: an analyst is signed in")

# =============================== dormant memberships ===============================
print("# dormant memberships")
s = c.put("/admin/security", headers=ADMIN, json={"dormant_days": 29})
ok(s.status_code == 422, "a dormant period under 30 days is refused")
ok(c.get("/admin/security", headers=ADMIN).json()["dormant_days"] == 90, "the default dormant period is 90 days")
age(T, analyst, 60)
ok(governance.dormant_sweep(T)["suspended"] == 0 and status_of(T, analyst) == "active", "60 days idle is not dormant at 90 days")
ok(c.put("/admin/security", headers=ADMIN, json={"dormant_days": 30}).status_code == 200, "a tenant can shorten the period to 30 days")
r = governance.dormant_sweep(T)
ok(r["suspended"] == 1 and status_of(T, analyst) == "suspended", "the same 60 idle days now suspend the membership")
ok(c.get("/me", headers=tok_analyst).status_code == 401, "their open session ends at once")
ok(sql(SUPER, "SELECT count(*) FROM refresh_tokens WHERE user_id=%s AND revoked_at IS NULL", analyst)[0][0] == 0, "and their refresh tokens are revoked")
ok(events(T, "membership_dormant_suspended") == 1, "the suspension is audited")
ok(len(told("dormant_suspended")) == 2, "both Tenant admins are told")
ok(not any("analyst@gov.example.com" in (w or "") for _, _, w in told("dormant_suspended")), "the notice masks the person's email")
r = governance.dormant_sweep(T)
ok(r["suspended"] == 0, "a second sweep finds nothing new")
ok(c.patch(f"/admin/users/{analyst}", headers=ADMIN, json={"status": "active"}).status_code == 200 and status_of(T, analyst) == "active", "an admin reactivates them")
ok(governance.dormant_sweep(T)["suspended"] == 0 and status_of(T, analyst) == "active", "a reactivated person is not suspended again at once")
age(T, A1, 200); age(T, A2, 200)
r = governance.dormant_sweep(T)
admins_active = sql(SUPER, "SELECT count(*) FROM tenant_memberships m JOIN roles r ON r.id=m.role_id WHERE m.tenant_id=%s AND m.status='active' AND r.is_locked", T)[0][0]
ok(r["suspended"] == 1 and r["skipped"] == 1 and admins_active == 1, "of two idle Tenant admins one stays: the last admin is never suspended")
sql(SUPER, "UPDATE tenant_memberships SET status='active', last_active_at=now() WHERE tenant_id=%s", T)
sql(SUPER, "UPDATE users SET status='active' WHERE org_id=%s", T)
ADMIN, ADMIN2 = relogin(a1_email, s1), relogin(a2_email, s2)      # the suspended one lost its session

# =============================== access reviews ===============================
print("# access reviews")
ok(c.post("/admin/access-reviews", headers=tok_auditor, json={}).status_code == 403, "an auditor can't open a review")
ok(c.post("/admin/access-reviews", json={}).status_code == 401, "nor can anyone without a sign-in")
r = c.post("/admin/access-reviews", headers=ADMIN, json={"title": "Q4 review"})
RID = r.json()["id"]
ok(r.status_code == 200 and r.json()["items"] == 5, "an admin opens a review: every active member is in it (5 people)")
ok(c.post("/admin/access-reviews", headers=ADMIN, json={}).status_code == 409, "a second review can't be opened while one is open")
detail = c.get(f"/admin/access-reviews/{RID}", headers=ADMIN).json()
ok(len(detail["members"]) == 5 and all(m["decision"] is None for m in detail["members"]), "nobody has a decision yet")
ok("analyst@gov.example.com" not in json.dumps(detail) and any("a•••" in (m["email"] or "") or "•" in (m["email"] or "") for m in detail["members"]), "emails are masked in the review")
ok(c.put(f"/admin/access-reviews/{RID}/members/{A1}", headers=ADMIN, json={"decision": "keep"}).status_code == 403, "nobody reviews their own access")
ok(c.put(f"/admin/access-reviews/{RID}/members/{analyst}", headers=ADMIN, json={"decision": "change"}).status_code == 422, "'change' needs the new role")
ok(c.put(f"/admin/access-reviews/{RID}/members/{analyst}", headers=ADMIN, json={"decision": "change", "new_role_id": str(tr[cat.TENANT_ADMIN])}).status_code == 422,
   "the locked Tenant admin role can't be the outcome of a review")
ok(c.put(f"/admin/access-reviews/{RID}/members/{analyst}", headers=ADMIN, json={"decision": "keep", "note": "still on the team"}).status_code == 200, "keep")
ok(c.put(f"/admin/access-reviews/{RID}/members/{analyst2}", headers=ADMIN, json={"decision": "change", "new_role_id": str(tr["Compliance officer"])}).status_code == 200, "change")
ok(c.put(f"/admin/access-reviews/{RID}/members/{auditor}", headers=ADMIN, json={"decision": "remove"}).status_code == 200, "remove")
ok(c.post(f"/admin/access-reviews/{RID}/sign-off", headers=ADMIN).status_code == 409, "sign-off needs a decision for everyone")
ok(c.put(f"/admin/access-reviews/{RID}/members/{A2}", headers=ADMIN, json={"decision": "keep"}).status_code == 200, "the other admin is kept")
ok(c.put(f"/admin/access-reviews/{RID}/members/{A1}", headers=ADMIN2, json={"decision": "remove"}).status_code == 200, "a second admin can decide on the first")
ok(c.put(f"/admin/access-reviews/{RID}/members/{A2}", headers=ADMIN, json={"decision": "remove"}).status_code == 200, "and the first on the second (neither is the last admin yet)")
ok(c.post(f"/admin/access-reviews/{RID}/sign-off", headers=ADMIN).status_code == 409 and status_of(T, auditor) == "active",
   "removing both admins is refused at sign-off, and nothing was applied")
c.put(f"/admin/access-reviews/{RID}/members/{A2}", headers=ADMIN, json={"decision": "keep"})
ok(c.get("/me", headers=tok_auditor).status_code == 200, "before sign-off the auditor still has access")
r = c.post(f"/admin/access-reviews/{RID}/sign-off", headers=ADMIN)
ok(r.status_code == 200 and r.json()["keep"] == 2 and r.json()["change"] == 1 and r.json()["remove"] == 2, f"sign-off applies every decision {r.json()}")
ok(status_of(T, auditor) == "suspended" and c.get("/me", headers=tok_auditor).status_code == 401, "a removed member is suspended and signed out at once")
ok(sql(SUPER, "SELECT r.name FROM tenant_memberships m JOIN roles r ON r.id=m.role_id WHERE m.tenant_id=%s AND m.user_id=%s", T, analyst2)[0][0] == "Compliance officer", "a changed member has the new role")
ok(status_of(T, A1) == "suspended" and status_of(T, A2) == "active", "(admin 1 was removed by admin 2's decision; admin 2 remains)")
ok(events(T, "access_review_signed_off") == 1 and events(T, "access_review_remove") == 2 and events(T, "access_review_change") == 1, "the sign-off and each applied decision are audited")
ok(c.put(f"/admin/access-reviews/{RID}/members/{analyst}", headers=ADMIN2, json={"decision": "remove"}).status_code == 409, "a signed-off review can't be changed")
ok(c.post(f"/admin/access-reviews/{RID}/sign-off", headers=ADMIN2).status_code == 409, "or signed off twice")
ADMIN = ADMIN2
sql(SUPER, "UPDATE tenant_memberships SET status='active' WHERE tenant_id=%s AND user_id=%s", T, A1)
sql(SUPER, "UPDATE users SET status='active' WHERE id=%s", A1)

# overdue reminders and the automatic quarterly review
r = c.post("/admin/access-reviews", headers=ADMIN, json={"title": "Overdue one"})
RID2 = r.json()["id"]
sql(SUPER, "UPDATE access_reviews SET due_at = now() - interval '2 days' WHERE id=%s", RID2)
ok(any(x["overdue"] for x in c.get("/admin/access-reviews", headers=ADMIN).json() if x["id"] == RID2), "a review past its due date shows as overdue")
SENT.clear()
ok(governance.review_cycle(T)["reminded"] == 1 and events(T, "access_review_overdue") == 1 and len(told("access_review_overdue")) >= 1, "an overdue review raises a reminder (audited, admins told)")
ok(governance.review_cycle(T)["reminded"] == 0, "and not again the next hour")
sql(SUPER, "UPDATE access_reviews SET last_reminder_at = now() - interval '8 days' WHERE id=%s", RID2)
ok(governance.review_cycle(T)["reminded"] == 1, "a week later it reminds again")
sql(SUPER, "UPDATE access_reviews SET status='cancelled' WHERE id=%s", RID2)
before_n = sql(SUPER, "SELECT count(*) FROM access_reviews WHERE tenant_id=%s", T)[0][0]
ok(governance.review_cycle(T)["opened"] == 0, "no new review while the last one is recent")
sql(SUPER, "UPDATE access_reviews SET opened_at = now() - interval '100 days' WHERE tenant_id=%s", T)
SENT.clear()
ok(governance.review_cycle(T)["opened"] == 1 and sql(SUPER, "SELECT count(*) FROM access_reviews WHERE tenant_id=%s", T)[0][0] == before_n + 1,
   "a review older than the tenant's period is followed by a new one, opened by the system")
ok(len(told("access_review_opened")) >= 1, "the admins are told about it")
sql(SUPER, "UPDATE access_reviews SET status='cancelled' WHERE tenant_id=%s AND status='open'", T)
sql(SUPER, "UPDATE security_settings SET access_review_days=365 WHERE org_id=%s", T)
ok(governance.review_cycle(T)["opened"] == 0, "access_review_days longer than the gap keeps the cycle quiet")
sql(SUPER, "UPDATE security_settings SET access_review_days=90 WHERE org_id=%s", T)

# another tenant never sees these reviews
B, br = tenant(name="Gov Other")
b_secret = pyotp.random_base32()
add_user(B, br[cat.TENANT_ADMIN], "admin@other.example.com", secret=b_secret)
ADMIN_B = bearer(two_factor_token(c, "admin@other.example.com", b_secret))
ok(c.get(f"/admin/access-reviews/{RID}", headers=ADMIN_B).status_code == 404 and c.get("/admin/access-reviews", headers=ADMIN_B).json() == [], "another tenant can't see or open this tenant's review")
ok(c.put(f"/admin/access-reviews/{RID}/members/{analyst}", headers=ADMIN_B, json={"decision": "remove"}).status_code == 404, "nor decide on it")

# =============================== platform staff review ===============================
print("# platform staff review")
o1 = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "owner1@gov.example.com")
o2 = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "owner2@gov.example.com")
sup = add_user(None, cat.PLATFORM_SUPPORT_ROLE_ID, "support@gov.example.com")
aud = add_user(None, cat.PLATFORM_AUDITOR_ROLE_ID, "pauditor@gov.example.com")
O1 = bearer(password_token(c, "owner1@gov.example.com"))
ok(c.post("/platform/access-reviews", headers=ADMIN, json={}).status_code == 403, "a Tenant admin can't review platform staff")
r = c.post("/platform/access-reviews", headers=O1, json={"title": "Staff review"})
PR = r.json()["id"]
ok(r.status_code == 200 and r.json()["items"] >= 4, "an owner opens the staff review")
ok(c.put(f"/platform/access-reviews/{PR}/members/{o1}", headers=O1, json={"decision": "keep"}).status_code == 403, "an owner can't review themselves")
ok(c.put(f"/platform/access-reviews/{PR}/members/{o2}", headers=O1, json={"decision": "remove"}).status_code == 409, "removing an owner goes through second-owner approval, not a review")
ok(c.put(f"/platform/access-reviews/{PR}/members/{o2}", headers=O1, json={"decision": "keep"}).status_code == 200, "keep an owner")
ok(c.put(f"/platform/access-reviews/{PR}/members/{sup}", headers=O1, json={"decision": "remove"}).status_code == 200, "remove support staff")
ok(c.put(f"/platform/access-reviews/{PR}/members/{aud}", headers=O1, json={"decision": "keep"}).status_code == 200, "keep the auditor")
for m in c.get(f"/platform/access-reviews/{PR}", headers=O1).json()["members"]:
    if m["decision"] is None and m["user_id"] != o1:
        c.put(f"/platform/access-reviews/{PR}/members/{m['user_id']}", headers=O1, json={"decision": "keep"})
O2 = bearer(password_token(c, "owner2@gov.example.com"))
ok(c.put(f"/platform/access-reviews/{PR}/members/{o1}", headers=O2, json={"decision": "keep"}).status_code == 200, "the other owner reviews the first")
r = c.post(f"/platform/access-reviews/{PR}/sign-off", headers=O2)
ok(r.status_code == 200 and sql(SUPER, "SELECT status FROM users WHERE id=%s", sup)[0][0] == "suspended", "sign-off suspends the removed staff member")
ok(sql(SUPER, "SELECT count(*) FROM audit_events WHERE org_id IS NULL AND action='access_review_signed_off'")[0][0] == 1, "the platform log records the sign-off")

# =============================== signed audit export ===============================
print("# audit export")
ok(c.post("/admin/audit/export", headers=tok_auditor, json={}).status_code in (401, 403), "an auditor without audit.export gets no file (and is signed out by the review)")
ok(c.post("/admin/audit/export", json={}).status_code == 401, "no sign-in, no export")
r = c.post("/admin/audit/export", headers=ADMIN, json={"format": "json"})
ok(r.status_code == 200 and r.json()["download_path"].startswith("/me/exports/"), "an admin asks for the audit log and gets a one-time link")
LINK = r.json()
mins = float(sql(SUPER, "SELECT extract(epoch FROM (expires_at - created_at))/60 FROM export_links ORDER BY created_at DESC LIMIT 1")[0][0])
ok(14.9 < mins < 15.1, f"the link lasts 15 minutes ({mins:.1f})")
ok("audit_exported" not in (sql(SUPER, "SELECT content_enc FROM export_links ORDER BY created_at DESC LIMIT 1")[0][0] or "") and
   "gov.example.com" not in (sql(SUPER, "SELECT content_enc FROM export_links ORDER BY created_at DESC LIMIT 1")[0][0] or ""), "the file waits encrypted")
ok(c.get(LINK["download_path"], headers=ADMIN_B).status_code == 404, "another tenant's admin can't fetch it")
ok(c.get(LINK["download_path"], headers=tok_analyst).status_code in (401, 404), "nor can another person")
ok(c.get(LINK["download_path"]).status_code == 401, "nor anyone not signed in")
g = c.get(LINK["download_path"], headers=ADMIN)
doc = g.json() if g.status_code == 200 else {}
ok(g.status_code == 200 and g.headers["content-disposition"].startswith("attachment") and g.headers["cache-control"] == "no-store", "the person who asked fetches it")
ok(doc.get("chain", {}).get("verified") is True and len(doc["events"]) > 10, "the file says the audit chain verified, with every event")
ok(doc["watermark"]["exported_by"]["user_id"] == A2 and doc["watermark"]["tenant"]["id"] == str(T), "it is watermarked with who, which tenant, when")
ok(governance.verify_export(doc) == {"signature_ok": True, "events_intact": True}, "its signature and every event hash check out")
bad = json.loads(json.dumps(doc)); bad["events"][3]["action"] = "nothing_happened"
ok(governance.verify_export(bad)["events_intact"] is False and governance.verify_export(bad)["signature_ok"] is False, "a changed event is detected, and so is the changed signature")
bad2 = json.loads(json.dumps(doc)); bad2["watermark"]["exported_by"]["user_id"] = "someone-else"
ok(governance.verify_export(bad2)["signature_ok"] is False, "a changed watermark breaks the signature")
ok(c.get(LINK["download_path"], headers=ADMIN).status_code == 410, "the link works once")
ok(sql(SUPER, "SELECT content_enc IS NULL FROM export_links ORDER BY created_at LIMIT 1")[0][0], "the content is deleted when fetched")
r = c.post("/admin/audit/export", headers=ADMIN, json={"format": "json"})
sql(SUPER, "UPDATE export_links SET expires_at = now() - interval '1 minute' WHERE id=(SELECT id FROM export_links ORDER BY created_at DESC LIMIT 1)")
ok(c.get(r.json()["download_path"], headers=ADMIN).status_code == 410, "an expired link is refused")
r = c.post("/admin/audit/export", headers=ADMIN, json={"format": "csv"})
csv_text = c.get(r.json()["download_path"], headers=ADMIN).text
lines = csv_text.strip().split("\n")
ok(lines[0].startswith("# Sentrail audit export") and "verified=True" in lines[1] and lines[2].startswith("seq,at,actor") and lines[-1].startswith("# signature=HMAC-SHA256:"), "CSV carries the watermark, the chain result and a signature")
body = "\n".join(lines[:-1]) + "\n"
ok(lines[-1].split(":", 1)[1] == governance.sign(body.encode()), "and the CSV signature matches its content")
r = c.post("/admin/audit/export", headers=ADMIN, json={"format": "json", "since": "2999-01-01T00:00:00Z"})
ok(len(c.get(r.json()["download_path"], headers=ADMIN).json()["events"]) == 0, "a date range outside the log gives an empty (still signed) file")
ok(c.post("/admin/audit/export", headers=ADMIN, json={"format": "xml"}).status_code == 422, "an unknown format is refused")
ok(events(T, "audit_exported") >= 4 and events(T, "export_downloaded") >= 3, "every export and download is audited")
ok(governance.expire_exports(str(T))["cleared"] >= 0 and sql(SUPER, "SELECT count(*) FROM export_links WHERE content_enc IS NOT NULL AND expires_at < now()")[0][0] == 0,
   "the clean-up job clears expired content")

# =============================== export controls and anomaly alerts ===============================
print("# export controls")
sql(SUPER, "UPDATE export_links SET used_at = now() - interval '2 hours'")
with pg.tx(T) as cur:
    cur.execute("""INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel) VALUES ('GOV-1', %s, 'C-GOV', 80, 'high', '[]', 'crypto')""", (T,))
    cur.execute("""INSERT INTO str_drafts (org_id, alert_id, final_enc, drafted_by, status) VALUES (%s,'GOV-1',%s,%s,'draft')""",
                (T, crypto.encrypt("Reported suspicious pattern GOVSTR", T, "str"), A2))
made = sql(SUPER, "SELECT count(*) FROM audit_events WHERE org_id=%s AND actor_id=%s AND action IN ('case_exported','audit_exported','data_exported') AND at > now() - interval '1 hour'", T, A2)[0][0]
ok(c.put("/admin/security", headers=ADMIN, json={"export_limit_per_hour": made + 3}).status_code == 200, f"the hourly export limit is a tenant setting ({made + 3}; {made} already used)")
ok(c.put("/admin/security", headers=ADMIN, json={"export_limit_per_hour": 0}).status_code == 422, "a limit of 0 is refused")
r = c.get("/cases/GOV-1/export", headers=ADMIN, params={"reason": "examiner request"})
ok(r.status_code == 200 and r.json()["watermark"]["content"] == "case GOV-1" and r.json()["watermark"]["exported_by"]["user_id"] == A2, "a case export is watermarked")
ok("GOVSTR" in json.dumps(r.json()), "(and carries the decrypted STR)")
ok(c.post("/admin/data-export", headers=tok_analyst).status_code in (401, 403), "an analyst can't export the tenant's data")
ok(c.post("/admin/data-export", headers=ADMIN).status_code == 200, "second counted export")
ok(c.post("/admin/audit/export", headers=ADMIN, json={}).status_code == 200, "third counted export")
r = c.post("/admin/audit/export", headers=ADMIN, json={})
ok(r.status_code == 429 and "Retry-After" in r.headers, "the next one is refused (cases, audit and tenant exports count together)")
ok(c.get("/cases/GOV-1/export", headers=ADMIN, params={"reason": "examiner request"}).status_code == 429, "also for a case export")
ok(events(T, "audit_exported") >= 5, "(refused attempts don't leave files)")
ok(sql(SUPER, "SELECT count(*) FROM export_links WHERE content_enc IS NOT NULL AND used_at IS NULL")[0][0] <= 2, "no file was produced by the refused ones")

print("# anomaly alerts")
SENT.clear()
sql(SUPER, "UPDATE security_settings SET export_limit_per_hour=500, anomaly_exports_per_hour=%s WHERE org_id=%s", made + 4, T)
ok(events(T, "anomaly_alert") == 0, "no alert yet")
for _ in range(3):
    c.post("/admin/audit/export", headers=ADMIN, json={})
ok(events(T, "anomaly_alert") == 1 and len(told("anomaly_alert")) >= 1, "exports above the threshold alert the Tenant admins")
n_alerts = events(T, "anomaly_alert")
c.post("/admin/audit/export", headers=ADMIN, json={})
ok(events(T, "anomaly_alert") == n_alerts, "once an hour per person, not on every export")
ok(c.put("/admin/security", headers=ADMIN, json={"anomaly_exports_per_hour": 1000, "anomaly_searches_per_hour": 5}).status_code == 200, "thresholds are tenant settings")
ok(c.put("/admin/security", headers=ADMIN, json={"anomaly_searches_per_hour": 2}).status_code == 422, "(with a floor, so they can't be set to alert on every click)")
SENT.clear()
tok_analyst = bearer(password_token(c, "analyst2@gov.example.com"))
codes = [c.get("/search", headers=tok_analyst, params={"q": f"customer-{i}", "reason": "routine check"}).status_code for i in range(7)]
ok(all(x in (200, 400) for x in codes) and events(T, "anomaly_alert") == n_alerts + 1, "searches above the threshold alert the admins too")
ok(sql(SUPER, "SELECT target, detail->>'threshold' FROM audit_events WHERE org_id=%s AND action='anomaly_alert' ORDER BY seq DESC LIMIT 1", T)[0] == ("search", "5"), "(the audit event records what was unusual and the threshold)")

os.environ["TRUST_COUNTRY_HEADER"] = "true"
ctry = lambda cc: (new_client().post("/auth/login", headers={"CF-IPCountry": cc} if cc else {}, json={"email": "analyst2@gov.example.com", "password": PW}).status_code)
base = events(T, "anomaly_alert")
ctry("CA"); ok(events(T, "anomaly_alert") == base, "the first country ever seen for a person is not an alert")
ctry("CA"); ok(events(T, "anomaly_alert") == base, "the same country again is not either")
ctry("DE"); ok(events(T, "anomaly_alert") == base + 1, "a new country alerts the Tenant admins")
ctry("DE"); ok(events(T, "anomaly_alert") == base + 1, "only the first time")
sql(SUPER, "UPDATE security_settings SET alert_new_country=false WHERE org_id=%s", T)
ctry("FR"); ok(events(T, "anomaly_alert") == base + 1, "alert_new_country=false silences it")
sql(SUPER, "UPDATE security_settings SET alert_new_country=true WHERE org_id=%s", T)
os.environ["TRUST_COUNTRY_HEADER"] = "false"
ctry("BR"); ok(events(T, "anomaly_alert") == base + 1 and sql(SUPER, "SELECT count(*) FROM user_countries WHERE country='BR'")[0][0] == 0,
               "without a trusted proxy the header is ignored (anyone can send it)")

# =============================== audit streaming ===============================
print("# audit streaming")
PRO, pr = tenant(plan="professional", name="Gov Pro")
psecret = pyotp.random_base32()
add_user(PRO, pr[cat.TENANT_ADMIN], "admin@pro.example.com", secret=psecret)
ADMIN_PRO = bearer(two_factor_token(c, "admin@pro.example.com", psecret))
ok(c.put("/admin/audit/stream", headers=ADMIN_PRO, json={"url": "https://siem.example.com/in"}).status_code == 403, "streaming is an Enterprise feature")
ok(c.put("/admin/audit/stream", headers=tok_analyst, json={"url": "https://siem.example.com/in"}).status_code in (401, 403), "and needs audit.export")
for bad_url in ("http://siem.example.com/in", "ftp://x", "https://10.1.2.3/in", "https://127.0.0.1/in", "https://169.254.169.254/latest", "notaurl"):
    if c.put("/admin/audit/stream", headers=ADMIN, json={"url": bad_url}).status_code != 422:
        ok(False, f"{bad_url} should be refused")
ok(True, "plain http, private, loopback and cloud-metadata addresses are refused")
try:
    governance.post_json("https://127.0.0.1/x", b"{}", {})
    refused = False
except RuntimeError:
    refused = True
ok(refused, "at delivery time a host that resolves to a private address is refused as well")

DELIVERED, FAIL = [], {"mode": None}


def fake_post(url, body, headers):
    if FAIL["mode"] == "raise":
        raise ConnectionError("down")
    if FAIL["mode"] == "500":
        return 500
    DELIVERED.append((url, body, headers))
    return 204


governance.post_json = fake_post
seq0 = sql(SUPER, "SELECT max(seq) FROM audit_events WHERE org_id=%s", T)[0][0]
r = c.put("/admin/audit/stream", headers=ADMIN, json={"url": "https://siem.example.com/in"})
SECRET = r.json()["signing_secret"]
ok(r.status_code == 200 and SECRET, "an admin sets the endpoint; the signing secret is shown once")
ok("signing_secret" not in c.get("/admin/audit/stream", headers=ADMIN).text and "siem.example.com" in c.get("/admin/audit/stream", headers=ADMIN).text, "and never again")
ok("signing_secret" not in c.put("/admin/audit/stream", headers=ADMIN, json={"url": "https://siem.example.com/in2"}).text, "changing the address keeps the same secret")
first = governance.stream_audit(str(T))
sent0 = [e["seq"] for e in json.loads(DELIVERED[0][1])["events"]] if DELIVERED else []
ok(sent0 and min(sent0) > seq0, "the history from before the stream was set up is never sent, only what happens after")
N0 = len(DELIVERED)
c.post("/admin/audit/export", headers=ADMIN, json={})
res = governance.stream_audit(str(T))
ok(res["sent"] >= 1 and len(DELIVERED) == N0 + 1, "new events are delivered")
url, body, headers = DELIVERED[-1]
payload = json.loads(body)
ok(payload["tenant"] == str(T) and all(e["org"] == str(T) for e in payload["events"]), "only this tenant's events, each with its seq and hash")
expected = "sha256=" + hmac.new(SECRET.encode(), headers["X-Sentrail-Timestamp"].encode() + b"." + body, hashlib.sha256).hexdigest()
ok(hmac.compare_digest(headers["X-Sentrail-Signature"], expected), "the receiver can verify the HMAC signature")
ok(governance.stream_audit(str(T))["sent"] == 0 and len(DELIVERED) == N0 + 1, "delivered events are not sent again")
c.post("/admin/audit/export", headers=ADMIN, json={})
FAIL["mode"] = "500"
ok(governance.stream_audit(str(T))["sent"] == 0 and c.get("/admin/audit/stream", headers=ADMIN).json()["failures"] == 1, "a failing receiver is counted")
FAIL["mode"] = "raise"
governance.stream_audit(str(T))
ok(c.get("/admin/audit/stream", headers=ADMIN).json()["failures"] == 2 and "ConnectionError" in c.get("/admin/audit/stream", headers=ADMIN).json()["last_error"], "a network error is too")
FAIL["mode"] = None
before_seq = c.get("/admin/audit/stream", headers=ADMIN).json()["delivered_up_to"]
governance.stream_audit(str(T))
st = c.get("/admin/audit/stream", headers=ADMIN).json()
ok(st["delivered_up_to"] > before_seq and st["failures"] == 0 and len(DELIVERED) == N0 + 2, "when it recovers the missed events arrive, at least once, and the failure count resets")
sql(SUPER, "UPDATE audit_streams SET failures=49 WHERE tenant_id=%s", T)
c.post("/admin/audit/export", headers=ADMIN, json={})
FAIL["mode"] = "500"
governance.stream_audit(str(T))
ok(c.get("/admin/audit/stream", headers=ADMIN).json()["enabled"] is False and events(T, "audit_stream_disabled") == 1, "after 50 failures in a row the stream switches itself off (audited)")
FAIL["mode"] = None
ok(governance.stream_audit(str(T)) == {"sent": 0}, "a switched-off stream sends nothing")
ok(c.delete("/admin/audit/stream", headers=ADMIN).status_code == 200 and c.get("/admin/audit/stream", headers=ADMIN).json() == {"configured": False}, "an admin removes it")
ok(c.delete("/admin/audit/stream", headers=ADMIN).status_code == 404, "(and removing nothing says so)")

# =============================== retention ===============================
print("# retention")
ok(c.put("/admin/security", headers=ADMIN, json={"retention_years": 4}).status_code == 422, "retention below the platform minimum (5 years) is refused")
ok(c.put("/admin/security", headers=ADMIN, json={"retention_years": 9}).status_code == 200, "and can be raised")
try:
    with pg.tx(T) as cur:
        cur.execute("SELECT purge_tenant_audit(%s)", (T,))
    refused = False
except psycopg.errors.Error:
    refused = True
ok(refused, "the audit log of a tenant that isn't deleted can't be removed")
try:
    sql(SUPER, "DELETE FROM audit_events WHERE org_id=%s", T)
    deleted = True
except psycopg.errors.Error:
    deleted = False
ok(not deleted, "and the table stays append-only for everyone else, even a superuser")

# =============================== offboarding ===============================
print("# offboarding")
r = c.post("/admin/data-export", headers=ADMIN)
EXP = r.json()
ok(r.status_code == 200, "a Tenant admin starts a full data export")
sql(SUPER, "UPDATE security_settings SET export_limit_per_hour=500 WHERE org_id=%s", T)
full = c.get(EXP["download_path"], headers=ADMIN).json()
flat = json.dumps(full)
ok({"organization", "members", "roles", "cases", "str_reports", "screenings", "audit", "security_settings", "api_keys"} <= set(full), "it holds the organization, people, roles, cases, STRs, screenings, settings and the audit log")
ok(any(m["email"] == "analyst@gov.example.com" for m in full["members"]) and any("GOVSTR" in (s["final_text"] or "") for s in full["str_reports"]), "people and STRs are readable (decrypted) for the tenant's own export")
ok(full["audit"]["chain"]["ok"] and governance.verify_export({"events": full["audit"]["events"], "signature": {}})["events_intact"], "the audit chain verifies inside the export")
ok(all(w not in flat.lower() for w in ("password_hash", "totp_secret", "key_hash", "token_hash", "public_key")), "no password hash, authenticator seed, key hash or passkey is in it")
body_wo_sig = {k: v for k, v in full.items() if k != "signature"}
ok(hmac.compare_digest(full["signature"]["value"], governance.sign(governance._canonical_doc(body_wo_sig))), "the whole file is signed")
ok(events(T, "data_exported") >= 1, "the export is audited")

# a throwaway tenant to delete: people, cases, SCIM token, review, stream, API key, and a person who also works for T
D, dr = tenant(name="Gov To Delete")
dsecret = pyotp.random_base32()
add_user(D, dr[cat.TENANT_ADMIN], "admin@delete.example.com", secret=dsecret)
shared = add_user(D, dr["Compliance analyst"], "shared@delete.example.com")
add_user(D, dr["Compliance analyst"], "gone@delete.example.com")
sql(SUPER, "INSERT INTO tenant_memberships (user_id, tenant_id, role_id, status) VALUES (%s,%s,%s,'active')", shared, T, tr["Compliance analyst"])
ADMIN_D = bearer(two_factor_token(c, "admin@delete.example.com", dsecret))
c.post("/admin/api-keys", headers=ADMIN_D, json={"label": "ramp"})
c.post("/admin/scim/tokens", headers=ADMIN_D, json={"label": "idp"})
c.post("/admin/access-reviews", headers=ADMIN_D, json={})
c.put("/admin/audit/stream", headers=ADMIN_D, json={"url": "https://siem.example.com/d"})
with pg.tx(D) as cur:
    cur.execute("INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel) VALUES ('D-1', %s, 'C-D', 90, 'high', '[]', 'crypto')", (D,))
    cur.execute("INSERT INTO screenings (id, org_id, customer_id, direction, address, amount, score, decision, reasons) VALUES ('D-S1', %s, 'C-D', 'out', 'addr', 1, 10, 'release', '[]')", (D,))
c.post("/admin/audit/export", headers=ADMIN_D, json={})
d_events = sql(SUPER, "SELECT count(*) FROM audit_events WHERE org_id=%s", D)[0][0]
t_events_before = sql(SUPER, "SELECT count(*) FROM audit_events WHERE org_id=%s", T)[0][0]
t_cases_before = sql(SUPER, "SELECT count(*) FROM alerts WHERE org_id=%s", T)[0][0]

ok2 = bearer(password_token(c, "owner2@gov.example.com"))
OA = bearer(password_token(c, "owner1@gov.example.com"))
aid = c.post(f"/platform/orgs/{D}/delete", headers=OA, json={"reason": "customer left the platform, contract ended"}).json()["approval_id"]
ok(c.post(f"/platform/approvals/{aid}/approve", headers=ok2).status_code == 200, "a second owner approves the deletion")
ok(sql(SUPER, "SELECT status FROM organizations WHERE id=%s", D)[0][0] == "deleted", "the tenant is deleted (data kept until retention passes)")
ok(governance.purge_deleted_tenants()["removed"] == [], "its data is not removed before the retention period is over")
ok(sql(SUPER, "SELECT count(*) FROM alerts WHERE org_id=%s", D)[0][0] == 1, "(the case is still there)")
sql(SUPER, "UPDATE organizations SET deletion_due_at = now() - interval '1 day' WHERE id=%s", D)
d_events = sql(SUPER, "SELECT count(*) FROM audit_events WHERE org_id=%s", D)[0][0]
res = governance.purge_deleted_tenants()
ok(res["removed"] == [str(D)], "once retention has passed the job removes the tenant's data")
leftovers = []
with psycopg.connect(SUPER, autocommit=True) as conn:
    for t, col in conn.execute("""SELECT table_name, column_name FROM information_schema.columns WHERE table_schema='public' AND column_name IN ('org_id','tenant_id')
                                  AND table_name NOT IN ('organizations')""").fetchall():
        k = conn.execute(f'SELECT count(*) FROM "{t}" WHERE "{col}"=%s', (D,)).fetchone()[0]
        if k:
            leftovers.append((t, k))
ok(leftovers == [("users", 1)], f"nothing carrying the tenant's id is left in any table (audit log included) except the person who also works elsewhere: {leftovers}")
ok(sql(SUPER, "SELECT count(*) FROM users WHERE email_bidx=%s", crypto.blind_index("gone@delete.example.com"))[0][0] == 0, "people who only worked there are gone")
ok(sql(SUPER, "SELECT count(*) FROM tenant_memberships WHERE user_id=%s AND tenant_id=%s AND status='active'", shared, T)[0][0] == 1, "a person who also works for another tenant keeps that membership")
ok(sql(SUPER, "SELECT count(*) FROM tenant_memberships m JOIN roles r ON r.id=m.role_id WHERE m.user_id=%s AND r.org_id=%s", shared, D)[0][0] == 0,
   "and nothing of theirs points at a removed role")
row = sql(SUPER, "SELECT legal_name, status, slug FROM organizations WHERE id=%s", D)[0]
ok(row[0] == "[removed]" and row[1] == "deleted" and row[2], "the organization row stays as a tombstone (its slug is never reused)")
rec = sql(SUPER, "SELECT detail FROM audit_events WHERE org_id IS NULL AND action='tenant_data_removed' AND target=%s", str(D))
ok(len(rec) == 1 and rec[0][0]["events_removed"] == d_events and rec[0][0]["audit_head_hash"] and rec[0][0]["retention_elapsed"], "the platform log has the deletion record with the tenant's final audit hash")
ok(sql(SUPER, "SELECT count(*) FROM audit_events WHERE org_id=%s", T)[0][0] == t_events_before and sql(SUPER, "SELECT count(*) FROM alerts WHERE org_id=%s", T)[0][0] == t_cases_before,
   "another tenant's data and log are untouched")
ok(governance.purge_deleted_tenants()["removed"] == [], "removing twice does nothing")
ok(c.get("/admin/audit/verify", headers=O1).status_code == 200 and c.get("/admin/audit/verify", headers=O1).json()["ok"], "the platform log still verifies")
ok(c.get("/admin/audit/verify", headers=ADMIN).json()["ok"], "and so does the other tenant's")

# =============================== the job runner ===============================
print("# job runner")
for name in ("dormant_sweep", "review_cycle", "audit_stream", "expire_exports"):
    ok(name in registry.TENANT_JOBS, f"tenant job registered: {name}")
for name in ("platform_review_cycle", "purge_deleted_tenants", "housekeeping"):
    ok(name in registry.GLOBAL_JOBS, f"global job registered: {name}")
registry.TENANT_JOBS["boom"] = lambda org: 1 / 0
res = runner.run_once()
ok("failed" in str(res["boom"]) or res["boom"]["failed"] >= 1, "a failing job is reported")
ok(all(k in res for k in ("dormant_sweep", "housekeeping", "purge_deleted_tenants")), "and does not stop the others")
runs = {r[0]: r[1] for r in sql(SUPER, "SELECT name, last_ok FROM job_runs")}
ok(runs.get("boom") is False and runs.get("dormant_sweep") is True, "what ran last, and whether it worked, is recorded")
del registry.TENANT_JOBS["boom"]
holder = psycopg.connect(SUPER, autocommit=True)
holder.execute("SELECT pg_advisory_lock(%s)", (runner.LOCK_KEY,))
# the lock belongs to a session on another connection; the runner uses the app role on the same server and cluster-wide lock space
res = runner.run_once({"housekeeping"})
holder.close()
ok(res == {"skipped": "another runner is working"}, "two runners never work at the same time")
ok("housekeeping" in runner.run_once({"housekeeping"}), "(and the lock is free again afterwards)")
out = subprocess.run([sys.executable, "-m", "scripts.run_jobs", "--only", "housekeeping"], capture_output=True, text=True, env=os.environ.copy(), cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ok(out.returncode == 0 and "housekeeping" in out.stdout, "python -m scripts.run_jobs runs jobs once from the command line")
