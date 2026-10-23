"""Authorization, phase 3: separation of duties, row-level security that knows the actor, restricted (need-to-know) cases,
read auditing, and the request check order. Real app, real database.
Needs a fresh migrated database. Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_authorization_e2e.py"""
import os
import uuid
import pyotp
import psycopg
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from fastapi.testclient import TestClient
from app import pg
from app.main import app
from app.access import catalogue as cat
from app.admin_api import provision_org
from app.security.middleware import limiter
from helpers_access import CSRF, add_user, bearer, password_token, sql, two_factor_token

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)


def actions(org, action=None):
    rows = sql(SUPER, "SELECT action, target, detail, actor_id::text FROM audit_events WHERE org_id=%s ORDER BY seq", org)
    return [r for r in rows if action is None or r[0] == action]


with pg.tx(platform=True) as cur:
    T, tr = provision_org(cur, "Authz Tenant", "MSB", "M5000001", plan="enterprise")
    U, ur = provision_org(cur, "Authz Other", "MSB", "M5000002", plan="enterprise")
S = {n: pyotp.random_base32() for n in ("admin", "admin2", "officer", "officer2", "owner_p", "psupport")}
admin = add_user(T, tr[cat.TENANT_ADMIN], "admin@authz.example.com", secret=S["admin"])
admin2 = add_user(T, tr[cat.TENANT_ADMIN], "admin2@authz.example.com", secret=S["admin2"])
officer = add_user(T, tr["Compliance officer"], "officer@authz.example.com", secret=S["officer"])
officer2 = add_user(T, tr["Compliance officer"], "officer2@authz.example.com", secret=S["officer2"])
analyst = add_user(T, tr["Compliance analyst"], "analyst@authz.example.com")
auditor = add_user(T, tr["Auditor (read-only)"], "auditor@authz.example.com")
outsider = add_user(U, ur["Compliance officer"], "outsider@authz.example.com")
owner = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "owner@authz.example.com")
psup = add_user(None, cat.PLATFORM_SUPPORT_ROLE_ID, "psupport@authz.example.com", secret=S["psupport"])

tok = {"admin": two_factor_token(c, "admin@authz.example.com", S["admin"]),
       "officer": two_factor_token(c, "officer@authz.example.com", S["officer"]),
       "officer2": two_factor_token(c, "officer2@authz.example.com", S["officer2"]),
       "analyst": password_token(c, "analyst@authz.example.com"),
       "auditor": password_token(c, "auditor@authz.example.com")}
H = {k: bearer(v) for k, v in tok.items()}


def case(alert_id, status="open", restricted=False, customer="C-1001"):
    with pg.tx(T) as cur:
        cur.execute("""INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel, status, restricted)
                       VALUES (%s,%s,%s,70,'high','[]','bank',%s,%s) ON CONFLICT DO NOTHING""", (alert_id, T, customer, status, restricted))


# ======================= separation of duties =======================
print("# separation of duties")
for who, uid_, label in (("admin", admin, "a Tenant admin"), ("officer", officer, "a compliance officer")):
    case(f"SOD-{who}", status="awaiting_approval")
    with pg.tx(T) as cur:
        cur.execute("INSERT INTO str_drafts (org_id, alert_id, final_enc, drafted_by, status) VALUES (%s,%s,NULL,%s,'awaiting_approval')", (T, f"SOD-{who}", uid_))
    r = c.post(f"/cases/SOD-{who}/str/approve", headers=H[who])
    ok(r.status_code == 409 and "drafted" in r.json()["detail"], f"{label} can't approve an STR they drafted (API)")
    try:
        sql(SUPER, "UPDATE str_drafts SET approved_by = drafted_by, status='approved' WHERE alert_id=%s", f"SOD-{who}")
        ok(False, f"{label}: database refuses self-approval")
    except psycopg.errors.CheckViolation:
        ok(True, f"and the database refuses it too (four_eyes check) for {label}")
r = c.post("/cases/SOD-admin/str/approve", headers=H["officer"])
ok(r.status_code == 200 and r.json()["status"] == "str_filed", "a different person can approve what the Tenant admin drafted")
r = c.post("/cases/SOD-admin/str/approve", headers=H["admin"])
ok(r.status_code == 409, "a filed STR can't be approved again, by anyone (filed cases are final)")

me_admin = c.patch(f"/admin/users/{admin}", headers=H["admin"], json={"status": "suspended"})
ok(me_admin.status_code == 403, "nobody changes their own status")
r = c.patch(f"/admin/users/{officer}", headers=H["officer"], json={"role_id": str(tr[cat.TENANT_ADMIN])})
ok(r.status_code == 403, "a compliance officer can't promote themselves (no users.manage; and never their own role)")
r = c.patch(f"/admin/users/{admin}", headers=H["admin"], json={"role_id": str(tr["Auditor (read-only)"])})
ok(r.status_code == 403, "a Tenant admin can't change their own role")
r = c.put(f"/admin/roles/{tr[cat.TENANT_ADMIN]}", headers=H["admin"], json={"name": cat.TENANT_ADMIN, "perms": ["users.manage"]})
ok(r.status_code == 403, "nobody changes the permissions of the role they hold")
tok_admin2 = two_factor_token(c, "admin2@authz.example.com", S["admin2"])
r = c.put(f"/admin/roles/{tr[cat.TENANT_ADMIN]}", headers=bearer(tok_admin2), json={"name": cat.TENANT_ADMIN, "perms": ["users.manage"]})
ok(r.status_code == 403, "even a second Tenant admin (same role) can't edit it: it holds the role too")
custom = c.post("/admin/roles", headers=H["admin"], json={"name": "Keeper", "perms": ["roles.manage"]}).json()["id"]
add_user(T, custom, "keeper@authz.example.com")
r = c.put(f"/admin/roles/{tr[cat.TENANT_ADMIN]}", headers=bearer(password_token(c, "keeper@authz.example.com")), json={"name": cat.TENANT_ADMIN, "perms": ["users.manage"]})
ok(r.status_code == 409 and "locked" in r.json()["detail"], "the Tenant admin role is locked for everyone else too")
ok(c.post(f"/admin/users/{admin}/reset-mfa", headers=H["admin"], json={"reason": "own reset attempt"}).status_code == 403, "nobody resets their own two-factor")
case("FINAL-1", status="closed")
r = c.post("/cases/FINAL-1/decision", headers=H["admin"], json={"decision": "escalate", "reason": "reopen attempt"})
ok(r.status_code == 409, "a closed case is final, even for a Tenant admin")
case("FINAL-2", status="str_filed")
ok(c.post("/cases/FINAL-2/decision", headers=H["officer"], json={"decision": "escalate", "reason": "reopen attempt"}).status_code == 409, "and a filed case is final for a compliance officer")
tok_owner = password_token(c, "owner@authz.example.com")
ok(c.post("/cases/SOD-admin/str/approve", headers=bearer(tok_owner)).status_code == 403, "a Platform owner has no case rights at all without an access session")
tok_ps = two_factor_token(c, "psupport@authz.example.com", S["psupport"])
ok(c.patch(f"/platform/users/{psup}", headers=bearer(tok_ps), json={"status": "suspended"}).status_code == 403, "platform support can't manage platform staff, least of all themselves")
r = c.patch(f"/platform/users/{owner}", headers=bearer(tok_owner), json={"status": "suspended"})
ok(r.status_code == 403, "a Platform owner can't suspend themselves")
r = c.post("/platform/invitations", headers=bearer(tok_ps), json={"email": "x@authz.example.com", "role_id": cat.PLATFORM_OWNER_ROLE_ID})
ok(r.status_code == 403, "only holders of platform.owners.manage can add an owner")

# ======================= request check order =======================
print("# request check order")
sql(SUPER, "UPDATE organizations SET status='suspended' WHERE id=%s", T)
r = c.get("/admin/users", headers=H["analyst"])
ok(r.status_code == 403 and "isn't active" in r.json()["detail"], "step 2 comes before step 4: in a suspended tenant even a call the person has no permission for says 'not active'")
sql(SUPER, "UPDATE organizations SET status='active' WHERE id=%s", T)
r = c.get("/admin/users", headers=H["analyst"])
ok(r.status_code == 403 and "doesn't allow" in r.json()["detail"], "in an active tenant the same call is refused for permission")
ok(c.get("/admin/users").status_code == 401, "step 1: no sign-in, no answer")

# ======================= row-level security knows the actor =======================
print("# row-level security by actor")
case("RLS-1")
rows_as = lambda actor, platform=False, org=T, table="alerts": _rows(org, platform, actor, table)


def _rows(org, platform, actor, table):
    with pg.tx(org, platform=platform, actor=actor) as cur:
        cur.execute(f"SELECT count(*) FROM {table}")
        return cur.fetchone()[0]


ok(rows_as(officer) > 0, "a member of the tenant sees its alerts")
ok(rows_as(None) > 0, "a system context with no actor (API key, scripts) sees them too, as before")
def _org_rows(org, actor, table):
    with pg.tx(org, actor=actor) as cur:
        cur.execute(f"SELECT count(*) FROM {table} WHERE org_id=%s", (org,))
        return cur.fetchone()[0]


ok(rows_as(outsider) == 0 and _org_rows(T, outsider, "users") == 0 and rows_as(outsider, table="security_settings") == 0,
   "a person from another tenant gets nothing from this one, even if the application passed the wrong tenant")
sql(SUPER, "UPDATE tenant_memberships SET status='suspended' WHERE user_id=%s", analyst)
ok(rows_as(analyst) == 0, "a suspended membership is cut off in the database itself")
sql(SUPER, "UPDATE tenant_memberships SET status='active' WHERE user_id=%s", analyst)
ok(rows_as(analyst) > 0, "and restored when the membership is active again")
sql(SUPER, "DELETE FROM tenant_memberships WHERE user_id=%s", auditor)
ok(rows_as(auditor) == 0, "a removed membership leaves no access")
sql(SUPER, "INSERT INTO tenant_memberships (user_id, tenant_id, role_id, status) VALUES (%s,%s,%s,'active')", auditor, T, tr["Auditor (read-only)"])
ok(rows_as(officer, table="users") >= 6, "members can see the tenant's people")
ok(_org_rows(U, outsider, "users") >= 1, "a person reaches the rows of their own tenant")
with pg.tx(T, actor=outsider) as cur:
    cur.execute("SELECT count(*) FROM users WHERE id=%s", (outsider,))
    ok(cur.fetchone()[0] == 1, "a person can read their own users row in a tenant context they don't belong to (needed for profile pages)")
# platform mode needs a platform actor
ok(rows_as(officer, platform=True, org=None, table="users") == 1, "a tenant user can't turn platform mode into a view of everyone's users (only their own row)")
ok(rows_as(owner, platform=True, org=None, table="users") > 5 and rows_as(psup, platform=True, org=None, table="users") > 5, "active platform staff can")
ok(rows_as(owner, platform=True, org=None, table="alerts") == 0, "but platform mode never reaches case data")
# owner access sessions
ok(rows_as(owner) == 0, "a Platform owner has no access to a tenant's data without an access session")
sql(SUPER, """INSERT INTO tenant_access_sessions (owner_user_id, tenant_id, reason, status, started_at, expires_at)
              VALUES (%s,%s,'rls test','active', now(), now() + interval '10 minutes')""", owner, T)
ok(rows_as(owner) > 0, "a live access session opens exactly that tenant to the owner")
ok(rows_as(owner, org=U) == 0, "and no other tenant")
sql(SUPER, "UPDATE tenant_access_sessions SET expires_at = now() - interval '1 minute' WHERE owner_user_id=%s", owner)
ok(rows_as(owner) == 0, "an expired access session opens nothing")
sql(SUPER, "UPDATE tenant_access_sessions SET status='ended' WHERE owner_user_id=%s", owner)

# ======================= restricted cases =======================
print("# restricted cases")
case("RST-1", customer="C-RESTRICTED-9")
with pg.tx(T) as cur:
    cur.execute("""INSERT INTO screenings (id, org_id, customer_id, direction, address, amount, score, decision, reasons)
                   VALUES ('RST-S1',%s,'C-RESTRICTED-9','out','TRestricted0000000000000000000001',100,80,'hold','[]')""", (T,))
    cur.execute("UPDATE alerts SET screening_id='RST-S1' WHERE id='RST-1'")
    cur.execute("INSERT INTO str_drafts (org_id, alert_id, final_enc, drafted_by, status) VALUES (%s,'RST-1',NULL,%s,'draft')", (T, officer))
r = c.put("/cases/RST-1/restricted", headers=H["analyst"], json={"restricted": True, "reason": "colleague involved"})
ok(r.status_code == 403, "an analyst (no restricted view) can't restrict a case")
r = c.put("/cases/RST-1/restricted", headers=H["officer"], json={"restricted": True, "reason": "involves a member of staff"})
ok(r.status_code == 200 and r.json()["restricted"] is True, "an officer (case work + restricted view) restricts it")
ok(c.put("/cases/RST-1/restricted", headers=H["officer"], json={"restricted": True, "reason": "again"}).status_code == 409, "restricting twice is a conflict, not a silent no-op")
ok(any(a[0] == "case_restricted" and a[1] == "RST-1" for a in actions(T)), "restricting is audited with its reason")
for who in ("analyst", "auditor"):
    ok(c.get("/cases/RST-1", headers=H[who]).status_code == 404, f"a restricted case answers 404 to someone without access ({who})")
    ok("RST-1" not in [a["id"] for a in c.get("/alerts", headers=H[who]).json()], f"and is missing from the alert queue ({who})")
ok(c.get("/screenings/RST-S1", headers=H["analyst"]).status_code == 404, "its screening is hidden from them as well")
with pg.tx(T, actor=analyst) as cur:
    cur.execute("SELECT customer_hidden(%s, 'C-RESTRICTED-9'), customer_hidden(%s, 'C-NOBODY')", (T, T))
    hidden_for_analyst, unknown = cur.fetchone()
with pg.tx(T, actor=officer) as cur:
    cur.execute("SELECT customer_hidden(%s, 'C-RESTRICTED-9')", (T,))
    hidden_for_officer = cur.fetchone()[0]
ok(hidden_for_analyst and not hidden_for_officer and not unknown,
   "customer searches skip the restricted case's customer for the analyst (customer_hidden), not for the officer, and not for unknown customers")
ok(sql(SUPER, "SELECT count(*) FROM str_drafts WHERE alert_id='RST-1'")[0][0] == 1, "(the data is still there for those who may see it)")
with pg.tx(T, actor=analyst) as cur:
    cur.execute("SELECT count(*) FROM str_drafts WHERE alert_id='RST-1'")
    ok(cur.fetchone()[0] == 0, "even directly in the database an analyst can't read its STR")
for who in ("officer", "admin"):
    ok(c.get("/cases/RST-1", headers=H[who]).status_code == 200, f"someone with cases.restricted.view opens it ({who})")
ok("RST-1" in [a["id"] for a in c.get("/alerts", headers=H["officer"]).json()], "and it is in their queue")
# named users
ok(c.post("/cases/RST-1/access", headers=H["officer"], json={"user_id": analyst}).status_code == 200, "an officer names the analyst for this one case")
ok(c.get("/cases/RST-1", headers=H["analyst"]).status_code == 200 and c.get("/screenings/RST-S1", headers=H["analyst"]).status_code == 200,
   "the named analyst can now open the case and its screening")
ok(c.get("/cases/RST-1", headers=H["auditor"]).status_code == 404, "and still nobody else")
ok(c.post("/cases/RST-1/access", headers=H["officer"], json={"user_id": outsider}).status_code == 409, "someone from another tenant can't be named")
ok([p["user_id"] for p in c.get("/cases/RST-1/access", headers=H["officer"]).json()["people"]] == [analyst], "the list of named people")
ok(c.get("/cases/RST-1/access", headers=H["analyst"]).status_code == 403, "but the named analyst can't see or change who else is named")
ok(c.delete(f"/cases/RST-1/access/{analyst}", headers=H["officer"]).status_code == 200 and c.get("/cases/RST-1", headers=H["analyst"]).status_code == 404,
   "removing the name closes it again")
c.post("/cases/RST-1/access", headers=H["officer"], json={"user_id": analyst})
ok(c.put("/cases/RST-1/restricted", headers=H["officer"], json={"restricted": False, "reason": "no longer sensitive"}).status_code == 200
   and c.get("/cases/RST-1", headers=H["analyst"]).status_code == 200, "un-restricting opens it to everyone who can view cases")
ok(sql(SUPER, "SELECT count(*) FROM case_access_grants WHERE alert_id='RST-1'")[0][0] == 0, "and clears the list of names")
c.put("/cases/RST-1/restricted", headers=H["officer"], json={"restricted": True, "reason": "back to need-to-know"})

# ======================= read auditing =======================
print("# read auditing")
case("VIEW-1")
before_views = len([a for a in actions(T, "case_viewed") if a[1] == "VIEW-1"])
for _ in range(3):
    c.get("/cases/VIEW-1", headers=H["officer"])
views = [a for a in actions(T, "case_viewed") if a[1] == "VIEW-1"]
ok(len(views) - before_views == 1 and views[-1][3] == officer, "an ordinary case opened three times in a row is logged once an hour, with who")
c.get("/cases/VIEW-1", headers=H["officer2"])
ok(len([a for a in actions(T, "case_viewed") if a[1] == "VIEW-1"]) - before_views == 2, "another person's view is logged separately")
r_before = len([a for a in actions(T, "case_viewed") if a[1] == "RST-1"])
for _ in range(3):
    c.get("/cases/RST-1", headers=H["officer"])
rv = [a for a in actions(T, "case_viewed") if a[1] == "RST-1"]
ok(len(rv) - r_before == 3 and rv[-1][2].get("restricted") is True, "every view of a restricted case is logged, marked restricted")
sql(SUPER, "ALTER TABLE audit_events DISABLE TRIGGER audit_no_update")
sql(SUPER, "UPDATE audit_events SET at = at - interval '2 hours' WHERE action='case_viewed' AND target='VIEW-1'")
sql(SUPER, "ALTER TABLE audit_events ENABLE TRIGGER audit_no_update")
c.get("/cases/VIEW-1", headers=H["officer"])
ok(len([a for a in actions(T, "case_viewed") if a[1] == "VIEW-1"]) - before_views == 3, "after an hour the next view is logged again")
case("STR-1", status="str_filed")
with pg.tx(T) as cur:
    cur.execute("INSERT INTO str_drafts (org_id, alert_id, final_enc, drafted_by, approved_by, status) VALUES (%s,'STR-1',NULL,%s,%s,'approved')", (T, officer2, officer))
r = c.get("/cases/STR-1/export", headers=H["officer"], params={"reason": "examiner request 4821"})
ok(r.status_code == 200 and any(a[0] == "str_viewed" and a[1] == "STR-1" for a in actions(T)) and any(a[0] == "case_exported" and a[1] == "STR-1" for a in actions(T)),
   "reading an STR (through an export) is logged as str_viewed and the export itself as case_exported")
ok(c.get("/cases/STR-1/export", headers=H["analyst"], params={"reason": "curious analyst"}).status_code == 403, "an analyst can't export")
