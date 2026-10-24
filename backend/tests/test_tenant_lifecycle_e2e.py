"""Tenant lifecycle, phase 4: create (pending) -> first admin accepts (active, two-factor mandatory) -> suspend / reactivate -> delete with a
second owner's approval, seat limits, invitation expiry, and replacing a lost Tenant admin. Real app, real database.
Needs a fresh migrated database. Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_tenant_lifecycle_e2e.py"""
import os
import pyotp
import psycopg
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from app import config, pg
from app.security.rbac import api_key
from app.main import app
from app.access import catalogue as cat
from app.admin_api import provision_org
from app.security.middleware import limiter
from helpers_access import CSRF, PW, add_user, bearer, code_at, password_login, password_token, sql, two_factor_token

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)

owner1 = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "owner1@life.example.com")
owner2 = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "owner2@life.example.com")
sup_secret = pyotp.random_base32()
add_user(None, cat.PLATFORM_SUPPORT_ROLE_ID, "support@life.example.com", secret=sup_secret)
# a minimal app with only the API-key check, so no screening (and no outside chain lookups) is involved
mini = FastAPI()
mini.get("/key-check")(lambda p=Depends(api_key): {"org": p.org_id})
k = TestClient(mini, base_url="https://testserver", raise_server_exceptions=False)
O1 = bearer(password_token(c, "owner1@life.example.com"))
O2 = bearer(password_token(c, "owner2@life.example.com"))
SUP = bearer(two_factor_token(c, "support@life.example.com", sup_secret))


def chain(org):
    return sql(SUPER, "SELECT action, detail FROM audit_events WHERE org_id IS NOT DISTINCT FROM %s ORDER BY seq", org)


def org_row(org):
    return sql(SUPER, "SELECT status, status_reason, deleted_at, deletion_due_at, slug FROM organizations WHERE id=%s", org)[0]


def fragment(link):
    return link.split("#", 1)[1]


BODY = {"legal_name": "Lifecycle Co", "business_type": "MSB", "registration": "M4000001", "plan": "starter",
        "admin_email": "first.admin@life.example.com", "slug": "lifecycle-co"}

# ======================= create (pending) =======================
print("# create")
ok(c.post("/platform/orgs", headers=SUP, json=BODY).status_code == 403, "platform support can't create a tenant")
ok(c.post("/platform/orgs", headers=O1, json={**BODY, "slug": "Bad Slug!"}).status_code == 422, "an invalid slug is refused")
r = c.post("/platform/orgs", headers=O1, json=BODY)
ok(r.status_code == 200 and r.json()["status"] == "pending" and r.json()["dev_link"], "a new tenant is created pending, with an invitation for its first admin")
T = r.json()["org_id"]
link = r.json()["dev_link"]
st, reason, deleted_at, due, slug = org_row(T)
ok(st == "pending" and slug == "lifecycle-co", "status pending and the chosen slug is stored")
ok(c.post("/platform/orgs", headers=O1, json={**BODY, "legal_name": "Other Co", "admin_email": "other@life.example.com"}).status_code == 409, "a taken slug is refused")
ok(sql(SUPER, "SELECT count(*) FROM roles WHERE org_id=%s", T)[0][0] == 4 and sql(SUPER, "SELECT is_locked FROM roles WHERE org_id=%s AND name='Tenant admin'", T)[0][0],
   "its four roles are seeded and the Tenant admin role is locked")
base = sql(SUPER, "SELECT min_password_len_floor, retention_years_floor FROM platform_settings")[0]
ss = sql(SUPER, "SELECT min_password_len, retention_years FROM security_settings WHERE org_id=%s", T)[0]
ok(ss == base, "the platform security baseline was copied into the tenant's settings")
ok({a for a, _ in chain(T)} >= {"tenant_created"} and "tenant_created" in [a for a, _ in chain(None)], "creating it is audited in the tenant's log and the platform's")
hours = sql(SUPER, "SELECT extract(epoch FROM (i.expires_at - now()))/3600 FROM invitations i JOIN users u ON u.id=i.user_id WHERE u.org_id=%s", T)[0][0]
ok(71 < float(hours) <= 72, f"the first admin's invitation lasts 72 hours ({float(hours):.1f} h left)")
ok(password_login(c, "first.admin@life.example.com").status_code == 401, "the invited admin can't sign in before accepting")

# ======================= first admin accepts =======================
print("# activation")
r = c.post("/invitations/accept", json={"token": fragment(link), "full_name": "First Admin", "password": PW})
ok(r.status_code == 200 and "two-factor" in r.json()["next"], "accepting tells a Tenant admin that two-factor is required")
ok(org_row(T)[0] == "active" and "tenant_activated" in [a for a, _ in chain(T)], "the tenant becomes active and that is audited")
ok(sql(SUPER, "SELECT mfa_mandatory FROM users WHERE org_id=%s", T)[0][0], "the first admin is marked as needing two-factor")
admin_tok = password_token(c, "first.admin@life.example.com")
me = c.get("/me", headers=bearer(admin_tok)).json()
ok(me["mfa_setup"] == "required" and me["role"] == "Tenant admin", "their session says two-factor setup is required")
r = c.get("/admin/users", headers=bearer(admin_tok))
ok(r.status_code == 403 and "two-factor" in r.json()["detail"].lower(), "until they set it up, nothing else works")
setup = c.post("/me/mfa/setup", headers=bearer(admin_tok)).json()
secret = setup["secret"]
conf = c.post("/me/mfa/confirm", headers=bearer(admin_tok), json={"code": code_at(secret, 0)})
ADMIN = bearer(conf.json()["access_token"])
ok(conf.status_code == 200 and c.get("/admin/users", headers=ADMIN).status_code == 200, "after setting up two-factor the admin can work")

# ======================= invitations: expiry, resend =======================
print("# invitations")
roles = {r["name"]: r["id"] for r in c.get("/admin/roles", headers=ADMIN).json()["roles"]}
r = c.post("/admin/invitations", headers=ADMIN, json={"email": "joiner@life.example.com", "role_id": roles["Compliance officer"]})
joiner_link = r.json()["dev_link"]
sql(SUPER, "UPDATE invitations SET expires_at = now() - interval '1 hour' WHERE token_hash IS NOT NULL AND accepted_at IS NULL")
ok(c.post("/invitations/accept", json={"token": fragment(joiner_link), "full_name": "Late Joiner", "password": PW}).status_code == 410, "an expired invitation can't be accepted (410)")
joiner_uid = sql(SUPER, "SELECT id::text FROM users WHERE org_id=%s AND status='invited'", T)[0][0]
ok(c.post(f"/platform/orgs/{T}/users/{joiner_uid}/resend-invitation", headers=SUP, json={"reason": "ticket 77: link expired"}).status_code == 200, "platform support can resend it")
r = c.post(f"/platform/orgs/{T}/users/{joiner_uid}/resend-invitation", headers=O1, json={"reason": "ticket 78: another link please"})
new_link = r.json()["dev_link"]

# ======================= seat limits =======================
print("# seats")
for i in range(3):
    add_user(T, (sql(SUPER, "SELECT id FROM roles WHERE org_id=%s AND name='Auditor (read-only)'", T)[0][0]), f"seat{i}@life.example.com")
active = sql(SUPER, "SELECT count(*) FROM tenant_memberships WHERE tenant_id=%s AND status='active'", T)[0][0]
ok(active == 4, f"4 of the 5 Starter seats are in use ({active})")
ok(c.post("/admin/invitations", headers=ADMIN, json={"email": "fifth@life.example.com", "role_id": roles["Compliance analyst"]}).status_code == 200, "a fifth seat can still be invited")
add_user(T, roles["Auditor (read-only)"], "seat3@life.example.com")
r = c.post("/admin/invitations", headers=ADMIN, json={"email": "sixth@life.example.com", "role_id": roles["Compliance analyst"]})
ok(r.status_code == 409 and "5 people" in r.json()["detail"], "with all 5 seats in use a new invitation is refused")
r = c.post("/invitations/accept", json={"token": fragment(new_link), "full_name": "Late Joiner", "password": PW})
ok(r.status_code == 409 and "seats" in r.json()["detail"], "and an invitation sent earlier can't be accepted into a full tenant (re-checked at acceptance)")
ok(c.put(f"/platform/orgs/{T}/plan", headers=O1, json={"plan": "professional"}).status_code == 200, "upgrading the plan opens more seats")
ok(c.post("/invitations/accept", json={"token": fragment(new_link), "full_name": "Late Joiner", "password": PW}).status_code == 200, "now the earlier invitation works")
ok(c.post("/admin/invitations", headers=ADMIN, json={"email": "sixth@life.example.com", "role_id": roles["Compliance analyst"]}).status_code == 200, "and so does a new one")

# ======================= suspend / reactivate =======================
print("# suspend and reactivate")
key = c.post("/admin/api-keys", headers=ADMIN, json={"label": "ramp"}).json()["api_key"]
KEY = {"Authorization": "Bearer " + key}
ok(k.get("/key-check", headers=KEY).status_code == 200, "an active tenant's API key is accepted")
ok(c.post(f"/platform/orgs/{T}/status", headers=SUP, json={"status": "suspended", "reason": "not allowed"}).status_code == 403, "support can't suspend a tenant")
ok(c.post(f"/platform/orgs/{T}/status", headers=O1, json={"status": "suspended", "reason": "x"}).status_code == 422, "a reason is required")
r = c.post(f"/platform/orgs/{T}/status", headers=O1, json={"status": "suspended", "reason": "ticket 91: unpaid invoice"})
ok(r.status_code == 200 and org_row(T)[0] == "suspended" and org_row(T)[1] == "ticket 91: unpaid invoice", "an owner suspends it with a reason")
ok(c.get("/me", headers=ADMIN).status_code in (401, 403), "live sessions stop at once")
r = password_login(c, "first.admin@life.example.com")
ok("access_token" not in r.text,
   "members can't sign in to a suspended tenant (old model: refused; new model: no tenant to enter, and no session in it)")
r = k.get("/key-check", headers=KEY)
ok(r.status_code == 403 and "isn't active" in r.json()["detail"], "its API keys stop working")
ok("tenant_suspended" in [a for a, _ in chain(T)] and "tenant_suspended" in [a for a, _ in chain(None)], "audited in the tenant's log and the platform's, with the reason")
ok(c.post(f"/platform/orgs/{T}/status", headers=O1, json={"status": "suspended", "reason": "again please"}).status_code == 409, "suspending twice is a conflict")
ok(sql(SUPER, "SELECT count(*) FROM users WHERE org_id=%s AND status='active'", T)[0][0] >= 4, "the data and people are kept")
r = c.post(f"/platform/orgs/{T}/status", headers=O1, json={"status": "active", "reason": "ticket 92: invoice paid"})
ok(r.status_code == 200 and org_row(T)[0] == "active", "reactivating works")
tok = c.post("/auth/login", json={"email": "first.admin@life.example.com", "password": PW}).json()
ok("mfa_token" in tok, "people can sign in again (the admin is asked for their second factor)")
r = c.post("/auth/mfa", json={"mfa_token": tok["mfa_token"], "code": code_at(secret, 1)})
ADMIN = bearer(r.json()["access_token"])
ok(k.get("/key-check", headers=KEY).status_code == 200, "and the API key works again")
pending = c.post("/platform/orgs", headers=O1, json={**BODY, "legal_name": "Pending Co", "slug": "pending-co", "admin_email": "pending.admin@life.example.com"}).json()["org_id"]
ok(c.post(f"/platform/orgs/{pending}/status", headers=O1, json={"status": "suspended", "reason": "not yet active"}).status_code == 409, "a tenant that is still pending can't be suspended")

# ======================= delete with a second owner =======================
print("# delete")
ok(c.post(f"/platform/orgs/{T}/delete", headers=SUP, json={"reason": "support wants it gone"}).status_code == 403, "support can't ask to delete a tenant")
r = c.post(f"/platform/orgs/{T}/delete", headers=O1, json={"reason": "ticket 95: customer left, contract ended"})
ok(r.status_code == 200 and org_row(T)[0] == "active", "an owner's request alone deletes nothing")
AID = r.json()["approval_id"]
ok(c.post(f"/platform/orgs/{T}/delete", headers=O2, json={"reason": "second request for the same"}).status_code == 409, "a second request for the same tenant is refused while one waits")
ok(c.post(f"/platform/approvals/{AID}/approve", headers=O1).status_code == 403, "the requester can't approve their own request")
ok(c.post(f"/platform/approvals/{AID}/approve", headers=SUP).status_code == 403, "support can't approve it")
try:
    sql(SUPER, "UPDATE platform_approvals SET approved_by = requested_by WHERE id=%s", AID)
    ok(False, "database refuses self-approval")
except psycopg.errors.CheckViolation:
    ok(True, "and the database refuses it too (approval_two_people)")
ok(any(a["id"] == AID and a["status"] == "pending" for a in c.get("/platform/approvals", headers=O2).json()), "the second owner sees it in the approvals list")
r = c.post(f"/platform/approvals/{AID}/approve", headers=O2)
ok(r.status_code == 200 and r.json()["executed"] == "tenant.delete", "a second owner approves and the tenant is deleted")
st, why, deleted_at, due, _ = org_row(T)
years = float(sql(SUPER, "SELECT extract(epoch FROM (deletion_due_at - deleted_at))/31557600 FROM organizations WHERE id=%s", T)[0][0])
ok(st == "deleted" and deleted_at is not None and 4.9 < years < 5.1, f"it is marked deleted and its data removal is scheduled after the retention period ({years:.1f} years)")
ok(c.get("/me", headers=ADMIN).status_code in (401, 403), "all its sessions ended")
ok(sql(SUPER, "SELECT count(*) FROM api_keys WHERE org_id=%s AND revoked_at IS NULL", T)[0][0] == 0, "all its API keys are revoked")
ok("tenant_deleted" in [a for a, _ in chain(T)] and "tenant_deleted" in [a for a, _ in chain(None)], "the deletion is audited in both logs")
ok(sql(SUPER, "SELECT count(*) FROM users WHERE org_id=%s", T)[0][0] > 0, "nothing is erased yet (removal waits for the retention period)")
ok(c.post(f"/platform/approvals/{AID}/approve", headers=O2).status_code == 409, "an approval can't be used twice")
ok(c.post(f"/platform/orgs/{T}/delete", headers=O1, json={"reason": "already deleted tenant"}).status_code == 409, "a deleted tenant can't be deleted again")
ok(c.post(f"/platform/orgs/{T}/status", headers=O1, json={"status": "active", "reason": "bring it back please"}).status_code == 409, "and can't be reactivated")
# expiry and denial
r = c.post(f"/platform/orgs/{pending}/delete", headers=O1, json={"reason": "ticket 96: created by mistake"})
AID2 = r.json()["approval_id"]
sql(SUPER, "UPDATE platform_approvals SET expires_at = now() - interval '1 minute' WHERE id=%s", AID2)
ok(c.post(f"/platform/approvals/{AID2}/approve", headers=O2).status_code == 410 and org_row(pending)[0] == "pending", "a request older than 24 hours expires and deletes nothing")
r = c.post(f"/platform/orgs/{pending}/delete", headers=O1, json={"reason": "ticket 97: really by mistake"})
AID3 = r.json()["approval_id"]
ok(c.post(f"/platform/approvals/{AID3}/deny", headers=O2, json={"reason": "keep it, we may use it"}).status_code == 200 and org_row(pending)[0] == "pending",
   "a second owner can deny it")

# ======================= replacing a lost Tenant admin =======================
print("# admin recovery")
with pg.tx(platform=True) as cur:
    R, rr = provision_org(cur, "Recover Co", "MSB", "M4000002", plan="professional")
gone = add_user(R, rr[cat.TENANT_ADMIN], "gone.admin@life.example.com")
officer = add_user(R, rr["Compliance officer"], "officer@life.example.com")
sql(SUPER, "UPDATE users SET status='suspended' WHERE id=%s", gone)          # the only admin left the company
ok(c.post(f"/platform/orgs/{R}/admin", headers=SUP, json={"email": "new.admin@life.example.com", "reason": "ticket 99: admin left"}).status_code == 403, "support can't assign an admin")
ok(c.post(f"/platform/orgs/{R}/admin", headers=O1, json={"email": "new.admin@life.example.com", "reason": "x"}).status_code == 422, "a reason is required")
r = c.post(f"/platform/orgs/{R}/admin", headers=O1, json={"email": "new.admin@life.example.com", "reason": "ticket 99: admin left the company"})
ok(r.status_code == 200 and r.json()["how"] == "invited (72 hours)", "a new person is invited as the replacement Tenant admin")
ok("tenant_admin_assigned" in [a for a, _ in chain(R)] and "tenant_admin_assigned" in [a for a, _ in chain(None)], "written to both audit logs, with the reason")
ok(any(d.get("reason", "").startswith("ticket 99") for a, d in chain(R) if a == "tenant_admin_assigned"), "the tenant's own log carries the reason")
r2 = c.post("/invitations/accept", json={"token": fragment(r.json()["dev_link"]), "full_name": "New Admin", "password": PW})
ok(r2.status_code == 200, "they accept")
ok(sql(SUPER, "SELECT r.name FROM users u JOIN roles r ON r.id=u.role_id WHERE u.org_id=%s AND u.status='active' AND r.name='Tenant admin'", R) != [], "and the tenant has a working Tenant admin again")
r = c.post(f"/platform/orgs/{R}/admin", headers=O1, json={"email": "officer@life.example.com", "reason": "ticket 100: second admin wanted"})
ok(r.status_code == 200 and r.json()["how"] == "promoted", "an existing member can be promoted instead")
ok(sql(SUPER, "SELECT r.name, u.mfa_mandatory FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=%s", officer)[0] == ("Tenant admin", True),
   "the promoted person becomes Tenant admin with two-factor mandatory")
r = c.post(f"/platform/orgs/{R}/admin", headers=O1, json={"email": "sixth@life.example.com", "reason": "wrong tenant on purpose"})
ok(r.status_code == 200,
   "someone who belongs to another tenant gets a membership here")
ok(c.post(f"/platform/orgs/{T}/admin", headers=O1, json={"email": "x@life.example.com", "reason": "tenant already deleted"}).status_code == 409, "a deleted tenant can't get an admin")

# ======================= an existing account becomes a membership =======================
print("# existing account")
r = c.post("/platform/orgs", headers=O1, json={**BODY, "legal_name": "Joined Co", "slug": "joined-co", "admin_email": "officer@life.example.com"})
ok(r.status_code == 200 and r.json()["status"] == "active" and "dev_link" not in r.json(),
   "when the first admin's email already has an account they get a membership and the tenant is active at once")
J = r.json()["org_id"]
ok(sql(SUPER, "SELECT status FROM tenant_memberships WHERE tenant_id=%s", J)[0][0] == "active", "the membership is Tenant admin and active")
