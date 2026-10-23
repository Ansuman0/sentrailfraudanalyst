"""SCIM 2.0 (phase 7, Enterprise): tokens, users, groups mapped to roles, deprovisioning that ends sessions at once, and isolation between
tenants. Real app, real database. Needs a fresh migrated database.
Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_scim_e2e.py"""
import json
import os
import pyotp
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from fastapi.testclient import TestClient
from app import pg
from app.access import catalogue as cat
from app.admin_api import provision_org
from app.main import app
from app.security.middleware import limiter
from helpers_access import CSRF, add_user, bearer, password_token, sql, two_factor_token

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)
scim = TestClient(app, base_url="https://testserver", raise_server_exceptions=False)       # the identity provider: no cookies, no CSRF header
U = "urn:ietf:params:scim:schemas:core:2.0:User"
G = "urn:ietf:params:scim:schemas:core:2.0:Group"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

with pg.tx(platform=True) as cur:
    S, sr = provision_org(cur, "Scim Co", "MSB", "M7000001", plan="enterprise")
    O, orr = provision_org(cur, "Other Co", "MSB", "M7000002", plan="enterprise")
    P, pr = provision_org(cur, "Pro Co", "MSB", "M7000003", plan="professional")
secrets = {k: pyotp.random_base32() for k in ("s_admin", "s_admin2", "o_admin", "p_admin")}
s_admin = add_user(S, sr[cat.TENANT_ADMIN], "admin@scim.example.com", secret=secrets["s_admin"])
s_admin2 = add_user(S, sr[cat.TENANT_ADMIN], "admin2@scim.example.com", secret=secrets["s_admin2"])
analyst = add_user(S, sr["Compliance analyst"], "analyst@scim.example.com")
o_admin = add_user(O, orr[cat.TENANT_ADMIN], "admin@other-scim.example.com", secret=secrets["o_admin"])
o_user = add_user(O, orr["Compliance analyst"], "worker@other-scim.example.com")
add_user(P, pr[cat.TENANT_ADMIN], "admin@pro-scim.example.com", secret=secrets["p_admin"])
ADMIN = bearer(two_factor_token(c, "admin@scim.example.com", secrets["s_admin"]))
ADMIN2 = bearer(two_factor_token(c, "admin2@scim.example.com", secrets["s_admin2"]))
ADMIN_O = bearer(two_factor_token(c, "admin@other-scim.example.com", secrets["o_admin"]))
ADMIN_P = bearer(two_factor_token(c, "admin@pro-scim.example.com", secrets["p_admin"]))
tok_analyst = bearer(password_token(c, "analyst@scim.example.com"))
sql(SUPER, "UPDATE organizations SET sso_default_role_id=%s WHERE id=%s", sr["Compliance analyst"], S)
H = lambda tok: {"Authorization": "Bearer " + tok, "Content-Type": "application/scim+json"}
role_of = lambda uid: sql(SUPER, "SELECT r.name FROM tenant_memberships m JOIN roles r ON r.id=m.role_id WHERE m.user_id=%s AND m.tenant_id=%s", uid, S)[0][0]
status_of = lambda uid: sql(SUPER, "SELECT status FROM tenant_memberships WHERE user_id=%s AND tenant_id=%s", uid, S)[0][0]
count = lambda action: sql(SUPER, "SELECT count(*) FROM audit_events WHERE org_id=%s AND action=%s", S, action)[0][0]

# =============================== tokens ===============================
print("# tokens")
ok(c.post("/admin/scim/tokens", headers=ADMIN_P, json={"label": "idp"}).status_code == 403, "SCIM is an Enterprise feature: a Professional tenant can't create tokens")
ok(c.post("/admin/scim/tokens", headers=tok_analyst, json={"label": "idp"}).status_code == 403, "an analyst can't either")
ok(c.post("/admin/scim/tokens", json={"label": "idp"}).status_code == 401, "nor anyone not signed in")
r = c.post("/admin/scim/tokens", headers=ADMIN, json={"label": "Entra ID"})
TOKEN, PREFIX = r.json()["token"], r.json()["prefix"]
ok(r.status_code == 200 and TOKEN.startswith("sct_") and r.json()["base_url"].endswith("/scim/v2"), "a Tenant admin creates a token (shown once, with the base URL)")
listing = json.dumps(c.get("/admin/scim/tokens", headers=ADMIN).json())
ok(TOKEN not in listing and PREFIX in listing, "the list shows the prefix, never the token")
stored = sql(SUPER, "SELECT token_hash FROM scim_tokens WHERE prefix=%s", PREFIX)[0][0]
ok(len(bytes(stored)) == 32 and TOKEN.encode() not in bytes(stored), "only a hash is stored")
o_tok = c.post("/admin/scim/tokens", headers=ADMIN_O, json={"label": "other idp"}).json()["token"]

ok(scim.get("/scim/v2/Users").status_code == 401, "no token: 401")
ok(scim.get("/scim/v2/Users", headers=H("sk_live_abc_def")).status_code == 401, "an API key is not a SCIM token")
ok(scim.get("/scim/v2/Users", headers=H("sct_" + PREFIX[4:] + "_wrong")).status_code == 401, "a wrong secret: 401")
ok(scim.get("/scim/v2/Users", headers=H(TOKEN)).status_code == 200, "the token works")
ok(sql(SUPER, "SELECT last_used_at IS NOT NULL FROM scim_tokens WHERE prefix=%s", PREFIX)[0][0], "its last use is recorded")
sp = scim.get("/scim/v2/ServiceProviderConfig", headers=H(TOKEN)).json()
ok(sp["patch"]["supported"] and not sp["bulk"]["supported"], "ServiceProviderConfig says what is supported")
err = scim.get("/scim/v2/Users/not-a-uuid", headers=H(TOKEN))
ok(err.status_code == 404 and err.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"] and err.headers["content-type"].startswith("application/scim+json"), "errors use the SCIM error format")

# =============================== users ===============================
print("# users")
new = {"schemas": [U], "userName": "new.hire@scim.example.com", "name": {"givenName": "New", "familyName": "Hire"}, "externalId": "idp-1", "active": True}
r = scim.post("/scim/v2/Users", headers=H(TOKEN), json=new)
NEW = r.json().get("id")
ok(r.status_code == 201 and r.json()["userName"] == "new.hire@scim.example.com" and r.json()["name"]["formatted"] == "New Hire" and r.json()["active"], "creating a person returns 201 with the SCIM representation")
ok(role_of(NEW) == "Compliance analyst" and status_of(NEW) == "active", "they get the tenant's default role, active")
row = sql(SUPER, "SELECT password_hash, auth_method, org_id, email_enc FROM users WHERE id=%s", NEW)[0]
ok(row[0] is None and row[1] == "keycloak" and str(row[2]) == str(S) and "new.hire" not in row[3], "no password (they sign in through the company's identity provider); the email is stored encrypted")
ok(scim.post("/scim/v2/Users", headers=H(TOKEN), json=new).status_code == 409, "the same email twice: 409 uniqueness")
ok(scim.post("/scim/v2/Users", headers=H(TOKEN), json={**new, "userName": "worker@other-scim.example.com"}).status_code == 409, "an email that already belongs to another tenant's person: 409, and nothing leaks")
ok(scim.post("/scim/v2/Users", headers=H(TOKEN), json={**new, "userName": "not-an-email"}).status_code == 400, "a userName that isn't an email: 400")
sql(SUPER, "UPDATE organizations SET sso_default_role_id=NULL WHERE id=%s", S)
r = scim.post("/scim/v2/Users", headers=H(TOKEN), json={**new, "userName": "norole@scim.example.com"})
ok(r.status_code == 400 and "default role" in r.json()["detail"], "without a default role, creating people is refused with a clear reason")
sql(SUPER, "UPDATE organizations SET sso_default_role_id=%s WHERE id=%s", sr["Compliance analyst"], S)
inactive = scim.post("/scim/v2/Users", headers=H(TOKEN), json={**new, "userName": "later@scim.example.com", "active": False}).json()
ok(not inactive["active"] and status_of(inactive["id"]) == "suspended", "a person created inactive has a suspended membership")

lst = scim.get("/scim/v2/Users", headers=H(TOKEN)).json()
ok(lst["totalResults"] == 5 and lst["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "the list has everyone in this tenant (2 admins, analyst, 2 new)")
ok("worker@other-scim.example.com" not in json.dumps(lst), "and nobody from another tenant")
f = scim.get("/scim/v2/Users", headers=H(TOKEN), params={"filter": 'userName eq "new.hire@scim.example.com"'}).json()
ok(f["totalResults"] == 1 and f["Resources"][0]["id"] == NEW, "filter userName eq finds one person (case-insensitive email lookup)")
ok(scim.get("/scim/v2/Users", headers=H(TOKEN), params={"filter": 'userName co "x"'}).status_code == 400, "other filters are refused clearly")
pg1 = scim.get("/scim/v2/Users", headers=H(TOKEN), params={"startIndex": 2, "count": 2}).json()
ok(pg1["itemsPerPage"] == 2 and pg1["startIndex"] == 2 and pg1["totalResults"] == 5, "paging works")
ok(scim.get(f"/scim/v2/Users/{NEW}", headers=H(TOKEN)).json()["externalId"] == "idp-1", "read one person")
ok(scim.get(f"/scim/v2/Users/{o_user}", headers=H(TOKEN)).status_code == 404, "a person of another tenant is 404")
ok(scim.get("/scim/v2/Users", headers=H(o_tok)).json()["totalResults"] == 2 and scim.get(f"/scim/v2/Users/{NEW}", headers=H(o_tok)).status_code == 404,
   "the other tenant's token sees only its own people")
for method, path, body in (("patch", f"/scim/v2/Users/{o_user}", {"schemas": [PATCH], "Operations": [{"op": "replace", "path": "active", "value": False}]}),
                           ("put", f"/scim/v2/Users/{o_user}", {"userName": "worker@other-scim.example.com", "active": False}),
                           ("delete", f"/scim/v2/Users/{o_user}", None)):
    r = getattr(scim, method)(path, headers=H(TOKEN), **({"json": body} if body else {}))
    if r.status_code != 404:
        ok(False, f"{method} on another tenant's person must be 404, got {r.status_code}")
ok(sql(SUPER, "SELECT status FROM tenant_memberships WHERE user_id=%s", o_user)[0][0] == "active", "this tenant's token can't change another tenant's people")

# updates
r = scim.patch(f"/scim/v2/Users/{NEW}", headers=H(TOKEN), json={"schemas": [PATCH], "Operations": [{"op": "replace", "path": "displayName", "value": "Newer Name"}]})
ok(r.status_code == 200 and r.json()["displayName"] == "Newer Name", "patch a name")
r = scim.patch(f"/scim/v2/Users/{NEW}", headers=H(TOKEN), json={"schemas": [PATCH], "Operations": [{"op": "Replace", "value": {"userName": "renamed@scim.example.com"}}]})
ok(r.status_code == 200 and r.json()["userName"] == "renamed@scim.example.com", "patch the email without a path (as Entra sends it)")
ok(scim.patch(f"/scim/v2/Users/{NEW}", headers=H(TOKEN), json={"Operations": [{"op": "replace", "path": "userName", "value": "admin@scim.example.com"}]}).status_code == 409, "an email already in use: 409")
ok(scim.patch(f"/scim/v2/Users/{NEW}", headers=H(TOKEN), json={"Operations": [{"op": "remove", "path": "name"}]}).status_code == 400, "an unsupported operation is refused")
r = scim.put(f"/scim/v2/Users/{NEW}", headers=H(TOKEN), json={"userName": "renamed@scim.example.com", "displayName": "Put Name", "externalId": "idp-9", "active": True})
ok(r.status_code == 200 and r.json()["externalId"] == "idp-9" and r.json()["displayName"] == "Put Name", "replace")

# =============================== deprovisioning ===============================
print("# deprovisioning")
ok(c.get("/me", headers=tok_analyst).status_code == 200, "the analyst is signed in")
before = count("scim_user_deprovisioned")
r = scim.patch(f"/scim/v2/Users/{analyst}", headers=H(TOKEN), json={"schemas": [PATCH], "Operations": [{"op": "replace", "path": "active", "value": "False"}]})
ok(r.status_code == 200 and r.json()["active"] is False and status_of(analyst) == "suspended", "active=false (even as the string Entra sends) suspends the membership")
ok(c.get("/me", headers=tok_analyst).status_code == 401, "their open session ends at once")
ok(sql(SUPER, "SELECT count(*) FROM refresh_tokens WHERE user_id=%s AND revoked_at IS NULL", analyst)[0][0] == 0, "and their refresh tokens are revoked")
ok(c.post("/auth/refresh").status_code == 401, "(no way back in)")
ok(count("scim_user_deprovisioned") == before + 1, "the deprovisioning is audited")
ok(sql(SUPER, "SELECT count(*) FROM users WHERE id=%s", analyst)[0][0] == 1, "the person is never deleted (their trail stays attributable)")
r = scim.patch(f"/scim/v2/Users/{analyst}", headers=H(TOKEN), json={"Operations": [{"op": "replace", "path": "active", "value": True}]})
ok(r.status_code == 200 and status_of(analyst) == "active", "active=true reactivates")
ok(scim.delete(f"/scim/v2/Users/{analyst}", headers=H(TOKEN)).status_code == 204 and status_of(analyst) == "suspended", "DELETE deprovisions too (204)")
ok(scim.delete(f"/scim/v2/Users/{analyst}", headers=H(TOKEN)).status_code == 204, "and deleting twice is harmless")
ok(sql(SUPER, "SELECT count(*) FROM users WHERE id=%s", analyst)[0][0] == 1, "(still not deleted)")
r = scim.patch(f"/scim/v2/Users/{s_admin2}", headers=H(TOKEN), json={"Operations": [{"op": "replace", "path": "active", "value": False}]})
ok(r.status_code == 200 and status_of(s_admin2) == "suspended", "a Tenant admin can be deprovisioned while another one remains")
r = scim.patch(f"/scim/v2/Users/{s_admin}", headers=H(TOKEN), json={"Operations": [{"op": "replace", "path": "active", "value": False}]})
ok(r.status_code == 409 and r.json()["scimType"] == "mutability" and status_of(s_admin) == "active", "the last active Tenant admin can't be deprovisioned")
ok(scim.delete(f"/scim/v2/Users/{s_admin}", headers=H(TOKEN)).status_code == 409, "nor deleted")
scim.patch(f"/scim/v2/Users/{s_admin2}", headers=H(TOKEN), json={"Operations": [{"op": "replace", "path": "active", "value": True}]})

# =============================== groups ===============================
print("# groups")
officer, auditor_role = sr["Compliance officer"], sr["Auditor (read-only)"]
r = scim.post("/scim/v2/Groups", headers=H(TOKEN), json={"schemas": [G], "displayName": "Officers", "members": [{"value": NEW}]})
GO = r.json().get("id")
ok(r.status_code == 201 and r.json()["members"][0]["value"] == NEW, "a group is created with a member")
ok(role_of(NEW) == "Compliance analyst", "a group with no role mapped changes nobody's role")
ok(scim.post("/scim/v2/Groups", headers=H(TOKEN), json={"displayName": "Officers"}).status_code == 409, "a duplicate group name: 409")
ok(scim.post("/scim/v2/Groups", headers=H(TOKEN), json={"displayName": "Bad", "members": [{"value": o_user}]}).status_code == 400, "a member from another tenant is refused")
ok(scim.post("/scim/v2/Groups", headers=H(TOKEN), json={"members": []}).status_code == 400, "a group needs a name")
ok(c.put(f"/admin/scim/groups/{GO}", headers=tok_analyst, json={"role_id": str(officer)}).status_code in (401, 403), "an analyst can't map groups to roles")
ok(c.put(f"/admin/scim/groups/{GO}", headers=ADMIN, json={"role_id": str(sr[cat.TENANT_ADMIN])}).status_code == 422, "the Tenant admin role can't be given through a group")
ok(c.put(f"/admin/scim/groups/{GO}", headers=ADMIN, json={"role_id": str(orr["Compliance officer"])}).status_code == 422, "nor a role of another tenant")
ok(c.put(f"/admin/scim/groups/{GO}", headers=ADMIN, json={"role_id": str(officer)}).status_code == 200 and role_of(NEW) == "Compliance officer", "an admin maps the group to a role: members get it at once")
r = scim.post("/scim/v2/Groups", headers=H(TOKEN), json={"displayName": "Auditors", "members": [{"value": NEW}, {"value": s_admin}]})
GA = r.json()["id"]
c.put(f"/admin/scim/groups/{GA}", headers=ADMIN, json={"role_id": str(auditor_role)})
ok(role_of(NEW) == "Compliance officer", "in two groups, the role with more permissions wins")
ok(role_of(s_admin) == cat.TENANT_ADMIN, "a Tenant admin in a mapped group keeps the admin role (groups never change admins)")
r = scim.patch(f"/scim/v2/Groups/{GO}", headers=H(TOKEN), json={"Operations": [{"op": "remove", "path": f'members[value eq "{NEW}"]'}]})
ok(r.status_code == 200 and r.json()["members"] == [] and role_of(NEW) == "Auditor (read-only)", "removed from the officers group, the remaining group's role applies")
r = scim.patch(f"/scim/v2/Groups/{GA}", headers=H(TOKEN), json={"Operations": [{"op": "remove", "path": "members", "value": [{"value": NEW}]}]})
ok(r.status_code == 200 and role_of(NEW) == "Compliance analyst", "removed from every mapped group they return to the tenant's default role")
r = scim.patch(f"/scim/v2/Groups/{GO}", headers=H(TOKEN), json={"Operations": [{"op": "add", "path": "members", "value": [{"value": NEW}, {"value": analyst}]}]})
ok(r.status_code == 200 and len(r.json()["members"]) == 2 and role_of(analyst) == "Compliance officer", "add members by patch")
r = scim.patch(f"/scim/v2/Groups/{GO}", headers=H(TOKEN), json={"Operations": [{"op": "replace", "path": "displayName", "value": "Compliance officers"}]})
ok(r.json()["displayName"] == "Compliance officers", "rename by patch")
r = scim.put(f"/scim/v2/Groups/{GO}", headers=H(TOKEN), json={"displayName": "Compliance officers", "members": [{"value": analyst}]})
ok(len(r.json()["members"]) == 1 and role_of(NEW) == "Compliance analyst" and role_of(analyst) == "Compliance officer", "replace the whole member list")
fl = scim.get("/scim/v2/Groups", headers=H(TOKEN), params={"filter": 'displayName eq "Compliance officers"'}).json()
ok(fl["totalResults"] == 1 and scim.get("/scim/v2/Groups", headers=H(TOKEN)).json()["totalResults"] == 2, "list and filter groups")
ok(scim.get("/scim/v2/Groups", headers=H(o_tok)).json()["totalResults"] == 0 and scim.get(f"/scim/v2/Groups/{GO}", headers=H(o_tok)).status_code == 404, "another tenant sees none of these groups")
ok(scim.delete(f"/scim/v2/Groups/{GO}", headers=H(o_tok)).status_code == 404 and scim.delete(f"/scim/v2/Groups/{GO}", headers=H(TOKEN)).status_code == 204, "only the owning tenant can delete one")
ok(role_of(analyst) == "Compliance analyst", "deleting a group returns its members to the default role")
mapping = c.get("/admin/scim/groups", headers=ADMIN).json()
ok(len(mapping) == 1 and mapping[0]["name"] == "Auditors" and mapping[0]["role"] == "Auditor (read-only)", "admins see the groups and their roles")
ok(count("scim_role_assigned") >= 4 and count("scim_group_created") == 2 and count("scim_group_deleted") == 1, "group and role changes are audited")

# =============================== switching it off ===============================
print("# revoking and switching off")
ok(c.delete(f"/admin/scim/tokens/{PREFIX}", headers=tok_analyst).status_code in (401, 403), "an analyst can't revoke tokens")
ok(c.delete(f"/admin/scim/tokens/{PREFIX}", headers=ADMIN_O).status_code == 404, "another tenant's admin can't revoke it")
sql(SUPER, "UPDATE org_features SET enabled=false WHERE org_id=%s AND feature='scim'", S)
r = scim.get("/scim/v2/Users", headers=H(TOKEN))
ok(r.status_code == 403 and "isn't turned on" in r.json()["detail"], "with the feature switched off the token stops working")
sql(SUPER, "UPDATE org_features SET enabled=true WHERE org_id=%s AND feature='scim'", S)
sql(SUPER, "UPDATE organizations SET status='suspended' WHERE id=%s", S)
ok(scim.get("/scim/v2/Users", headers=H(TOKEN)).status_code == 403, "a suspended tenant's token is refused")
sql(SUPER, "UPDATE organizations SET status='active' WHERE id=%s", S)
ok(c.delete(f"/admin/scim/tokens/{PREFIX}", headers=ADMIN).status_code == 200, "an admin revokes the token")
ok(scim.get("/scim/v2/Users", headers=H(TOKEN)).status_code == 401, "it stops working at once")
ok(c.delete(f"/admin/scim/tokens/{PREFIX}", headers=ADMIN).status_code == 404, "(and revoking twice says so)")
ok(count("scim_token_created") == 1 and count("scim_token_revoked") == 1 and count("scim_user_created") == 2, "token and user creation are audited")
ok(scim.get("/scim/v2/Users", headers=H(o_tok)).status_code == 200, "the other tenant's token is unaffected")
