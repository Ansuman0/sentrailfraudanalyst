"""Every built-in role, signed in for real, against every protected route (phase 8 acceptance: the screens hide what a role can't use, and the
API refuses it anyway). For each role the allowed routes must not answer 401/403 and every other route must; the expectation is derived from the
route table (app/access/routes.py) and the role's stored permissions, plus hard-coded invariants from the brief's matrices.
Needs a fresh migrated database. Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_roles_e2e.py"""
import os
import re
import pyotp
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from fastapi.testclient import TestClient
from app import pg
from app.access import catalogue as cat, routes
from app.admin_api import provision_org
from app.main import app
from app.security.middleware import limiter
from helpers_access import CSRF, add_user, bearer, password_token, sql, two_factor_token

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)

with pg.tx(platform=True) as cur:
    T, tr = provision_org(cur, "Roles Co", "MSB", "M8200001", plan="enterprise")
SKIP = {("GET", "/wallets/{address}/trace"), ("POST", "/cases/{alert_id}/investigate")}        # call outside services
ZERO = "00000000-0000-0000-0000-000000000000"
FILL = {"alert_id": "NOPE", "sid": "NOPE", "address": "0x0", "prefix": "sk_live_none", "role_id": ZERO, "uid": ZERO, "user_id": ZERO, "org_id": ZERO,
        "approval_id": ZERO, "family_id": ZERO, "key": "starter", "rid": ZERO, "gid": ZERO, "tid": ZERO, "token": "none", "passkey_id": ZERO, "sid_": ZERO}
BODY = {"reason": "role matrix check"}

# who signs in: tenant roles (all with an authenticator app, signed in fresh so step-up isn't what is being tested) and platform roles
people = {}
for name in (cat.TENANT_ADMIN, "Compliance officer", "Compliance analyst", "Auditor (read-only)"):
    secret = pyotp.random_base32()
    email = re.sub(r"\W+", "-", name.lower()) + "@roles.example.com"
    uid = add_user(T, tr[name], email, secret=secret)
    people[name] = ("tenant", bearer(two_factor_token(c, email, secret)), uid, tr[name])
for name, role_id in (("Platform owner", cat.PLATFORM_OWNER_ROLE_ID), ("Platform support", cat.PLATFORM_SUPPORT_ROLE_ID),
                      ("Platform auditor", cat.PLATFORM_AUDITOR_ROLE_ID)):
    secret = pyotp.random_base32()
    email = re.sub(r"\W+", "-", name.lower()) + "@roles.example.com"
    uid = add_user(None, role_id, email, secret=secret)
    people[name] = ("platform", bearer(two_factor_token(c, email, secret)), uid, role_id)

table = [r for r in routes.route_table(app) if r["kind"] == "permission" and (r["method"], r["path"]) not in SKIP]
ok(len(table) >= 90, f"the route table has {len(table)} permission-protected routes to check")


def held(role_id) -> set:
    return {r[0] for r in sql(SUPER, "SELECT perm FROM role_permissions WHERE role_id=%s", role_id)}


def call(tok, r):
    path = re.sub(r"\{(\w+)\}", lambda m: FILL.get(m.group(1), "x"), r["path"])
    kw = {"headers": tok}
    if r["method"] in ("POST", "PUT", "PATCH"):
        kw["json"] = BODY
    return getattr(c, r["method"].lower())(path, **kw)


for name, (scope, tok, uid, role_id) in people.items():
    mine = held(role_id)
    me = c.get("/me", headers=tok)
    ok(me.status_code == 200 and me.json()["role"] == name and set(me.json()["permissions"]) >= mine, f"{name}: signs in and /me lists the role's permissions")
    wrong, checked = [], 0
    for r in table:
        needed = r["perms"]
        may = (any(p in mine for p in needed) if r["any"] else all(p in mine for p in needed))
        # a permission held only through an old name still counts (the alias is resolved by the API, not by this test)
        if not may and not r["any"]:
            may = all(p in mine or any(p in al for k, al in cat.ALIASES.items() if k in mine) for p in needed)
        status = call(tok, r).status_code
        checked += 1
        if may and status in (401, 403):
            wrong.append((r["method"], r["path"], status, "should be allowed"))
        if not may and status not in (401, 403):
            wrong.append((r["method"], r["path"], status, "should be refused"))
    ok(not wrong, f"{name}: {checked} routes, allowed ones open and every other refused ({wrong[:3]})")

# invariants from the brief's matrices, spelled out so a change to a template has to be a deliberate edit of this list
inv = {
    "Compliance analyst": {"yes": ["cases.view", "cases.decide", "str.draft", "wallet.trace"], "no": ["str.approve", "screening.override", "policy.edit", "data.export", "users.manage", "audit.view", "security.manage", "apikeys.manage"]},
    "Compliance officer": {"yes": ["cases.view", "str.approve", "screening.override", "policy.edit", "data.export", "audit.view"], "no": ["users.manage", "security.manage", "apikeys.manage", "roles.manage", "features.manage"]},
    "Auditor (read-only)": {"yes": ["cases.view", "audit.view", "audit.export"], "no": ["cases.decide", "str.draft", "str.approve", "users.manage", "security.manage", "data.export"]},
    cat.TENANT_ADMIN: {"yes": list(cat.TENANT_PERMS), "no": []},
    "Platform support": {"yes": ["platform.support"], "no": ["platform.tenants.manage", "platform.tenant.access", "platform.owners.manage", "platform.security.manage", "cases.view", "audit.view"]},
    "Platform auditor": {"yes": ["platform.audit.view"], "no": ["platform.tenants.manage", "platform.tenant.access", "platform.support", "cases.view"]},
    "Platform owner": {"yes": list(cat.PLATFORM_PERMS), "no": ["cases.view", "cases.decide", "str.approve", "data.export", "users.manage"]},
}
for name, rule in inv.items():
    mine = held(people[name][3])
    ok(all(p in mine for p in rule["yes"]) and not any(p in mine for p in rule["no"]), f"{name}: holds exactly the intended kind of access")

# platform staff reach no customer data, whatever they call
for name in ("Platform owner", "Platform support", "Platform auditor"):
    tok = people[name][1]
    ok(c.get("/alerts", headers=tok).status_code in (401, 403) and c.get("/search", headers=tok, params={"q": "x", "reason": "check"}).status_code in (401, 403),
       f"{name}: customer data is refused (it is only reachable through an access session)")
# and tenant roles reach no platform route
for name in (cat.TENANT_ADMIN, "Compliance officer", "Compliance analyst", "Auditor (read-only)"):
    tok = people[name][1]
    ok(all(c.get(p, headers=tok).status_code in (401, 403) for p in ("/platform/orgs", "/platform/users", "/platform/security", "/platform/approvals")),
       f"{name}: the platform console is refused")

# effective permissions agree with what the API enforces
admin_tok = people[cat.TENANT_ADMIN][1]
for name in ("Compliance officer", "Compliance analyst", "Auditor (read-only)"):
    eff = c.get(f"/admin/users/{people[name][2]}/effective-permissions", headers=admin_tok).json()
    ok({p["key"] for p in eff["permissions"]} == held(people[name][3]), f"{name}: 'effective permissions' lists exactly the stored permissions")
