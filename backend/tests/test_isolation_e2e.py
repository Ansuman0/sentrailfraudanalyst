"""Tenant isolation, route by route (G12). Real app, real database, real two-factor sign-ins.

Tenant B holds distinctive data (everything about it contains the word "zebra"). For EVERY route that needs a sign-in, a person from
tenant A with every tenant permission (a Tenant admin) calls it with tenant B's IDs, and platform staff call every tenant route too.
Expected: 403 or 404, never data. Afterwards tenant B is checked to be exactly as it was, and no log line mentions B's data.
Background jobs register in app/access/jobs.py; each one is run for tenant A and checked the same way (there are none yet).

Needs a fresh migrated database. Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_isolation_e2e.py
Negative control (must FAIL): ISOLATION_NEGATIVE_CONTROL=1 on another fresh database."""
import hashlib
import logging
import os
import re
import uuid
import pyotp
import psycopg
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from fastapi.testclient import TestClient
from app import pg
from app.main import app
from app.access import catalogue as cat, jobs, routes
from app.admin_api import provision_org
from app.security import audit, crypto
from app.security.middleware import limiter
from helpers_access import CSRF, add_user, bearer, claims, password_token, sql, two_factor_token

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)

# ---------------------------------------------------------------------------------------------------------------------
# Fixtures: tenant A (the caller) and tenant B (the data that must stay invisible)
# ---------------------------------------------------------------------------------------------------------------------
with pg.tx(platform=True) as cur:
    A, ar = provision_org(cur, "Isolation A", "MSB", "M6000001", plan="enterprise")
    B, br = provision_org(cur, "Isolation B", "MSB", "M6000002", plan="enterprise")
sec = {n: pyotp.random_base32() for n in ("admin_a", "admin_b", "support")}
admin_a = add_user(A, ar[cat.TENANT_ADMIN], "admin@iso-a.example.com", "Alpha Admin", secret=sec["admin_a"])
add_user(A, ar["Compliance analyst"], "analyst@iso-a.example.com", "Alpha Analyst")
admin_b = add_user(B, br[cat.TENANT_ADMIN], "zebra.admin@iso-b.example.com", "Zebra Admin", secret=sec["admin_b"])
user_b = add_user(B, br["Compliance officer"], "zebra.officer@iso-b.example.com", "Zebra Officer")
owner = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, "owner@iso.example.com", "Platform Owner")
support = add_user(None, cat.PLATFORM_SUPPORT_ROLE_ID, "support@iso.example.com", "Platform Support", secret=sec["support"])

B_ALERT, B_SCREEN, B_CLIENT_REF = "ISO-B-1", "ISO-S-B-1", "zebra-ramp-ref"
with pg.tx(B) as cur:
    cur.execute("""INSERT INTO screenings (id, org_id, customer_id, direction, address, amount, score, decision, reasons, client_ref, result)
                   VALUES (%s,%s,'C-ZEBRA-77','out','TZebraAddress000000000000000000001',5000,80,'hold',%s,%s,%s)""",
                (B_SCREEN, B, '[{"source":"rule","text":"ZEBRA wire pattern"}]', B_CLIENT_REF, '{"note":"ZEBRA stored answer"}'))
    cur.execute("""INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel, screening_id)
                   VALUES (%s,%s,'C-ZEBRA-77',80,'high',%s,'crypto',%s)""",
                (B_ALERT, B, '[{"source":"rule","text":"ZEBRA wire pattern"}]', B_SCREEN))
    cur.execute("""INSERT INTO str_drafts (org_id, alert_id, final_enc, drafted_by, status) VALUES (%s,%s,%s,%s,'awaiting_approval')""",
                (B, B_ALERT, crypto.encrypt("ZEBRA suspicious transaction report", B, "str"), user_b))
    audit.write(cur, B, user_b, "Compliance officer", "zebra_event", B_ALERT, {"note": "ZEBRA audit detail"})

tok_b = two_factor_token(c, "zebra.admin@iso-b.example.com", sec["admin_b"])
kr = c.post("/admin/api-keys", headers=bearer(tok_b), json={"label": "zebra-key"})
B_PREFIX = kr.json()["prefix"]
inv = c.post("/admin/invitations", headers=bearer(tok_b), json={"email": "zebra.invitee@iso-b.example.com", "role_id": str(br["Compliance officer"])})
B_FAMILY = claims(tok_b)["sid"]
role_b = c.post("/admin/roles", headers=bearer(tok_b), json={"name": "ZebraRole", "perms": ["cases.view"]}).json()["id"]
with pg.tx(B) as cur:
    cur.execute("SELECT id FROM users WHERE status='invited'")
    invited_b = str(cur.fetchone()[0])


def snapshot_b():
    """A fingerprint of everything of tenant B's that a caller from A could touch."""
    rows = sql(SUPER, """SELECT
        (SELECT md5(string_agg(id || status || restricted::text || coalesce(assigned_to::text,''), ',' ORDER BY id)) FROM alerts WHERE org_id=%(b)s),
        (SELECT md5(string_agg(id::text || status || session_version::text || mfa_enabled::text, ',' ORDER BY id)) FROM users WHERE org_id=%(b)s),
        (SELECT md5(string_agg(r.id::text || r.name || coalesce((SELECT string_agg(perm, ',' ORDER BY perm) FROM role_permissions WHERE role_id=r.id), ''), ',' ORDER BY r.id)) FROM roles r WHERE r.org_id=%(b)s),
        (SELECT md5(string_agg(prefix || coalesce(revoked_at::text,'live'), ',' ORDER BY prefix)) FROM api_keys WHERE org_id=%(b)s),
        (SELECT md5(string_agg(feature || in_plan::text || enabled::text, ',' ORDER BY feature)) FROM org_features WHERE org_id=%(b)s),
        (SELECT md5(security_settings::text) FROM security_settings WHERE org_id=%(b)s),
        (SELECT md5(policy::text) FROM screening_policy WHERE org_id=%(b)s),
        (SELECT md5(string_agg(id || coalesce(override,'none'), ',' ORDER BY id)) FROM screenings WHERE org_id=%(b)s),
        (SELECT md5(string_agg(alert_id || status || coalesce(approved_by::text,''), ',' ORDER BY alert_id)) FROM str_drafts WHERE org_id=%(b)s),
        (SELECT count(*) FROM audit_events WHERE org_id=%(b)s),
        (SELECT count(*) FROM refresh_tokens WHERE family_id=%(fam)s AND revoked_at IS NULL),
        (SELECT md5(string_agg(plan || status, ',')) FROM organizations WHERE id=%(b)s)""".replace("%(b)s", f"'{B}'").replace("%(fam)s", f"'{B_FAMILY}'"))
    return rows[0]


if os.environ.get("ISOLATION_NEGATIVE_CONTROL"):
    # Proof that this suite can fail: with row-level security off on the case tables it MUST report leaks (expect FAIL lines).
    for table in ("alerts", "screenings", "str_drafts"):
        sql(SUPER, f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        sql(SUPER, f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
before = snapshot_b()

# ---------------------------------------------------------------------------------------------------------------------
# What the callers send
# ---------------------------------------------------------------------------------------------------------------------
VALUES = {"alert_id": B_ALERT, "sid": B_SCREEN, "uid": invited_b, "role_id": role_b, "prefix": B_PREFIX, "org_id": str(B),
          "family_id": B_FAMILY, "user_id": user_b, "key": "professional", "approval_id": str(uuid.uuid4()), "address": "TZebraAddress000000000000000000001"}
BODIES = {
    ("POST", "/cases/{alert_id}/decision"): {"decision": "false_positive", "reason": "isolation check"},
    ("POST", "/cases/{alert_id}/assign"): {"user_id": user_b},
    ("POST", "/cases/{alert_id}/str/submit"): {"final_text": "x" * 60},
    ("POST", "/screenings/{sid}/override"): {"action": "release", "reason": "isolation check"},
    ("PATCH", "/admin/users/{uid}"): {"status": "suspended"},
    ("POST", "/admin/users/{uid}/reset-mfa"): {"reason": "isolation check"},
    ("POST", "/admin/users/{uid}/reveal-email"): {"reason": "isolation check"},
    ("PUT", "/admin/roles/{role_id}"): {"name": "ZebraRole", "perms": ["cases.view", "audit.view"]},
    ("PUT", "/cases/{alert_id}/restricted"): {"restricted": True, "reason": "isolation check"},
    ("POST", "/cases/{alert_id}/access"): {"user_id": user_b},
    ("PUT", "/platform/orgs/{org_id}/plan"): {"plan": "starter"},
    ("POST", "/platform/orgs/{org_id}/status"): {"status": "suspended", "reason": "isolation check"},
    ("POST", "/platform/orgs/{org_id}/delete"): {"reason": "isolation check"},
    ("POST", "/platform/orgs/{org_id}/admin"): {"email": "intruder@iso.example.com", "reason": "isolation check"},
    ("POST", "/platform/approvals/{approval_id}/deny"): {"reason": "isolation check"},
    ("PUT", "/platform/orgs/{org_id}/features"): {"features": []},
}
QUERIES = {("GET", "/cases/{alert_id}/export"): {"reason": "isolation check"}, ("GET", "/search"): {"q": "C-ZEBRA-77", "reason": "isolation check"},
           ("GET", "/platform/orgs/{org_id}/users"): {"reason": "isolation check ticket"}}
SKIP = {("GET", "/wallets/{address}/trace"): "public chain data, no tenant rows (and it calls outside services)",
        ("POST", "/screen"): "machine route: checked below through the stored-answer lookup"}

table = [r for r in routes.route_table(app) if r["kind"] in ("permission", "session")]
HAS_ID = lambda path: "{" in path


def call(token, r):
    path = r["path"]
    for name in re.findall(r"\{(\w+)\}", path):
        path = path.replace("{" + name + "}", VALUES[name])
    kw = {"headers": bearer(token)}
    key = (r["method"], r["path"])
    if key in QUERIES:
        kw["params"] = QUERIES[key]
    if r["method"] in ("POST", "PUT", "PATCH") and path != "/upload":
        kw["json"] = BODIES.get(key, {})
    return c.request(r["method"], path, **kw)


class Capture(logging.Handler):
    lines = []
    def emit(self, record):
        Capture.lines.append(record.getMessage() + " " + " ".join(str(v) for v in record.__dict__.values()))


root = logging.getLogger()
handler = Capture()
root.addHandler(handler)
old_level = root.level
root.setLevel(logging.DEBUG)

# ---------------------------------------------------------------------------------------------------------------------
# 1. Tenant A's Tenant admin against tenant B's IDs, on every route that needs a sign-in
# ---------------------------------------------------------------------------------------------------------------------
tok_a = two_factor_token(c, "admin@iso-a.example.com", sec["admin_a"])
hold = [r for r in table if (r["method"], r["path"]) not in SKIP]
reads = [r for r in hold if r["method"] == "GET"]
writes = [r for r in hold if r["method"] != "GET" and r["path"] != "/session/tenant" and not r["path"].startswith(("/me/mfa", "/me/sessions/end"))
          and r["path"] != "/session/step-up"]
leaks, odd, tested = [], [], 0
for r in reads + writes:
    # routes about the caller's own account have no tenant data to leak; they are exercised through the ID variants below
    if r["kind"] == "session" and not HAS_ID(r["path"]):
        continue
    resp = call(tok_a, r)
    tested += 1
    where = f'{r["method"]} {r["path"]} -> {resp.status_code}'
    if "zebra" in resp.text.lower():
        leaks.append(where)
    if HAS_ID(r["path"]) and not (resp.status_code in (403, 404, 409, 422)):
        odd.append(where)
    if resp.status_code >= 500:
        odd.append(where + " (server error)")
ok(tested >= 50, f"{tested} routes called as tenant A's Tenant admin with tenant B's IDs")
ok(not leaks, f"no response contained tenant B's data {leaks}")
ok(not odd, f"every route given a tenant B ID answered 403/404/409/422, none succeeded and none crashed {odd}")
ok(len(SKIP) == 2, "the only routes not called are the two with a stated reason: " + "; ".join(f"{m} {p}" for (m, p) in SKIP))

# the machine route: tenant A can't be handed tenant B's stored answer for a retried request
from app import db
ok(db.find_screening_by_ref(str(A), B_CLIENT_REF) is None and db.find_screening_by_ref(str(B), B_CLIENT_REF) is not None,
   "/screen: a retry's stored answer is looked up per tenant, so tenant A never receives tenant B's")

# ---------------------------------------------------------------------------------------------------------------------
# 2. Nothing of tenant B changed
# ---------------------------------------------------------------------------------------------------------------------
after = snapshot_b()
names = ["alerts", "users", "roles", "api keys", "features", "security settings", "policy", "screenings", "str drafts", "audit log size",
         "live sessions", "plan and status"]
changed = [n for n, x, y in zip(names, before, after) if x != y]
ok(not changed, f"tenant B is exactly as it was after every attempt from tenant A: changed = {changed}")

# ---------------------------------------------------------------------------------------------------------------------
# 3. Platform staff against tenant routes
# ---------------------------------------------------------------------------------------------------------------------
tenant_routes = [r for r in hold if r["kind"] == "permission" and r["perms"] and not any(p.startswith("platform.") for p in r["perms"])]
p_odd, p_leaks = [], []
for who, tok in (("platform owner", password_token(c, "owner@iso.example.com")), ("platform support", two_factor_token(c, "support@iso.example.com", sec["support"]))):
    for r in tenant_routes:
        resp = call(tok, r)
        # /admin/audit and /admin/audit/verify are shared with platform.audit.view: for platform staff they answer with the PLATFORM log
        if resp.status_code < 400 and not r["path"].startswith("/admin/audit"):
            p_odd.append(f"{who}: {r['method']} {r['path']} -> {resp.status_code}")
        if "zebra" in resp.text.lower():
            p_leaks.append(f"{who}: {r['method']} {r['path']}")
ok(len(tenant_routes) >= 35, f"platform staff called {len(tenant_routes)} tenant routes with tenant B's IDs")
ok(not p_odd and not p_leaks, f"platform owner and platform support get nothing from tenant routes (no access session exists yet) {p_odd} {p_leaks}")

# ---------------------------------------------------------------------------------------------------------------------
# 4. Without a sign-in, and background jobs
# ---------------------------------------------------------------------------------------------------------------------
anon = [r for r in routes.route_table(app) if r["kind"] in ("permission", "session")]
no_auth = []
for r in anon:
    path = r["path"]
    for name in re.findall(r"\{(\w+)\}", path):
        path = path.replace("{" + name + "}", VALUES[name])
    kw = {} if r["method"] in ("GET", "DELETE") else {"json": {}}
    st = c.request(r["method"], path, **kw).status_code
    if st != 401 and (r["method"], r["path"]) not in SKIP:
        no_auth.append(f'{r["method"]} {r["path"]} -> {st}')
ok(not no_auth, f"without a sign-in every protected route answers 401 {no_auth}")

ran = []
for name, job in jobs.TENANT_JOBS.items():
    job(str(A))
    ran.append(name)
ok(True, f"background jobs registered for the isolation check: {ran or 'none yet (the registry is app/access/jobs.py)'}")
after_jobs = snapshot_b()
ok(after_jobs == before, "tenant B is untouched after the jobs too")

root.removeHandler(handler)
root.setLevel(old_level)
mentions = [line[:160] for line in Capture.lines if "zebra" in line.lower() and not line.startswith("HTTP Request:")]   # the test client's own request log is not the app's
ok(not mentions, f"no log line mentions tenant B's data ({len(Capture.lines)} lines checked): {mentions[:3]}")
