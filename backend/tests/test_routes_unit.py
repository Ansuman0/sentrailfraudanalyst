"""Every route declares what protects it, and docs/route-permissions.md is generated from that (no database needed).
Run: PYTHONPATH=. ENV=dev python tests/test_routes_unit.py"""
from pathlib import Path
from fastapi import Depends, FastAPI
from app.access import catalogue as cat, routes
from app.main import app
from app.security import rbac

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)

table = routes.route_table(app)
ok(len(table) >= 60, f"the route table covers the real app ({len(table)} routes)")
ok(routes.violations(app) == [], "every route in the real app declares a permission, is public by name, or is self-service")
ok(all(r["kind"] != "none" for r in table), "no route is unclassified")

public = {(r["method"], r["path"]) for r in table if r["kind"] == "public"}
ok(public == routes.PUBLIC, "the public list is exactly the allowlist (nothing is public by accident)")
ok({r["path"] for r in table if r["kind"] == "session"} <= {r["path"] for r in table if r["path"].startswith(routes.SELF_SERVICE_PREFIXES)},
   "signed-in-only routes are all self-service (/me*, /session/*)")
ok({(r["method"], r["path"]) for r in table if r["kind"] == "api_key"} == {("POST", "/screen")}, "only /screen takes an API key")

# every permission a route asks for exists (a typo would silently lock everyone out)
known = {p.key for p in cat.PERMISSIONS}
asked = {p for r in table for p in r["perms"]}
ok(asked <= known, f"every permission a route asks for is in the catalogue: {sorted(asked - known)}")
ok(not (asked & set(cat.RETIRED_PERMISSIONS)), "no route asks for a retired permission name")
# the split of users.manage: sensitive admin routes ask for their own permission
by_route = {(r["method"], r["path"]): r["perms"] for r in table}
ok(by_route[("GET", "/admin/security")] == ["security.manage"] and by_route[("PUT", "/admin/security")] == ["security.manage"], "security settings need security.manage")
ok(by_route[("POST", "/admin/api-keys")] == ["apikeys.manage"] and by_route[("DELETE", "/admin/api-keys/{prefix}")] == ["apikeys.manage"], "API keys need apikeys.manage")
ok(by_route[("POST", "/admin/users/{uid}/reveal-email")] == ["users.pii.reveal"], "revealing an email needs users.pii.reveal")
ok(by_route[("PUT", "/admin/sso")] == ["security.manage"], "company sign-in is a security setting")
ok(by_route[("POST", "/platform/orgs")] == ["platform.tenants.manage"], "creating a tenant needs platform.tenants.manage")
ok(by_route[("PUT", "/cases/{alert_id}/restricted")] == ["cases.decide", "cases.restricted.view"], "restricting a case needs both case work and restricted view")

# the check itself works
bad = FastAPI()


@bad.get("/open-door")
def open_door():
    return {}


@bad.get("/sneaky-session")
def sneaky(p=Depends(rbac.signed_in_user)):
    return {}


found = routes.violations(bad)
ok(len(found) == 2 and "open-door" in found[0] and "sneaky-session" in found[1], "a route with no permission, or a signed-in route outside /me, is a violation")
try:
    routes.check_routes(bad)
    ok(False, "check_routes refuses an unprotected route")
except RuntimeError as e:
    ok("open-door" in str(e), "check_routes raises, so the API refuses to start with an unprotected route")

doc = Path(__file__).resolve().parents[2] / "docs" / "route-permissions.md"
ok(doc.exists() and doc.read_text(encoding="utf-8").replace("\r\n", "\n") == routes.render_markdown(app).replace("\r\n", "\n"),
   "docs/route-permissions.md is current (regenerate: python -m scripts.gen_route_doc)")

# ---- no old permission name survives anywhere outside the migrations, the catalogue that retires it and the historical snapshot ----
import re
from pathlib import Path
root = Path(__file__).resolve().parents[2]
old = re.compile("|".join(re.escape(n) for n in cat.RETIRED_PERMISSIONS))
skip_dirs = {"node_modules", ".venv", "migrations", "memory", ".git", "__pycache__", "dist"}
skip_files = {"catalogue.py", "test_access_model_migration.py", "access-control-current-state.md", "test_routes_unit.py"}
hits = []
for f in root.rglob("*"):
    if f.is_file() and f.suffix in {".py", ".ts", ".tsx", ".md", ".yml", ".yaml", ".json", ".sh", ".tf", ".sql"} and f.name not in skip_files             and not (set(f.relative_to(root).parts) & skip_dirs):
        if old.search(f.read_text(encoding="utf-8", errors="ignore")):
            hits.append(str(f.relative_to(root)))
ok(not hits, f"no retired permission name is referenced anywhere in code, tests or docs: {hits}")
