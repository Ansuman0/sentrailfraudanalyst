"""Permission catalogue: internal consistency, and docs/permissions.md is generated from it (no database needed).
Run: PYTHONPATH=. python tests/test_catalogue_unit.py"""
from pathlib import Path
from app.access import catalogue as cat

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)

keys = [p.key for p in cat.PERMISSIONS]
ok(len(keys) == len(set(keys)), "every permission key is defined once")
ok(len(cat.TENANT_PERMS) == 19 and len(cat.PLATFORM_PERMS) == 10, "19 tenant and 10 platform permissions (access brief sections 3.3 and 3.4)")
ok(all(p.scope in ("tenant", "platform") for p in cat.PERMISSIONS), "every permission has a scope")
ok(all(k.startswith("platform.") for k in cat.PLATFORM_PERMS) and not any(k.startswith("platform.") for k in cat.TENANT_PERMS),
   "platform permissions are exactly the platform.* keys")
for t in cat.TEMPLATES:
    ok(set(t.perms) <= set(keys), f"template {t.name} only holds defined permissions")
    wrong = [k for k in t.perms if next(p.scope for p in cat.PERMISSIONS if p.key == k) != t.scope]
    ok(not wrong, f"template {t.name} holds only {t.scope} permissions")
ok(set(cat.TEMPLATE_BY_NAME[cat.PLATFORM_OWNER].perms) == set(cat.PLATFORM_PERMS), "Platform owner holds every platform permission")
ok(set(cat.TEMPLATE_BY_NAME[cat.TENANT_ADMIN].perms) == set(cat.TENANT_PERMS), "Tenant admin holds every tenant permission")
ok(cat.STEP_UP_PERMS == {"str.approve", "screening.override", "policy.edit", "data.export", "audit.export", "security.manage",
                         "apikeys.manage", "platform.tenants.delete", "platform.tenant.access", "platform.owners.manage",
                         "platform.security.manage"}, "step-up permissions match the matrices")
officer = set(cat.TEMPLATE_BY_NAME["Compliance officer"].perms)
analyst = set(cat.TEMPLATE_BY_NAME["Compliance analyst"].perms)
ok("str.approve" in officer and "str.approve" not in analyst and "screening.override" not in analyst,
   "analyst can't approve STRs or override held screenings; officer can")
ok(cat.TEMPLATE_BY_NAME["Auditor (read-only)"].perms == ("cases.view", "audit.view", "audit.export"), "auditor is read-only plus audit export")
ok(all(new in keys for news in cat.ALIASES.values() for new in news) and not set(cat.ALIASES) & set(keys), "aliases point at defined names and old names are gone")

perms, added = cat.expand_aliases({"platform.tenants.manage", "platform.support"})
ok("orgs.manage" in perms and added == {"orgs.manage"}, "holders of platform.tenants.manage still satisfy the old name orgs.manage")
perms, added = cat.expand_aliases({"platform.support"})
ok("orgs.manage" not in perms and not added, "an alias is not granted to someone without the new permission")

doc = Path(__file__).resolve().parents[2] / "docs" / "permissions.md"
ok(doc.exists() and doc.read_text(encoding="utf-8").replace("\r\n", "\n") == cat.render_markdown().replace("\r\n", "\n"),
   "docs/permissions.md is current (regenerate: python -m scripts.gen_permissions_doc)")

from scripts import gen_frontend_roles
fixture = gen_frontend_roles.target
ok(fixture.exists() and fixture.read_text(encoding="utf-8").replace(chr(13) + chr(10), chr(10)) == gen_frontend_roles.render(),
   "frontend/src/test/roles.fixture.json is current (regenerate: python -m scripts.gen_frontend_roles)")
