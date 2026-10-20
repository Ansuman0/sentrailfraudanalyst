"""Print the role and permission seed data as a Markdown reference (docs/ROLES.md).
Usage: SUPERUSER_DATABASE_URL=... python -m scripts.roles_doc > docs/ROLES.md"""
import os
import psycopg

with psycopg.connect(os.environ["SUPERUSER_DATABASE_URL"]) as c:
    print("# Roles and permissions (seed data)\n")
    print("Generated from `role_templates`, `role_template_permissions` and `permissions` by `scripts/roles_doc.py`.")
    print("Every permission belongs to one login type. A database trigger rejects any role that mixes them,")
    print("so platform staff can never be given access to customer data.\n")
    for scope, title in (("platform", "Platform console login (Sentrail staff)"), ("tenant", "Organization login (customers)")):
        roles = c.execute("SELECT name, description FROM role_templates WHERE scope=%s ORDER BY sort", (scope,)).fetchall()
        perms = c.execute("SELECT key, description, grp FROM permissions WHERE scope=%s ORDER BY grp, key", (scope,)).fetchall()
        held = {(t, p) for t, p in c.execute("SELECT template, perm FROM role_template_permissions").fetchall()}
        print(f"## {title}\n")
        for n, d in roles:
            print(f"- **{n}**: {d}")
        print("\n| Permission | " + " | ".join(n for n, _ in roles) + " |")
        print("|---|" + "---|" * len(roles))
        for key, desc, grp in perms:
            print(f"| {desc} (`{key}`) | " + " | ".join("✓" if (n, key) in held else "" for n, _ in roles) + " |")
        print()
    print("Platform roles are created once by migration 005. Organization roles are copied from these templates")
    print("into every new organization by `provision_org()`, and each organization can add its own custom roles.")
