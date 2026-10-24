"""The one source of truth for permissions, scopes, step-up flags, role templates and permission aliases.

Everything else is derived from here:
  - `sync(conn)` makes the database match (permissions, templates, aliases, the locked Tenant admin role, the Platform owner role);
    `scripts/migrate.py` runs it after the SQL migrations, so a new permission is one edit in this file.
  - `render_markdown()` generates docs/permissions.md (`python -m scripts.gen_permissions_doc`); a unit test fails when the file is stale.

Access model spec: sections 3.3 (tenant matrix), 3.4 (platform matrix) and 3.2 (roles) of the access-control brief.
"""
from dataclasses import dataclass

TENANT, PLATFORM = "tenant", "platform"

TENANT_ADMIN = "Tenant admin"
PLATFORM_OWNER = "Platform owner"

# Fixed IDs of the built-in platform roles (organization roles get generated IDs per tenant).
PLATFORM_OWNER_ROLE_ID = "00000000-0000-0000-0000-000000000002"
PLATFORM_SUPPORT_ROLE_ID = "00000000-0000-0000-0000-000000000003"
PLATFORM_AUDITOR_ROLE_ID = "00000000-0000-0000-0000-000000000004"
LEGACY_PLATFORM_ADMIN_ROLE_ID = "00000000-0000-0000-0000-000000000001"   # merged into Platform owner by migration 009


@dataclass(frozen=True)
class Perm:
    key: str
    scope: str
    group: str
    description: str
    step_up: bool = False


# Pairs of permissions one role should not hold together (separation of duties). Shown as warnings on the roles screen; never blocking,
# because a small team may have a reason. The locked Tenant admin role is exempt (it holds everything by design).
SOD_CONFLICTS: list[tuple[str, str, str]] = [
    ("users.manage", "cases.decide", "One person could create an account and approve their own work."),
    ("users.manage", "str.approve", "One person could create an account and approve their own work."),
    ("str.draft", "str.approve", "One person could write a report and approve it (the system still blocks approving your own draft)."),
    ("roles.manage", "users.manage", "One person could give themselves or a colleague any access."),
    ("policy.edit", "screening.override", "One person could loosen the rules and then release the transfers they held back."),
    ("apikeys.manage", "screening.override", "One person could issue the key that screens transfers and also override its holds."),
    ("audit.export", "users.manage", "One person could change who has access and also take the evidence out."),
]


PERMISSIONS: list[Perm] = [
    # ---- Tenant permissions (section 3.3) ----
    Perm("cases.view", TENANT, "Customer data", "Alert queue, case detail, screenings, search, current policy"),
    Perm("cases.restricted.view", TENANT, "Customer data", "Cases marked restricted (need-to-know)"),
    Perm("wallet.trace", TENANT, "Customer data", "Trace a wallet"),
    Perm("cases.decide", TENANT, "Customer data", "Decide and assign alerts; upload statements"),
    Perm("str.draft", TENANT, "Reporting", "AI investigation, draft and submit an STR"),
    Perm("str.approve", TENANT, "Reporting", "Approve and file an STR (never one you drafted)", step_up=True),
    Perm("screening.override", TENANT, "Customer data", "Override a held screening, once", step_up=True),
    Perm("policy.edit", TENANT, "Governance", "Screening policy thresholds", step_up=True),
    Perm("data.export", TENANT, "Reporting", "Export a full case with its STR (reason required)", step_up=True),
    Perm("audit.view", TENANT, "Governance", "View the tenant audit log and verify the chain"),
    Perm("audit.export", TENANT, "Governance", "Export or stream the tenant audit log", step_up=True),
    Perm("users.manage", TENANT, "Administration", "Invite, suspend and change the role of members"),
    Perm("users.pii.reveal", TENANT, "Administration", "Reveal a member's email (reason required)"),
    Perm("security.manage", TENANT, "Administration",
         "Two-factor policy, timeouts, passwords, IP allowlist, retention, SSO, owner-access setting", step_up=True),
    Perm("apikeys.manage", TENANT, "Administration", "Create, list, rotate and revoke API keys", step_up=True),
    Perm("roles.manage", TENANT, "Administration", "Create and edit custom roles"),
    Perm("features.manage", TENANT, "Administration", "Switch plan features on or off"),
    Perm("access.review", TENANT, "Governance", "Run and sign off access reviews"),
    Perm("teams.manage", TENANT, "Administration", "Create teams and queues (optional)"),
    # ---- Platform permissions (section 3.4) ----
    Perm("platform.tenants.manage", PLATFORM, "Tenants",
         "Create a tenant, invite its first admin, change plan, suspend or reactivate, assign a replacement admin"),
    Perm("platform.tenants.delete", PLATFORM, "Tenants", "Delete a tenant (second-owner approval)", step_up=True),
    Perm("platform.plans.manage", PLATFORM, "Plans and policy", "Edit plans and a tenant's feature set"),
    Perm("platform.support", PLATFORM, "Tenants", "List tenants, view masked users, resend invitations (reason required)"),
    Perm("platform.tenant.access", PLATFORM, "Tenants", "Enter a tenant with Tenant admin rights through an access session", step_up=True),
    Perm("platform.users.manage", PLATFORM, "Platform team", "Invite, suspend and change support and auditor staff"),
    Perm("platform.owners.manage", PLATFORM, "Platform team", "Add, change or suspend owners (second-owner approval)", step_up=True),
    Perm("platform.roles.manage", PLATFORM, "Platform team", "Edit platform roles"),
    Perm("platform.security.manage", PLATFORM, "Plans and policy",
         "Platform security baseline (loosening needs second-owner approval)", step_up=True),
    Perm("platform.audit.view", PLATFORM, "Oversight", "View and verify the platform audit log"),
]

TENANT_PERMS = [p.key for p in PERMISSIONS if p.scope == TENANT]
PLATFORM_PERMS = [p.key for p in PERMISSIONS if p.scope == PLATFORM]
STEP_UP_PERMS = {p.key for p in PERMISSIONS if p.step_up}


@dataclass(frozen=True)
class Template:
    name: str
    scope: str
    description: str
    sort: int
    perms: tuple[str, ...]


# The Auditor template keeps its stored name "Auditor (read-only)" (it appears in seeds, tests and screens); the brief calls it "Auditor".
TEMPLATES: list[Template] = [
    Template(PLATFORM_OWNER, PLATFORM, "Full control of the platform. Holds the break-glass login", 1, tuple(PLATFORM_PERMS)),
    Template("Platform support", PLATFORM, "Helps tenants with sign-in. Never sees customer data", 2, ("platform.support",)),
    Template("Platform auditor", PLATFORM, "Reads the platform audit log", 3, ("platform.audit.view",)),
    Template(TENANT_ADMIN, TENANT, "Every tenant permission inside their own tenant. Locked: cannot be edited or deleted", 1, tuple(TENANT_PERMS)),
    Template("Compliance officer", TENANT, "Works cases, approves STRs, overrides held screenings, sets policy, exports", 2,
             ("cases.view", "cases.restricted.view", "wallet.trace", "cases.decide", "str.draft", "str.approve", "screening.override",
              "policy.edit", "data.export", "audit.view", "teams.manage")),
    Template("Compliance analyst", TENANT, "Works alerts and drafts STRs for approval", 3,
             ("cases.view", "wallet.trace", "cases.decide", "str.draft")),
    Template("Auditor (read-only)", TENANT, "Reads cases and the audit log", 4, ("cases.view", "audit.view", "audit.export")),
]
TEMPLATE_BY_NAME = {t.name: t for t in TEMPLATES}

# Names that existed before access model v2 and no longer do (migration 017 removed them for good): nothing may ask for them.
RETIRED_PERMISSIONS = ("orgs.manage", "orgs.delete")
RETIRED_ROLES = {"Platform admin": PLATFORM_OWNER, "Organization admin": TENANT_ADMIN}


# ---------------------------------------------------------------------------------------------------------------------
# Database sync
# ---------------------------------------------------------------------------------------------------------------------
def sync(conn) -> dict:
    """Make the database match this file. Idempotent. `conn` is a psycopg connection for the schema owner (not in a transaction).

    Never removes a permission from a role someone may have customised; it only
      - upserts permissions and templates,
      - gives the Platform owner role every platform permission and the locked Tenant admin roles every tenant permission,
        and ends the sessions of the holders when that added something (they reload their permissions on the next request).
    """
    changed = {"owner_added": 0, "tenant_admin_added": 0}
    with conn.transaction():
        conn.execute("SELECT set_config('app.platform', 'on', true)")
        conn.execute("SELECT set_config('app.role_sync', 'on', true)")
        for p in PERMISSIONS:
            conn.execute("""INSERT INTO permissions (key, description, scope, grp, step_up) VALUES (%s,%s,%s,%s,%s)
                            ON CONFLICT (key) DO UPDATE SET description=EXCLUDED.description, scope=EXCLUDED.scope,
                                                            grp=EXCLUDED.grp, step_up=EXCLUDED.step_up""",
                         (p.key, p.description, p.scope, p.group, p.step_up))
        for t in TEMPLATES:
            conn.execute("""INSERT INTO role_templates (name, scope, description, sort) VALUES (%s,%s,%s,%s)
                            ON CONFLICT (name) DO UPDATE SET scope=EXCLUDED.scope, description=EXCLUDED.description, sort=EXCLUDED.sort""",
                         (t.name, t.scope, t.description, t.sort))
            conn.execute("DELETE FROM role_template_permissions WHERE template=%s", (t.name,))
            for perm in t.perms:
                conn.execute("INSERT INTO role_template_permissions VALUES (%s,%s)", (t.name, perm))
        conn.execute("DELETE FROM role_templates WHERE name <> ALL(%s)", ([t.name for t in TEMPLATES],))

        # Platform owner: every platform permission.
        added = conn.execute("""INSERT INTO role_permissions SELECT %s, key FROM permissions WHERE scope='platform'
                                ON CONFLICT DO NOTHING RETURNING perm""", (PLATFORM_OWNER_ROLE_ID,)).fetchall()
        changed["owner_added"] = len(added)
        if added:
            conn.execute("UPDATE users SET session_version = session_version + 1 WHERE role_id = %s", (PLATFORM_OWNER_ROLE_ID,))
        # Locked Tenant admin roles: every tenant permission.
        rows = conn.execute("""INSERT INTO role_permissions
                               SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
                               WHERE r.is_locked AND r.scope='tenant' AND p.scope='tenant' ON CONFLICT DO NOTHING RETURNING role_id""").fetchall()
        changed["tenant_admin_added"] = len(rows)
        if rows:
            conn.execute("UPDATE users SET session_version = session_version + 1 WHERE role_id = ANY(%s)", (list({r[0] for r in rows}),))
    return changed


# ---------------------------------------------------------------------------------------------------------------------
# Generated documentation
# ---------------------------------------------------------------------------------------------------------------------
def _matrix(scope: str) -> list[str]:
    roles = [t for t in TEMPLATES if t.scope == scope]
    perms = [p for p in PERMISSIONS if p.scope == scope]
    lines = ["| Permission | Covers | Step-up | " + " | ".join(t.name for t in roles) + " |",
             "|---|---|---|" + "---|" * len(roles)]
    for p in perms:
        lines.append(f"| `{p.key}` | {p.description} | {'2FA' if p.step_up else ''} | "
                     + " | ".join("✓" if p.key in t.perms else "" for t in roles) + " |")
    return lines


def render_markdown() -> str:
    out = ["# Permissions",
           "",
           "Generated from `backend/app/access/catalogue.py` by `python -m scripts.gen_permissions_doc`. Do not edit by hand:",
           "a unit test fails when this file is out of date.",
           "",
           "\"2FA\" in the Step-up column means a fresh two-factor check within the step-up window.",
           "Every signed-in user can also view their own profile, set up their own two-factor, manage their own sessions and switch tenants.",
           "",
           "## Tenant roles", ""]
    out += _matrix(TENANT)
    out += ["", f"**{TENANT_ADMIN}** is locked: it always holds every tenant permission and cannot be edited or deleted.", "",
            "## Platform roles", ""]
    out += _matrix(PLATFORM)
    out += ["", f"**{PLATFORM_OWNER}** holds every platform permission (an explicit list generated from this catalogue). "
                "It replaces the former Platform admin role.", "",
            ""]
    out += ["`users.manage` keeps its name; its former extra powers are the separate permissions `users.pii.reveal`, "
                "`security.manage` and `apikeys.manage`.", ""]
    return "\n".join(out)
