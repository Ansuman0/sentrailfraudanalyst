# Roles and permissions (seed data)

Generated from `role_templates`, `role_template_permissions` and `permissions` by `backend/scripts/roles_doc.py`.
Every permission belongs to one login type. A database trigger rejects any role that mixes them,
so platform staff can never be given access to customer data.

## Platform console login (Sentrail staff)

- **Platform owner**: Full control of the platform. Holds the break-glass login
- **Platform admin**: Runs tenants, plans and the platform team
- **Platform support**: Helps tenants with sign-in. Never sees customer data
- **Platform auditor**: Reads the platform audit log

| Permission | Platform owner | Platform admin | Platform support | Platform auditor |
|---|---|---|---|---|
| View the platform audit log (`platform.audit.view`) | ✓ | ✓ |  | ✓ |
| Manage plans and which features they include (`platform.plans.manage`) | ✓ | ✓ |  |  |
| Set the security baseline every tenant must meet (`platform.security.manage`) | ✓ |  |  |  |
| Edit platform roles (`platform.roles.manage`) | ✓ |  |  |  |
| Invite and manage platform staff (`platform.users.manage`) | ✓ | ✓ |  |  |
| Create organizations and change their plan (`orgs.manage`) | ✓ | ✓ |  |  |
| Support tenants: see user list and resend invitations (`platform.support`) | ✓ | ✓ | ✓ |  |

## Organization login (customers)

- **Organization admin**: Manages people, roles, features and security for one organization
- **Compliance officer**: Works cases, approves STRs and sets screening policy
- **Compliance analyst**: Works alerts and drafts STRs for approval
- **Auditor (read-only)**: Reads cases and the audit log

| Permission | Organization admin | Compliance officer | Compliance analyst | Auditor (read-only) |
|---|---|---|---|---|
| Turn features on or off (`features.manage`) | ✓ |  |  |  |
| Edit roles and permissions (`roles.manage`) | ✓ |  |  |  |
| Invite and manage users (`users.manage`) | ✓ |  |  |  |
| Close alerts, request info (`cases.decide`) |  | ✓ | ✓ |  |
| View alerts, cases and transfers (`cases.view`) |  | ✓ | ✓ | ✓ |
| Release or block held transfers (`screening.override`) |  | ✓ | ✓ |  |
| Trace wallets (`wallet.trace`) |  | ✓ | ✓ |  |
| View audit log (`audit.view`) | ✓ | ✓ |  | ✓ |
| Change screening policy (`policy.edit`) |  | ✓ |  |  |
| Export case data (`data.export`) |  | ✓ |  |  |
| Approve and file STRs (`str.approve`) |  | ✓ |  |  |
| Run AI investigation and draft STRs (`str.draft`) |  | ✓ | ✓ |  |

Platform roles are created once by migration 005. Organization roles are copied from these templates
into every new organization by `provision_org()`, and each organization can add its own custom roles.
