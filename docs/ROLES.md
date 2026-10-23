# Roles and permissions (seed data)

Generated from the database seed (now itself synced from `backend/app/access/catalogue.py`; see [permissions.md](permissions.md)) by `backend/scripts/roles_doc.py`.
Every permission belongs to one login type. A database trigger rejects any role that mixes them,
so platform staff can never be given access to customer data.

## Platform console login (Sentrail staff)

- **Platform owner**: Full control of the platform. Holds the break-glass login
- **Platform support**: Helps tenants with sign-in. Never sees customer data
- **Platform auditor**: Reads the platform audit log

| Permission | Platform owner | Platform support | Platform auditor |
|---|---|---|---|
| View and verify the platform audit log (`platform.audit.view`) | ✓ |  | ✓ |
| Edit plans and a tenant's feature set (`platform.plans.manage`) | ✓ |  |  |
| Platform security baseline (loosening needs second-owner approval) (`platform.security.manage`) | ✓ |  |  |
| Add, change or suspend owners (second-owner approval) (`platform.owners.manage`) | ✓ |  |  |
| Edit platform roles (`platform.roles.manage`) | ✓ |  |  |
| Invite, suspend and change support and auditor staff (`platform.users.manage`) | ✓ |  |  |
| List tenants, view masked users, resend invitations (reason required) (`platform.support`) | ✓ | ✓ |  |
| Enter a tenant with Tenant admin rights through an access session (`platform.tenant.access`) | ✓ |  |  |
| Delete a tenant (second-owner approval) (`platform.tenants.delete`) | ✓ |  |  |
| Create a tenant, invite its first admin, change plan, suspend or reactivate, assign a replacement admin (`platform.tenants.manage`) | ✓ |  |  |

## Organization login (customers)

- **Tenant admin**: Every tenant permission inside their own tenant. Locked: cannot be edited or deleted
- **Compliance officer**: Works cases, approves STRs, overrides held screenings, sets policy, exports
- **Compliance analyst**: Works alerts and drafts STRs for approval
- **Auditor (read-only)**: Reads cases and the audit log

| Permission | Tenant admin | Compliance officer | Compliance analyst | Auditor (read-only) |
|---|---|---|---|---|
| Create, list, rotate and revoke API keys (`apikeys.manage`) | ✓ |  |  |  |
| Switch plan features on or off (`features.manage`) | ✓ |  |  |  |
| Create and edit custom roles (`roles.manage`) | ✓ |  |  |  |
| Two-factor policy, timeouts, passwords, IP allowlist, retention, SSO, owner-access setting (`security.manage`) | ✓ |  |  |  |
| Create teams and queues (optional) (`teams.manage`) | ✓ | ✓ |  |  |
| Invite, suspend and change the role of members (`users.manage`) | ✓ |  |  |  |
| Reveal a member's email (reason required) (`users.pii.reveal`) | ✓ |  |  |  |
| Decide and assign alerts; upload statements (`cases.decide`) | ✓ | ✓ | ✓ |  |
| Cases marked restricted (need-to-know) (`cases.restricted.view`) | ✓ | ✓ |  |  |
| Alert queue, case detail, screenings, search, current policy (`cases.view`) | ✓ | ✓ | ✓ | ✓ |
| Override a held screening, once (`screening.override`) | ✓ | ✓ |  |  |
| Trace a wallet (`wallet.trace`) | ✓ | ✓ | ✓ |  |
| Run and sign off access reviews (`access.review`) | ✓ |  |  |  |
| Export or stream the tenant audit log (`audit.export`) | ✓ |  |  | ✓ |
| View the tenant audit log and verify the chain (`audit.view`) | ✓ | ✓ |  | ✓ |
| Screening policy thresholds (`policy.edit`) | ✓ | ✓ |  |  |
| Export a full case with its STR (reason required) (`data.export`) | ✓ | ✓ |  |  |
| Approve and file an STR (never one you drafted) (`str.approve`) | ✓ | ✓ |  |  |
| AI investigation, draft and submit an STR (`str.draft`) | ✓ | ✓ | ✓ |  |

Platform roles are created once by migration 005. Organization roles are copied from these templates
into every new organization by `provision_org()`, and each organization can add its own custom roles.
