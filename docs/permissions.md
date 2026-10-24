# Permissions

Generated from `backend/app/access/catalogue.py` by `python -m scripts.gen_permissions_doc`. Do not edit by hand:
a unit test fails when this file is out of date.

"2FA" in the Step-up column means a fresh two-factor check within the step-up window.
Every signed-in user can also view their own profile, set up their own two-factor, manage their own sessions and switch tenants.

## Tenant roles

| Permission | Covers | Step-up | Tenant admin | Compliance officer | Compliance analyst | Auditor (read-only) |
|---|---|---|---|---|---|---|
| `cases.view` | Alert queue, case detail, screenings, search, current policy |  | ✓ | ✓ | ✓ | ✓ |
| `cases.restricted.view` | Cases marked restricted (need-to-know) |  | ✓ | ✓ |  |  |
| `wallet.trace` | Trace a wallet |  | ✓ | ✓ | ✓ |  |
| `cases.decide` | Decide and assign alerts; upload statements |  | ✓ | ✓ | ✓ |  |
| `str.draft` | AI investigation, draft and submit an STR |  | ✓ | ✓ | ✓ |  |
| `str.approve` | Approve and file an STR (never one you drafted) | 2FA | ✓ | ✓ |  |  |
| `screening.override` | Override a held screening, once | 2FA | ✓ | ✓ |  |  |
| `policy.edit` | Screening policy thresholds | 2FA | ✓ | ✓ |  |  |
| `data.export` | Export a full case with its STR (reason required) | 2FA | ✓ | ✓ |  |  |
| `audit.view` | View the tenant audit log and verify the chain |  | ✓ | ✓ |  | ✓ |
| `audit.export` | Export or stream the tenant audit log | 2FA | ✓ |  |  | ✓ |
| `users.manage` | Invite, suspend and change the role of members |  | ✓ |  |  |  |
| `users.pii.reveal` | Reveal a member's email (reason required) |  | ✓ |  |  |  |
| `security.manage` | Two-factor policy, timeouts, passwords, IP allowlist, retention, SSO, owner-access setting | 2FA | ✓ |  |  |  |
| `apikeys.manage` | Create, list, rotate and revoke API keys | 2FA | ✓ |  |  |  |
| `roles.manage` | Create and edit custom roles |  | ✓ |  |  |  |
| `features.manage` | Switch plan features on or off |  | ✓ |  |  |  |
| `access.review` | Run and sign off access reviews |  | ✓ |  |  |  |
| `teams.manage` | Create teams and queues (optional) |  | ✓ | ✓ |  |  |

**Tenant admin** is locked: it always holds every tenant permission and cannot be edited or deleted.

## Platform roles

| Permission | Covers | Step-up | Platform owner | Platform support | Platform auditor |
|---|---|---|---|---|---|
| `platform.tenants.manage` | Create a tenant, invite its first admin, change plan, suspend or reactivate, assign a replacement admin |  | ✓ |  |  |
| `platform.tenants.delete` | Delete a tenant (second-owner approval) | 2FA | ✓ |  |  |
| `platform.plans.manage` | Edit plans and a tenant's feature set |  | ✓ |  |  |
| `platform.support` | List tenants, view masked users, resend invitations (reason required) |  | ✓ | ✓ |  |
| `platform.tenant.access` | Enter a tenant with Tenant admin rights through an access session | 2FA | ✓ |  |  |
| `platform.users.manage` | Invite, suspend and change support and auditor staff |  | ✓ |  |  |
| `platform.owners.manage` | Add, change or suspend owners (second-owner approval) | 2FA | ✓ |  |  |
| `platform.roles.manage` | Edit platform roles |  | ✓ |  |  |
| `platform.security.manage` | Platform security baseline (loosening needs second-owner approval) | 2FA | ✓ |  |  |
| `platform.audit.view` | View and verify the platform audit log |  | ✓ |  | ✓ |

**Platform owner** holds every platform permission (an explicit list generated from this catalogue). It replaces the former Platform admin role.


`users.manage` keeps its name; its former extra powers are the separate permissions `users.pii.reveal`, `security.manage` and `apikeys.manage`.
