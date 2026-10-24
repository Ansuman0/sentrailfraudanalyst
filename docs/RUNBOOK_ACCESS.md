# Access runbook

What to do when something about *who can get in* needs a human: the sealed break-glass account, a platform owner who has to enter a
customer's organization, a customer who has lost its administrator, a company whose sign-in provider is down, a suspended or deleted
organization, and the worker that runs the background jobs. Design background: [IDENTITY.md](IDENTITY.md).

Every step below leaves an audit trail on purpose. Nothing here needs, or should use, direct database access.

## 1. Break-glass account

One sealed Platform owner account that works when nothing else does (it is the only platform login that may use a password without a passkey).

**Create it (once, by an operator with the production environment):**
```
cd backend && BREAK_GLASS_PASSWORD='...20+ characters...' python -m scripts.create_break_glass breakglass@your-domain
```
Write the password on paper, seal it, store it where two people must be present to open it. The database allows exactly one such account.

**Use it only when** no owner can sign in (all lost their passkey, the sign-in screen itself is failing). Using it:
1. signs in with the password; every other owner is emailed and the platform log records `break_glass_used`;
2. everything stays locked until the password is changed (`POST /me/password`, or My account), which ends all its sessions;
3. reseal the new password.

**After use:** write down why (incident ticket), check the platform audit log for what was done, and confirm each owner has a passkey registered
again. If the seal was broken without a real need, treat it as a security incident and rotate immediately.

## 2. A platform owner has to work inside a customer's organization

Platform staff never see customer data directly. An owner asks for a time-limited session (Organizations > Request access, with a reason):

| The organization's setting (Security > who may enter) | What happens |
|---|---|
| allow (default) | the session starts at once; their administrators are emailed |
| require approval | a Tenant admin approves or denies under *Platform access requests* (requests lapse after 24 h) |
| deny | refused, unless a **second owner** approves a recorded legal hold for that organization |

The owner then enters from *Tenant access sessions*. A session lasts 60 minutes and can be extended once. It can be ended by the owner, by any
owner, or by the organization at any time. Everything the owner does is in the organization's audit log (tagged with the session) and in the
platform's. After the session, the organization's administrators can review exactly what happened under Audit log.

**Legal hold:** `POST /platform/orgs/{id}/legal-hold` (an owner asks, a second owner approves). While it is on, access to a `deny` organization is
possible; lifting it also needs a second owner.

## 3. The organization has lost its administrator

A Tenant admin account can't be removed if it is the last one, so this happens when the person has left without handing over, or lost their
authenticator and passkey.

1. Confirm who is entitled to ask (contract contact), out of band. Record the ticket.
2. A platform owner calls `POST /platform/orgs/{id}/admin {email, reason}` (API for now; there is no screen for it yet). If the
   new admin's email already has an account they get a Tenant admin membership; otherwise a 72-hour invitation is emailed. Two-factor is mandatory
   for them from the first sign-in. Both the organization's and the platform's audit logs record it.
3. If the lost admin only lost their second factor, a *different* admin resets it: Users > Reset two-factor (with a reason). An admin can't reset
   their own.

## 4. A company's sign-in provider is down (single sign-on enforced)

When company sign-in is enforced, passwords are refused for that company's people, except one **emergency login** (a Tenant admin with a passkey).
1. The company admin signs in with the emergency login (password plus passkey) and can turn enforcement off under *Company sign-in*.
2. If no emergency login was set up and the provider is down, the only route is an owner access session (section 2): inside it the owner has
   Tenant admin rights and turns enforcement off under *Company sign-in*. It is logged in both audit logs.

## 5. Suspending, reactivating and deleting an organization

* **Suspend** (Organizations > Suspend, with a reason): everyone is signed out and API keys stop working; data is kept. **Reactivate** reverses it.
* **Delete** needs a second owner: one asks (Delete…, with a reason), another approves under *Approvals* within 24 hours. The organization is then
  closed at once and its data is kept until its retention period (at least 5 years) ends, then removed by the worker, with a deletion record in the
  platform log. Before asking, tell the customer to export their data (Security > Export all data).

## 6. People who leave, or are inactive

* Remove access immediately: Users > Suspend (ends their sessions in that organization at once), or remove them in the identity provider when SCIM is on.
* People unused for the organization's dormant period (default 90 days) are suspended automatically and the administrators are told.
* Every quarter the system opens an access review; administrators mark each person keep, change or remove and sign it off (evidence: [soc2-access-evidence.md](soc2-access-evidence.md)).

## 7. The worker

`worker` (every compose file) runs `python -m scripts.run_jobs --loop` every five minutes: dormant members, access reviews, audit streaming,
export clean-up, platform staff review, tenant data removal, housekeeping. `python -m scripts.run_jobs` runs everything once; `--only name` runs one.

* Is it alive? `job_runs` records the last run and result of every job (platform scope); a job that has not run for an hour means the worker is down.
* One lock stops two runners from working at once; a second manual run says so and does nothing.
* A job that fails for one organization is logged (`job_failed`) and the others still run.

## 8. Quick reference: who can do what to whom

| I need to... | Who | Where |
|---|---|---|
| reset someone's two-factor | another Tenant admin | Users |
| replace the last admin | platform owner | `POST /platform/orgs/{id}/admin` (API) |
| add, change or suspend an owner | an owner, **approved by a second owner** | Staff, Approvals |
| loosen the platform security baseline | an owner, **approved by a second owner** | Security baseline, Approvals |
| enter a customer's organization | platform owner, per the customer's setting | Organizations, Tenant access sessions |
| end an owner's session inside my organization | my Tenant admin | Platform access requests |
