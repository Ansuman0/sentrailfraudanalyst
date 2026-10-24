# Access control: current state (Phase 0 discovery)

> **Historical snapshot.** This is the discovery report written *before* the access model was rebuilt (phase 0). It describes the old model, so it still names permissions and roles that no longer exist (for example `orgs.manage`, now `platform.tenants.manage`). For how things work now, read [IDENTITY.md](IDENTITY.md), [permissions.md](permissions.md) and [route-permissions.md](route-permissions.md).

Written 2026-10-23 against commit `37c90f1` (branch `main`). Read-only discovery for the access-control rebuild: no application code or migration was changed.
Everything below was read from the code; "not found" means a search of `backend/app`, `backend/scripts` and `backend/migrations` returned nothing.

**Vocabulary.** The code and database say *organization* (`organizations`, `org_id`, `org_features`, "Organization admin"); the target model says *tenant*. This document uses the code's names and gives the target name in brackets. See Question 1.

---

## 1. Where things live

| Concern | Where |
|---|---|
| Users | `users` table (`001_init.sql`, extended in `003`, `007`, `008`). One row per person, **one `org_id` and one `role_id` column**; `org_id IS NULL` = platform staff. Email and name are AES-GCM encrypted; `email_bidx` (HMAC) is **globally UNIQUE**. |
| Roles / permissions | `permissions(key, description, scope, grp)`, `roles(id, org_id, name, is_system)` (`org_id NULL` = platform role), `role_permissions(role_id, perm)`. Templates: `role_templates`, `role_template_permissions` (`005`). Platform roles have fixed IDs `…0001` Platform admin, `…0002` Platform owner, `…0003` Support, `…0004` Auditor. Organization system roles are created per organization by `admin_api.provision_org()`. |
| Authentication | `backend/app/admin_api.py` (one 1,316-line router): `/auth/login`, `/auth/mfa`, `/auth/refresh`, `/auth/discover`, `/auth/oidc/*`, `/auth/logout`, `/invitations/accept`, `/me/mfa/*`. Password hashing and policy: `security/passwords.py` (argon2id, length rule, Have-I-Been-Pwned range check, fails open). TOTP: `security/mfa.py`. |
| Sessions | `security/tokens.py`: Ed25519 JWT access token (10 min; claims `sub org rid sv amr sid jti`), opaque refresh token (12 h, SHA-256 stored in `refresh_tokens`, rotated on use, reuse revokes the family). `users.session_version` is checked on every request. Cookie `sentrail_rt`: HttpOnly, Secure, SameSite=Strict, path `/auth`. The access token travels in an `Authorization` header, never a cookie. |
| Two-factor | TOTP only. `users.mfa_enabled`, `mfa_enabled_at` (trigger), CHECK `users_mfa_has_secret`, `recovery_codes`. `security_settings.mfa_required` per organization. **No passkeys / WebAuthn code exists** (only the settings flags `platform_settings.passkeys_allowed` and `platform_staff_passkey_only`, never read by any check). |
| SSO | Keycloak OIDC (backend-for-frontend, `security/oidc.py`) when `AUTH_MODE=keycloak`. Per-organization columns on `organizations`: `sso_domain`, `sso_idp_alias`, `sso_enforced`, `sso_domain_pending`; `security_settings.sso_enabled/oidc_issuer/oidc_client_id`. No SAML. |
| API keys | `api_keys` (prefix, sha256 `key_hash`, `scopes` default `{screen}`, `label`, `created_at`, `revoked_at`). Auth: `rbac.api_key()`. |
| Plans / features | `plans(key, name, features[], max_users, sort)`, `org_features(org_id, feature, in_plan, enabled)` with CHECK limited to six features (`screening, alerts, ai, trace, statements, export`). |
| Audit log | `audit_events` (append-only trigger + revoked privileges), per-organization SHA-256 hash chain, advisory lock per organization (`security/audit.py`). Platform events use `org_id NULL` (own chain). `GET /admin/audit`, `GET /admin/audit/verify`. |
| Request authorization | `security/rbac.py`: `signed_in_user` → `current_user` → `require(*perms, feature=)` / `require_any(...)`. IP allowlist is checked inside `signed_in_user`. |
| Platform security baseline | `platform_settings` (single row) + trigger `enforce_platform_floor()` on `security_settings` (stricter-only: password length, idle timeout, retention). |
| Rate limits | `slowapi` (`security/middleware.py`, default 300/min per client IP; per-route limits in `admin_api.py`, `/screen` 600/min per API key). Sign-in lockout: table `login_throttle` keyed by (email blind index, IP), 5 failures → locked 15 min (`MAX_FAILED, LOCK_MIN = 5, 15`). |
| Tests | `backend/tests/`: `test_security_e2e` (33), `test_oidc_e2e` (20), `test_platform_e2e` (30), `test_cases_e2e` (78), plus unit suites. Run by `tests/run_all.sh`. |
| Web app | `frontend/src/pages/`: Users, Roles, Features, Security, Sso, ApiKeys, Audit, Organizations, Plans, PlatformSecurity, Account, SignIn, Join, TwoFactorSetup. **Missing** (already tracked as K-07): platform roles and platform staff screens. |

## 2. How the tenant reaches the database (RLS)

- `pg.tx(org_id, platform=False)` opens a transaction and runs `set_config('app.org_id', …, true)` and `set_config('app.platform', 'on'|'off', true)`. **The application sets the tenant**, from the access token's `org` claim (`p.org_id`). The database never checks that the user is a member of that organization; it trusts the GUC.
- Policy `tenant_isolation` (identical on `org_features, security_settings, roles, users, invitations, api_keys, alerts, str_drafts, screenings, screening_policy, audit_events`), FORCE RLS on:

  ```sql
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid
         OR (current_setting('app.platform', true) = 'on' AND <true|false per table>))
  ```
  `<true>` only for `org_features, security_settings, roles, users, invitations, audit_events`; `false` for alerts, str_drafts, screenings, screening_policy, api_keys. So platform mode can read and write **every organization's users, roles, security settings, invitations and audit events** at database level; case data and API keys are blocked from platform mode by the database.
- `organizations` has its own policy `org_self` (`id = app.org_id OR app.platform = 'on'`).
- **Tables with no RLS:** `refresh_tokens`, `recovery_codes`, `oidc_login_states`, `login_throttle` (tenant-linked only through `user_id` or a hash), and the global configuration tables `permissions, role_templates, role_template_permissions, plans, platform_settings`.
- **Paths that bypass or widen RLS:**
  1. `sentrail_auth` (NOLOGIN, BYPASSRLS) owns seven `SECURITY DEFINER` lookup functions used before the tenant is known: `auth_lookup`, `invitation_lookup`, `api_key_lookup`, `user_org_lookup`, `idp_lookup`, `sso_domain_lookup`, `org_display` (`001`, `003`, `004`). Column grants are narrow.
  2. `pg.tx(platform=True)`: 23 call sites in `admin_api.py` (platform console, invitations, login/refresh for platform users, org creation), plus scripts `seed.py`, `seed_demo_data.py`, `create_platform_admin.py`, `rotate_keys.py`.
  3. Bare `pg.pool().connection()` use for login throttle, token and invitation lookups, `api_key()` lookups.
  4. Superuser connections in scripts only: `schema_doc.py`, `roles_doc.py`, tests; `migrate.py` uses `sentrail_owner`.
  5. There are **no background jobs, schedulers or workers** in the codebase (searched for APScheduler, Celery, `BackgroundTasks`, `create_task`, cron). Exports are synchronous API calls.

## 3. Permissions and routes

### 3.1 Permission list in the database (after migrations 001–008)

Tenant scope: `cases.view, cases.decide, wallet.trace, screening.override, str.draft, str.approve, data.export, policy.edit, audit.view, users.manage, roles.manage, features.manage`.
Platform scope: `orgs.manage, platform.support, platform.users.manage, platform.roles.manage, platform.plans.manage, platform.security.manage, platform.audit.view`.

### 3.2 Current role templates (what the database seeds today)

| Role | Permissions today |
|---|---|
| Platform owner | orgs.manage, platform.support, platform.users.manage, platform.roles.manage, platform.plans.manage, platform.security.manage, platform.audit.view |
| Platform admin | orgs.manage, platform.support, platform.users.manage, platform.plans.manage, platform.audit.view |
| Platform support | platform.support |
| Platform auditor | platform.audit.view |
| Organization admin | **users.manage, roles.manage, features.manage, audit.view only, no case permissions at all** |
| Compliance officer | cases.view, cases.decide, wallet.trace, screening.override, str.draft, str.approve, data.export, policy.edit, audit.view |
| Compliance analyst | cases.view, cases.decide, wallet.trace, **screening.override**, str.draft |
| Auditor (read-only) | cases.view, audit.view |

### 3.3 Every route and its guard

Request check today: JWT valid → user reloaded (status, `session_version`, role, permissions) → IP allowlist → "second factor or allowed to skip" → permission → feature. There is **no tenant-status check** and no step-up window.

**Case and screening routes (`main.py`)**

| Route | Guard |
|---|---|
| GET `/healthz`, `/readyz` | none (public, by design) |
| GET `/alerts` | `cases.view` + feature `alerts` |
| GET `/cases/{id}`, GET `/search`, GET `/policy` | `cases.view` |
| GET `/wallets/{address}/trace` | `wallet.trace` + feature `trace` |
| POST `/cases/{id}/investigate` | `str.draft` + feature `ai` |
| POST `/cases/{id}/decision`, `/assign` | `cases.decide` |
| POST `/cases/{id}/str/submit` | `str.draft` |
| POST `/cases/{id}/str/approve` | `str.approve` (+ session-has-2FA) |
| GET `/cases/{id}/export` | `data.export` + feature `export` (+ 2FA); reason required |
| POST `/upload` | `cases.decide` + feature `statements` |
| POST `/screen` | API key; 600/min per key |
| GET `/screenings/{sid}` | `cases.view` + feature `screening` |
| POST `/screenings/{sid}/override` | `screening.override` + feature `screening` (+ 2FA) |
| PUT `/policy` | `policy.edit` (+ 2FA) |

**Identity, administration and platform routes (`admin_api.py`)**

| Route | Guard |
|---|---|
| POST `/auth/login` (5/min), `/auth/mfa` (10/min), `/auth/refresh`, `/auth/discover` (20/min), GET `/auth/oidc/login`, `/auth/oidc/callback`, `/auth/oidc/logout`, POST `/auth/logout`, POST `/invitations/accept` | none (pre-authentication, by design) |
| POST `/me/mfa/setup`, `/me/mfa/confirm`; GET `/me` | signed-in only |
| GET `/me/sessions`, DELETE `/me/sessions/{family}`, POST `/me/sessions/end-others` | signed-in (`current_user`) |
| POST `/admin/invitations`; GET `/admin/users`; POST `…/reveal-email`; PATCH `/admin/users/{uid}`; POST `…/reset-mfa` | `users.manage` |
| GET/POST `/admin/roles`, PUT `/admin/roles/{id}` | `roles.manage` |
| GET/PUT `/admin/features` | `features.manage` |
| GET/PUT `/admin/security` | **`users.manage`** |
| PUT `/admin/sso`, POST `/admin/sso/verify` | **`users.manage`** |
| POST/GET `/admin/api-keys`, DELETE `/admin/api-keys/{prefix}` | **`users.manage`** (+ feature `screening` on create) |
| GET `/admin/audit`, `/admin/audit/verify` | `audit.view` or `platform.audit.view` |
| POST/GET `/platform/orgs` | `orgs.manage` (list also `platform.support`) |
| PUT `/platform/orgs/{id}/features` | `platform.plans.manage` |
| PUT `/platform/orgs/{id}/plan` | `orgs.manage` |
| GET `/platform/orgs/{id}/users`, POST `…/resend-invitation` | `platform.support` |
| GET `/platform/users`, POST `/platform/invitations`, PATCH `/platform/users/{uid}` | `platform.users.manage` |
| GET/POST/PUT `/platform/roles…` | `platform.roles.manage` (list also `platform.users.manage`) |
| GET/PUT `/platform/plans…` | `platform.plans.manage` (GET also `orgs.manage`) |
| GET/PUT `/platform/security` | `platform.security.manage` |

**Routes with no permission declared:** only the pre-auth routes, the three health/`/me*` self-service routes above, and `/healthz`/`/readyz`. Every data route declares one. There is no startup or CI check that would catch a future route without one (G12 / Phase 3 item).

**Routes that do not exist at all:** tenant suspend/reactivate/delete, tenant switch, access sessions, approvals, access reviews, audit export or streaming, SCIM, teams, API-key rotation or expiry, step-up.

## 4. The scope trigger, quoted in full (`005_platform_console.sql`)

```sql
CREATE FUNCTION check_perm_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE role_scope text; perm_scope text;
BEGIN
  SELECT CASE WHEN org_id IS NULL THEN 'platform' ELSE 'tenant' END INTO role_scope FROM roles WHERE id = NEW.role_id;
  SELECT scope INTO perm_scope FROM permissions WHERE key = NEW.perm;
  IF role_scope IS DISTINCT FROM perm_scope THEN
    RAISE EXCEPTION 'permission % is for % roles, not % roles', NEW.perm, perm_scope, role_scope;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER role_perm_scope BEFORE INSERT OR UPDATE ON role_permissions
  FOR EACH ROW EXECUTE FUNCTION check_perm_scope();
```
The scope of a role is derived from `roles.org_id` (NULL = platform). A wildcard `*` cannot be stored as it is: `role_permissions.perm` is a foreign key to `permissions(key)`, and the trigger needs a scope for every permission.

---

## 5. Gap and improvement status

Legend: **Confirmed** (the gap exists as described), **Partly present** (some of it exists), **Solved**.

### Gaps

| ID | Status | Evidence |
|---|---|---|
| G1 One role per user | **Confirmed** | `users.org_id` and `users.role_id NOT NULL` in `001_init.sql`; `email_bidx UNIQUE` means one account per email. |
| G2 Single sign-in and switching | **Partly present** | One `/auth/login` serves all (no separate admin login) and the web app has one sign-in page. No tenant picker, `GET /me/tenants`, `POST /session/tenant`, or routing by membership count; token carries a single `org`. |
| G3 Audited owner access | **Confirmed absent, and deliberately blocked today** | Platform mode is denied case data by RLS (`false` for alerts, str_drafts, screenings, policy, api_keys). No access-session table or route. Phase 5 reverses a design property; see Conflict C4. |
| G4 Owner/admin split | **Confirmed** | Two platform roles with different permission sets (3.2); admin cannot edit roles or the security baseline. |
| G5 Old templates, locked Tenant admin | **Confirmed** | Organization admin has no case permissions (3.2). `is_system` exists, but nothing stops editing the admin role beyond the self-edit rule (`admin_api.py` ~793) and the "keep one admin" guard. |
| G6 Tenant SSO enforced | **Confirmed not enforced** | `sso_enforced` is stored. In `AUTH_MODE=local` password login is always allowed; in `keycloak` mode org users cannot use the password route at all (`found[1] is not None` → 401), which is a global switch, not the per-tenant flag. `sso_enforced` is read only by `sso_domain_lookup`, which returns it to `/auth/discover`, and that response ignores it. SAML absent; just-in-time membership absent. |
| G7 Passkeys / Tenant-admin 2FA | **Confirmed** | No WebAuthn. `platform_staff_passkey_only` is stored and never enforced. Two-factor is optional per organization by an explicit user decision (see Conflict C2). Since `37c90f1`, non-owner platform staff and the demo organizations are required to use TOTP. |
| G8 Step-up | **Partly present** | `MFA_SENSITIVE_PERMS` (`str.approve, data.export, policy.edit, screening.override`) require that the session used a second factor **at all**; there is no `last_mfa_at`, no time window and no `step_up_required` response. |
| G9 `users.manage` overloaded | **Confirmed** | One permission guards invites, users, email reveal, MFA reset, security settings, SSO and API keys (3.3). |
| G10 API key hardening | **Partly present** | Hashed (sha256), prefix shown, shown once, revoke, per-key rate limit, and keys are refused for inactive organizations or when screening is off. **Missing:** expiry, IP allowlist, `last_used_at`, rotation with overlap. Note the hash is a plain SHA-256 of a 256-bit random secret, adequate for that entropy. |
| G11 Tenant lifecycle | **Partly present** | `organizations.status` CHECK allows `pending, active, trial, suspended` (no `deleted`; `trial` is extra). `provision_org()` inserts `active` directly: no pending state and no first-admin invite in the same step. Status is honoured only at OIDC lookup and by `api_key()`. **No endpoint changes it.** `plans.max_users` exists (5/25/NULL, matching Section 3.7) but is **never enforced** at invite. |
| G12 Isolation tests | **Partly present** | A handful of checks (`test_security_e2e.py:83`, `test_cases_e2e.py:156`: another organization cannot open an alert; cannot assign another's role). No per-route sweep, no job coverage, no CI gate. |
| G13 SCIM | **Confirmed absent** | Nothing found. |
| G14 Access reviews | **Confirmed absent** | Nothing found. |
| G15 Dormant handling | **Confirmed absent** | `last_login_at` exists; nothing reads it. |
| G16 Audit export / retention | **Partly present** | `security_settings.retention_years` (≥5, platform floor) is stored and validated but **nothing enforces or deletes anything**. No export, no streaming. Hash-chain verify exists. |
| G17 Offboarding | **Confirmed absent** | No tenant export or deletion path. |
| G18 Owner-access setting | **Confirmed absent** | Moot until G3. |
| G19 Mixed names | **Confirmed** | `orgs.manage`, `users.manage` etc.; no aliases. |
| G20 Last-admin recovery | **Partly present** | `_keep_one_admin` prevents removing the last Organization admin; no owner-assigned replacement flow. |

### Improvements

| ID | Status | Evidence |
|---|---|---|
| I1 Credential protection | **Partly present** | Present: per-IP route limits (login 5/min), per-(email, IP) lockout (5 failures → 15 min, identical for unknown emails), argon2id, min length ≥12 (floor 14), breached check (HIBP k-anonymity), no composition rules. Differences from the target: the lock is 5 failures, not 10 in 15 minutes; no progressive delay; limits are per (email, IP), not per account across IPs; slowapi counters are in process memory (per worker). |
| I2 Session hardening | **Partly present** | Present: refresh cookie HttpOnly, Secure, SameSite=Strict; rotating refresh tokens with reuse detection; access token not in a cookie, so CSRF cannot ride it; idle timeout via shortened token lifetime, absolute limit via `max_session_hours`; `session_version` bumps revoke sessions on role, status, 2FA and password change. Missing: new session ID on tenant switch (no switching exists); explicit CSRF token (only cookie routes `/auth/refresh` and `/auth/logout`, protected by SameSite=Strict + CORS allowlist). |
| I3 Need-to-know cases | **Confirmed absent** | No `restricted` flag. |
| I4 Four-eyes platform actions | **Confirmed absent** | Platform owner removal is blocked only by the "keep one owner" rule. |
| I5 Break-glass | **Partly present** | Platform staff have a password + TOTP login described as break-glass (`admin_api.py:31`, `sign_in` label), but there is no sealed account, no alerting and no forced rotation. |
| I6 Security notifications | **Partly present** | `services/mailer.py` exists (invitations only). No new-device, 2FA, password or role-change email. |
| I7 Permission catalogue | **Partly present** | Seeds live in SQL migrations; `scripts/roles_doc.py` generates `docs/ROLES.md` from the database. No single source file; no CI freshness check; no "effective permissions" or "preview as role". |
| I8 Export controls | **Partly present** | `/cases/{id}/export` needs `data.export`, 2FA, plan feature and a reason, and is audited. No rate limit specific to export, watermark, expiring or single-use link. |
| I9 Anomaly alerts | **Confirmed absent** | No jobs, no volume or geolocation logic. |
| I10 Permission cache | **Solved (no cache exists)** | Permissions are reloaded from the database on every request (`rbac.signed_in_user`); `session_version` is checked each time. The requirement becomes relevant only if a cache is introduced. |
| I11 Teams and queues | **Confirmed absent** | Optional. |
| I12 Read auditing | **Partly present** | Writes are audited; export is audited. Case detail views, STR reads and searches are **not** audited. |
| I13 Admin screens | **Partly present** | Tenant: Users, Roles, Features, Security, SSO, API keys, Audit exist. Platform: Organizations, Plans, Security baseline exist. Missing: platform staff and roles screens, members/memberships, access reviews, owner-access requests, approvals, access sessions. |

---

## 6. Conflicts with the prompt and risks (need a decision before Phase 1)

**C1. Encryption is bound to one organization.** `crypto._aad(org_id, column)` binds every encrypted value to its organization. `users.email_enc` and `name_enc` use the user's `org_id` as the key context. With memberships (G1) one person has several tenants, so identity data must be encrypted **per user, not per organization** (re-encrypt under a `NULL`-organization context), while case and STR data stay per tenant. This touches `crypto.py`, `seed.py`, `rotate_keys.py` and every place that decrypts an email. It is the largest hidden cost of Phase 1.

**C2. Two-factor decisions already recorded as the user's explicit choice.** `PROJECT_MEMORY.md` records (2026-10-16 and 2026-10-17) that two-factor is optional per organization and nothing is forced by default; the most recent instruction (2026-10-23) is: sign-in is a single email+password form, two-factor for everyone except the owner login, which the code now does for non-owner platform staff and for the demo organizations only. G7 asks for **mandatory two-factor for every Tenant admin** and **passkey-only owners**. These supersede the recorded decision; I will not apply them without your confirmation.

**C3. Tenant admin holds no case permissions today; the target gives it all of them.** Today an Organization admin administers people and cannot touch cases, which is part of the separation of duties and what the platform tests rely on. The target (Sections 3.2–3.3) gives Tenant admin "every tenant permission", including `cases.decide`, `str.approve`, `screening.override`, `data.export`. Ground rules still forbid approving one's own STR and changing one's own role, and that holds, but it changes who can see and act on customer data. `_no_escalation` ("only give permissions you hold") will also stop being a meaningful limit for admins. The Section 3.3 matrix is explicit, so I will follow it; flagging so the change is deliberate.

**C4. Owner access reverses a database-level design guarantee.** Today, RLS stops platform mode from reading case data at all ("never see tenant customer data", `PROJECT_MEMORY.md`). G3 needs a path where a Platform owner acts inside a tenant. That needs a new database mechanism: a session GUC for the acting user (`app.user_id`), policies that consult `tenant_memberships` and `tenant_access_sessions`, and a rewrite of `pg.tx`. It also means the RLS predicate in Section 5/Phase 3 can no longer be "tenant = app.org_id" alone.

**C5. `*` for Platform owner cannot be stored.** `role_permissions.perm` is a foreign key to `permissions(key)`, and `check_perm_scope()` requires every permission to have a scope. Proposal: keep owner's permissions as an explicit, complete list generated from the catalogue (I7), and let the catalogue treat "owner = all platform permissions" as a rule, rather than inserting a literal `*`. Alternatively add a `*` pseudo-permission with scope `platform`. Needs your preference.

**C6. Tenant admin "locked, always holds every tenant permission".** If the catalogue adds a permission later, locked roles must be re-synchronised by a migration or a startup reconcile. Proposal: reconcile at migration time, covered by the catalogue CI check.

**C7. Role-template behaviour changes (intended, listed for the Phase 1 snapshot test).**
- Compliance analyst **loses** `screening.override` (today it has it).
- Organization admin **gains** all tenant permissions (C3).
- Platform admin is merged into Platform owner; those users gain `platform.roles.manage`, `platform.security.manage` and everything new.
- `data.export`, `policy.edit`, `screening.override`, `str.approve` become time-windowed step-up instead of "session has a second factor".

**C8. Plan features and the six-value CHECK.** `org_features.feature` is constrained to six names; Section 3.7 adds SSO, SCIM and audit streaming for Enterprise. A migration must widen the CHECK, and `plans.features` must be updated. `plans.max_users` already matches the target numbers and needs enforcement only.

**C9. There is no job runner.** G15 (dormant), G14 (reminders), G17 (scheduled deletion), I9 (anomalies) and SIEM streaming all need scheduled or asynchronous work, and there is none. This needs an architecture decision (a worker container in `docker-compose` and the AWS stack, or a scheduler thread in the API). It affects the deployment pipeline and the single-host AWS setup, so I propose settling it before Phase 7 and designing Phase 1 tables (`last_active_at`) with it in mind.

**C10. Tables without RLS hold user-linked data.** `refresh_tokens` and `recovery_codes` have no RLS. They are protected only by application code. The isolation suite (G12) should include them, and RLS on them is worth adding in Phase 3 (needs `user_id` → membership join or a GUC).

**C11. Tenant status is not part of the per-request check.** A suspended organization's already-issued access token keeps working for up to 10 minutes, and `current_user` never reads `organizations.status`. Section 3.6 step 2 will close this; it is a real behaviour change for suspended tenants.

**C12. Naming.** Rename `organizations`/`org_id`/`org_features` to `tenants`/`tenant_id`/`tenant_features`, or keep the physical names and use "tenant" only in the API, UI, docs and new tables? A physical rename touches 11 RLS policies, 7 `SECURITY DEFINER` functions, all queries and the Keycloak mapping.

**C13. Deployment constraint.** The system runs on one AWS host with one Postgres on its disk, and the owner login's data keys are not in OpenBao. Migrations must stay forward-safe on live demo data; the down-migrations required by the ground rules are not part of the current tooling (`scripts/migrate.py` is forward-only and checksummed, and `CLAUDE.md` says never edit an applied migration). Down migrations will therefore be written as paired `NNN_name.down.sql` files run by a new `migrate --down`, which is a small change to `migrate.py`.

**C14. Already-pushed related work.** Commit `37c90f1` (2026-10-23) removed the SSO button from the sign-in page and made non-owner platform staff and the demo organizations require two-factor, per your earlier instruction. Phase 2 builds on that. The `AUTH_MODE` of the AWS server is still `keycloak` and the demo users there still need re-creating; that is a deployment step, not part of this work.

## 7. Proposed adjustments to the phase plan

1. **Phase 1 gets one extra item:** move user identity encryption to a per-user context (C1), with a re-encrypt migration and test. Without it, a user cannot have two tenants.
2. **Phase 1 also adds** `migrate --down` support (C13) and the `ACCESS_MODEL_V2` flag plumbing, because both are prerequisites for the ground rules.
3. **Phase 3 absorbs** the database context change from C4 (`app.user_id` GUC, membership-aware policies) so RLS is rewritten once, not twice; Phase 5 then only adds the access-session rows.
4. **Decide the job runner (C9) before Phase 4**, because tenant deletion scheduling (G17) and invite expiry reminders need it. Phase 7 depends on it.
5. **Split Phase 6** into 6a (API keys, enforced SSO settings, mandatory 2FA/passkeys) and 6b (SAML and JIT provisioning). SAML has no code or library in the project today and is the largest single item.
6. **Phase 8 UI:** the platform staff and roles screens (K-07) are prerequisites for I13 and are not built yet.

## 8. Questions for you before Phase 1

1. **Naming:** physical rename to `tenant*`, or keep `organization*` in the database and say "tenant" at the API/UI layer? (C12; I recommend keeping the physical names.)
2. **Two-factor policy:** confirm that G7 supersedes the recorded "optional" decision for Tenant admins and platform owners (C2).
3. **Tenant admin power:** confirm that Tenant admin gets the full case permissions as in Section 3.3 (C3).
4. **Owner `*`:** explicit complete permission list generated from the catalogue, or a literal `*` pseudo-permission (C5)?
5. **Job runner:** a dedicated worker container, or a scheduler thread inside the API (C9)?
6. **Identity encryption:** approve moving user email and name to a per-user encryption context (C1), which re-encrypts existing user data.
7. **Environment:** the AWS server holds real demo data. Should the migrations be tested against a copy first and applied to the server only at Phase 9, or applied phase by phase? (I recommend applying only at cut-over.)
