# Producing access evidence (SOC 2 and similar audits)

What an auditor asks for about *who can reach what*, and how to produce it from Sentrail without a database query. Everything below is
available to a **Tenant admin** (or a role holding the permission named) in a tenant, and to **Platform owners** for the platform's own staff.
Every action that produces evidence is itself audited (who asked, when), and every file carries a watermark (who took it out, which tenant, when).

| Auditor asks for | Produce it | Permission |
|---|---|---|
| The current list of people with access, their roles and status | `GET /admin/users` (screen: Users), or the `members` section of the full data export | `users.manage` / `data.export` |
| What each role can do | `GET /admin/roles`; `docs/permissions.md` is the matrix for the software version in use | `roles.manage` |
| Proof that access is reviewed regularly | `GET /admin/access-reviews` (each review: opened, due, signed off by whom and when) and `GET /admin/access-reviews/{id}` (every person with the decision, note and time) | `access.review` |
| Evidence that removals were carried out | the audit events `access_review_remove`, `access_review_change`, `membership_dormant_suspended`, `scim_user_deprovisioned`, `user_suspended` (and `user_active` when restored) in the audit export | `audit.export` |
| Joiner / mover / leaver trail | audit events `user_invited`, `user_enrolled`, `role_changed`, `scim_user_created`, `scim_role_assigned`, `scim_user_deprovisioned`, `sso_jit_provisioned` | `audit.export` |
| Authentication settings in force | `GET /admin/security` (two-factor, idle timeout, password length, IP allowlist, retention, dormant period, review cycle, export limits, anomaly thresholds), `GET /admin/sso` (company sign-in) | `security.manage` |
| Changes to those settings | audit events `security_settings_changed` (before and after), `sso_configured`, `owner_access_setting_changed` | `audit.export` |
| Privileged access by the vendor (Sentrail staff) | audit events `owner_access_requested`, `owner_access_started`, `owner_access_ended`, and every action they took (tagged `access_session_id`) in your own log | `audit.view` |
| Unusual activity | audit events `anomaly_alert` (volume of searches or exports, sign-in from a new country) | `audit.export` |
| Who exported data | audit events `case_exported`, `audit_exported`, `data_exported`, `export_downloaded`; exports carry a watermark naming the person | `audit.export` |
| Log integrity | the signed audit export (below), or `GET /admin/audit/verify` | `audit.export` / `audit.view` |
| Offboarding and deletion | `POST /admin/data-export` (your data, before you leave); after deletion the platform keeps a `tenant_data_removed` record (what was removed, and the final hash of your audit chain). Ask your Sentrail contact for that record | `data.export` |

## The signed audit export

`POST /admin/audit/export {"format": "json" | "csv", "since": ..., "until": ...}` returns a one-time download link (15 minutes, fetched by you,
while signed in, once). The file contains:

* **watermark**: who exported, from which tenant, when;
* **chain**: whether the *whole* audit chain verified at the time, how many events it holds, and the hash of its latest event;
* **events**: each with its time, actor, role, action, target, detail, address, and the hashes that link it to the event before it;
* **signature**: an HMAC-SHA256 over the file, made with a key only Sentrail holds, so a file that was altered after export fails Sentrail's check.

### Checking it yourself

The audit log is a hash chain: each event's hash is `SHA-256(previous hash || canonical JSON of the event)`, so editing, removing or reordering any
event breaks every hash after it. You can verify a JSON export without any Sentrail key:

```
python scripts/verify_audit_export.py audit-20261023T101500Z.json
```

It prints `INTACT` or lists the events that do not match. To prove the file is the one Sentrail issued, send it to Sentrail: the signature check
(`app.governance.verify_export`) needs the platform's key.

A CSV export carries the same watermark and chain result in its first lines and `# signature=HMAC-SHA256:...` as its last line.

## Streaming to your SIEM (Enterprise)

`PUT /admin/audit/stream {"url": "https://..."}` sends new events to your endpoint within about five minutes, in order, at least once. Every
delivery carries `X-Sentrail-Timestamp` and `X-Sentrail-Signature: sha256=HMAC(secret, timestamp + "." + body)`; the secret is shown once when you
first set the stream up. Only `https` addresses outside private networks are accepted. After 50 failed deliveries in a row the stream switches
itself off and your administrators are told.

## Retention

The audit log is append-only; nothing deletes it while the tenant exists. A deleted tenant's data (and its log) is removed only after its
retention period (`retention_years`, at least the platform minimum of 5 years, configurable upward under Security) has passed. The removal is
recorded in the platform log.

## Mapping to SOC 2 criteria (informal guide, not an attestation)

| Criterion | Where to look |
|---|---|
| CC6.1 logical access controls | roles and permission matrix (`docs/permissions.md`), per-tenant isolation (row-level security), `GET /admin/users` |
| CC6.2 provisioning and removal | invitations, SCIM audit events, access reviews, dormant suspensions |
| CC6.3 role-based access, least privilege | `docs/permissions.md`, `docs/route-permissions.md`, restricted cases, access review decisions |
| CC6.6 / CC6.7 authentication and data movement | `GET /admin/security`, single sign-on and passkeys settings, export controls (watermark, single-use links, hourly limits) |
| CC7.2 monitoring | audit export or SIEM stream, `anomaly_alert` events |
| CC7.3 / CC7.4 incident response | break-glass and owner-access events, `docs/IDENTITY.md` runbook |
