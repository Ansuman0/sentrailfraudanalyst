# Table reference

Generated from the database by `backend/scripts/schema_doc.py`. RLS = row-level security on.

## alerts  (RLS)

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | text | no |  |
| `org_id` | uuid | no |  |
| `customer_id` | text | no |  |
| `score` | integer | no |  |
| `band` | text | no |  |
| `reasons` | jsonb | no |  |
| `channel` | text | yes |  |
| `status` | text | no | 'open'::text |
| `assigned_to` | uuid | yes |  |
| `created_at` | timestamp with time zone | no | now() |
| `screening_id` | text | yes |  |

## api_keys  (RLS)

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | uuid | no | gen_random_uuid() |
| `org_id` | uuid | no |  |
| `prefix` | text | no |  |
| `key_hash` | bytea | no |  |
| `scopes` | ARRAY | no | '{screen}'::text[] |
| `created_by` | uuid | yes |  |
| `revoked_at` | timestamp with time zone | yes |  |
| `label` | text | yes |  |
| `created_at` | timestamp with time zone | no | now() |

## audit_events  (RLS)

| Column | Type | Null | Default |
|---|---|---|---|
| `seq` | bigint | no | nextval('audit_events_seq_seq'::regclass) |
| `org_id` | uuid | yes |  |
| `at` | timestamp with time zone | no | now() |
| `actor_id` | uuid | yes |  |
| `actor_role` | text | yes |  |
| `action` | text | no |  |
| `target` | text | yes |  |
| `detail` | jsonb | no | '{}'::jsonb |
| `ip` | inet | yes |  |
| `prev_hash` | bytea | no |  |
| `hash` | bytea | no |  |

## invitations  (RLS)

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | uuid | no | gen_random_uuid() |
| `org_id` | uuid | yes |  |
| `user_id` | uuid | no |  |
| `token_hash` | bytea | no |  |
| `invited_by` | uuid | yes |  |
| `expires_at` | timestamp with time zone | no |  |
| `accepted_at` | timestamp with time zone | yes |  |

## login_throttle

| Column | Type | Null | Default |
|---|---|---|---|
| `key_hash` | bytea | no |  |
| `ip` | text | no | ''::text |
| `failed` | integer | no | 0 |
| `locked_until` | timestamp with time zone | yes |  |
| `updated_at` | timestamp with time zone | no | now() |

## oidc_login_states

| Column | Type | Null | Default |
|---|---|---|---|
| `state_hash` | bytea | no |  |
| `nonce` | text | no |  |
| `code_verifier` | text | no |  |
| `return_to` | text | no | '/'::text |
| `created_at` | timestamp with time zone | no | now() |
| `expires_at` | timestamp with time zone | no | (now() + '00:10:00'::interval) |

## org_features  (RLS)

| Column | Type | Null | Default |
|---|---|---|---|
| `org_id` | uuid | no |  |
| `feature` | text | no |  |
| `in_plan` | boolean | no | true |
| `enabled` | boolean | no | true |

## organizations  (RLS)

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | uuid | no | gen_random_uuid() |
| `legal_name` | text | no |  |
| `business_type` | text | no |  |
| `registration` | text | no |  |
| `data_region` | text | no | 'ca-central'::text |
| `plan` | text | no | 'professional'::text |
| `status` | text | no | 'pending'::text |
| `created_at` | timestamp with time zone | no | now() |
| `slug` | text | yes |  |
| `environment` | text | no | 'production'::text |
| `brand_color` | text | no | '#0F6E56'::text |
| `sso_domain` | USER-DEFINED | yes |  |
| `sso_idp_alias` | text | yes |  |
| `sso_enforced` | boolean | no | false |
| `sso_domain_pending` | USER-DEFINED | yes |  |
| `domain_verify_token` | text | yes |  |

## permissions

| Column | Type | Null | Default |
|---|---|---|---|
| `key` | text | no |  |
| `description` | text | no |  |
| `scope` | text | no | 'tenant'::text |
| `grp` | text | no | 'General'::text |

## plans

| Column | Type | Null | Default |
|---|---|---|---|
| `key` | text | no |  |
| `name` | text | no |  |
| `features` | ARRAY | no |  |
| `max_users` | integer | yes |  |
| `sort` | integer | no |  |

## platform_settings

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | boolean | no | true |
| `min_password_len_floor` | integer | no | 14 |
| `max_idle_timeout_min` | integer | no | 30 |
| `max_session_hours` | integer | no | 12 |
| `retention_years_floor` | integer | no | 5 |
| `passkeys_allowed` | boolean | no | true |
| `platform_staff_passkey_only` | boolean | no | true |
| `allowed_regions` | ARRAY | no | '{ca-central,ca-east}'::text[] |
| `updated_at` | timestamp with time zone | no | now() |

## recovery_codes

| Column | Type | Null | Default |
|---|---|---|---|
| `user_id` | uuid | yes |  |
| `code_hash` | text | no |  |
| `used_at` | timestamp with time zone | yes |  |

## refresh_tokens

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | uuid | no | gen_random_uuid() |
| `user_id` | uuid | no |  |
| `family_id` | uuid | no |  |
| `token_hash` | bytea | no |  |
| `expires_at` | timestamp with time zone | no |  |
| `revoked_at` | timestamp with time zone | yes |  |
| `user_agent` | text | yes |  |
| `ip` | inet | yes |  |
| `created_at` | timestamp with time zone | no | now() |
| `auth_method` | text | yes |  |

## role_permissions

| Column | Type | Null | Default |
|---|---|---|---|
| `role_id` | uuid | no |  |
| `perm` | text | no |  |

## role_template_permissions

| Column | Type | Null | Default |
|---|---|---|---|
| `template` | text | no |  |
| `perm` | text | no |  |

## role_templates

| Column | Type | Null | Default |
|---|---|---|---|
| `name` | text | no |  |
| `scope` | text | no |  |
| `description` | text | no |  |
| `sort` | integer | no |  |

## roles  (RLS)

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | uuid | no | gen_random_uuid() |
| `org_id` | uuid | yes |  |
| `name` | text | no |  |
| `is_system` | boolean | no | false |

## schema_migrations

| Column | Type | Null | Default |
|---|---|---|---|
| `version` | text | no |  |
| `checksum` | text | no |  |
| `applied_at` | timestamp with time zone | no | now() |

## screening_policy  (RLS)

| Column | Type | Null | Default |
|---|---|---|---|
| `org_id` | uuid | no |  |
| `policy` | jsonb | no |  |

## screenings  (RLS)

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | text | no |  |
| `org_id` | uuid | no |  |
| `customer_id` | text | no |  |
| `direction` | text | no |  |
| `address` | text | no |  |
| `amount` | numeric | no |  |
| `score` | integer | no |  |
| `decision` | text | no |  |
| `reasons` | jsonb | no |  |
| `override` | text | yes |  |
| `override_by` | uuid | yes |  |
| `created_at` | timestamp with time zone | no | now() |
| `client_ref` | text | yes |  |
| `asset` | text | yes |  |
| `fiat_value` | numeric | yes |  |
| `result` | jsonb | yes |  |
| `override_reason` | text | yes |  |
| `override_at` | timestamp with time zone | yes |  |

## security_settings  (RLS)

| Column | Type | Null | Default |
|---|---|---|---|
| `org_id` | uuid | no |  |
| `mfa_required` | boolean | no | true |
| `sso_enabled` | boolean | no | false |
| `oidc_issuer` | text | yes |  |
| `oidc_client_id` | text | yes |  |
| `idle_timeout_min` | integer | no | 15 |
| `min_password_len` | integer | no | 14 |
| `ip_allowlist` | ARRAY | no | '{}'::cidr[] |
| `retention_years` | integer | no | 5 |

## str_drafts  (RLS)

| Column | Type | Null | Default |
|---|---|---|---|
| `org_id` | uuid | no |  |
| `alert_id` | text | no |  |
| `ai_draft_enc` | text | yes |  |
| `final_enc` | text | yes |  |
| `drafted_by` | uuid | yes |  |
| `approved_by` | uuid | yes |  |
| `status` | text | no | 'draft'::text |
| `updated_at` | timestamp with time zone | no | now() |

## users  (RLS)

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | uuid | no | gen_random_uuid() |
| `org_id` | uuid | yes |  |
| `role_id` | uuid | no |  |
| `email_enc` | text | no |  |
| `email_bidx` | bytea | no |  |
| `name_enc` | text | yes |  |
| `phone_enc` | text | yes |  |
| `password_hash` | text | yes |  |
| `totp_secret_enc` | text | yes |  |
| `totp_last_step` | bigint | no | 0 |
| `status` | text | no | 'invited'::text |
| `failed_logins` | integer | no | 0 |
| `locked_until` | timestamp with time zone | yes |  |
| `session_version` | integer | no | 1 |
| `last_login_at` | timestamp with time zone | yes |  |
| `created_at` | timestamp with time zone | no | now() |
| `idp_subject` | text | yes |  |
| `auth_method` | text | no | 'local'::text |

