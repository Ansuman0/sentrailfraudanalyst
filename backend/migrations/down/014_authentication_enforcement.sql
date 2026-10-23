-- Reverts 014_authentication_enforcement.sql. Registered passkeys and API key controls are lost.
SELECT set_config('app.platform', 'on', true);
ALTER TABLE security_settings ADD COLUMN oidc_issuer text, ADD COLUMN oidc_client_id text, ADD COLUMN sso_enabled boolean NOT NULL DEFAULT false;
DROP FUNCTION sso_jit_lookup(text);
ALTER TABLE organizations DROP COLUMN sso_default_role_id, DROP COLUMN sso_protocol;
DROP INDEX one_sso_emergency_per_tenant;
ALTER TABLE users DROP COLUMN sso_emergency;
ALTER TABLE platform_settings ALTER COLUMN platform_staff_passkey_only SET DEFAULT true;
DROP TABLE webauthn_challenges, user_passkeys;
GRANT CREATE ON SCHEMA public TO sentrail_auth;
DROP FUNCTION api_key_lookup(text);
CREATE FUNCTION api_key_lookup(p text) RETURNS TABLE(org_id uuid, key_hash bytea, scopes text[])
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$ SELECT org_id, key_hash, scopes FROM api_keys WHERE prefix = p AND revoked_at IS NULL $$;
ALTER FUNCTION api_key_lookup(text) OWNER TO sentrail_auth;
REVOKE CREATE ON SCHEMA public FROM sentrail_auth;
GRANT EXECUTE ON FUNCTION api_key_lookup(text) TO sentrail_app;
REVOKE SELECT (expires_at, ip_allowlist, rate_limit_per_min) ON api_keys FROM sentrail_auth;
ALTER TABLE api_keys DROP COLUMN expires_at, DROP COLUMN ip_allowlist, DROP COLUMN last_used_at, DROP COLUMN rate_limit_per_min,
  DROP COLUMN rotated_at, DROP COLUMN replaced_by;
