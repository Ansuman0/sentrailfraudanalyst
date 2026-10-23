-- Access model v2, phase 6: API key controls, passkeys (WebAuthn), company sign-in enforcement. Reversible: migrations/down/014_authentication_enforcement.sql.
SELECT set_config('app.platform', 'on', true);

-- ---------- API keys (G10): expiry, IP allowlist, last use, rotation overlap, per-key rate limit ----------
ALTER TABLE api_keys
  ADD COLUMN expires_at         timestamptz,                                   -- optional; rotation sets it 24 h ahead on the old key
  ADD COLUMN ip_allowlist       cidr[] NOT NULL DEFAULT '{}',                 -- empty = any address
  ADD COLUMN last_used_at       timestamptz,
  ADD COLUMN rate_limit_per_min int NOT NULL DEFAULT 600 CHECK (rate_limit_per_min BETWEEN 1 AND 6000),
  ADD COLUMN rotated_at         timestamptz,
  ADD COLUMN replaced_by        text;
GRANT SELECT (expires_at, ip_allowlist, rate_limit_per_min) ON api_keys TO sentrail_auth;
GRANT CREATE ON SCHEMA public TO sentrail_auth;
DROP FUNCTION api_key_lookup(text);
CREATE FUNCTION api_key_lookup(p text) RETURNS TABLE(org_id uuid, key_hash bytea, scopes text[], expires_at timestamptz, ip_allowlist cidr[], rate_limit_per_min int)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, key_hash, scopes, expires_at, ip_allowlist, rate_limit_per_min FROM api_keys WHERE prefix = p AND revoked_at IS NULL $$;
ALTER FUNCTION api_key_lookup(text) OWNER TO sentrail_auth;
REVOKE CREATE ON SCHEMA public FROM sentrail_auth;
GRANT EXECUTE ON FUNCTION api_key_lookup(text) TO sentrail_app;

-- ---------- Passkeys (G7): owners must use them; anyone may register them ----------
CREATE TABLE user_passkeys (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id bytea NOT NULL UNIQUE,
  public_key    bytea NOT NULL,
  sign_count    bigint NOT NULL DEFAULT 0,
  name          text NOT NULL,
  transports    text[] NOT NULL DEFAULT '{}',
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz
);
CREATE INDEX ON user_passkeys (user_id);
CREATE TABLE webauthn_challenges (                      -- one-time challenges, five minutes
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose    text NOT NULL CHECK (purpose IN ('register', 'login', 'step_up')),
  challenge  bytea NOT NULL,
  expires_at timestamptz NOT NULL DEFAULT now() + interval '5 minutes'
);
CREATE INDEX ON webauthn_challenges (user_id, purpose);
GRANT SELECT, INSERT, UPDATE, DELETE ON user_passkeys, webauthn_challenges TO sentrail_app;

-- Owners without a passkey are limited to registering one once the platform requires it. Off until the owners have enrolled.
ALTER TABLE platform_settings ALTER COLUMN platform_staff_passkey_only SET DEFAULT false;
UPDATE platform_settings SET platform_staff_passkey_only = false;

-- ---------- Company sign-in (G6) ----------
ALTER TABLE users ADD COLUMN sso_emergency boolean NOT NULL DEFAULT false;    -- the one password login that still works when SSO is enforced
CREATE UNIQUE INDEX one_sso_emergency_per_tenant ON users (org_id) WHERE sso_emergency;
ALTER TABLE organizations
  ADD COLUMN sso_default_role_id uuid REFERENCES roles(id),                   -- role of people created on their first company sign-in
  ADD COLUMN sso_protocol text NOT NULL DEFAULT 'oidc' CHECK (sso_protocol IN ('oidc', 'saml'));   -- how the company's identity provider talks to Keycloak
GRANT SELECT (sso_default_role_id, sso_protocol) ON organizations TO sentrail_auth;
GRANT CREATE ON SCHEMA public TO sentrail_auth;
-- the organization (and role) a verified company domain provisions new people into on their first company sign-in
CREATE FUNCTION sso_jit_lookup(d text) RETURNS TABLE(org_id uuid, role_id uuid)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, sso_default_role_id FROM organizations
  WHERE sso_domain = d::citext AND status IN ('active','trial') AND sso_idp_alias IS NOT NULL AND sso_default_role_id IS NOT NULL $$;
ALTER FUNCTION sso_jit_lookup(text) OWNER TO sentrail_auth;
REVOKE CREATE ON SCHEMA public FROM sentrail_auth;
GRANT EXECUTE ON FUNCTION sso_jit_lookup(text) TO sentrail_app;

-- These two were stored and never used: the company's identity provider is configured in Keycloak (OIDC or SAML), not here.
-- and "company sign-in is on" is simply a verified domain with an identity provider alias: one source of truth, not a second switch.
ALTER TABLE security_settings DROP COLUMN oidc_issuer, DROP COLUMN oidc_client_id, DROP COLUMN sso_enabled;
