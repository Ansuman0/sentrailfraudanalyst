-- Access model v2, phase 2: a session belongs to one active tenant, remembers its last two-factor check, and devices are known per user.
SELECT set_config('app.platform', 'on', true);

-- The session (refresh-token family) carries the active tenant and when the user last proved a second factor (step-up).
-- scope: 'tenant' (inside one tenant), 'platform' (the console), 'select' (signed in, tenant not chosen yet: only /me, /me/tenants, /session/*).
ALTER TABLE refresh_tokens
  ADD COLUMN last_mfa_at timestamptz,
  ADD COLUMN tenant_id   uuid,
  ADD COLUMN scope       text NOT NULL DEFAULT 'tenant' CHECK (scope IN ('tenant','platform','select'));
UPDATE refresh_tokens t SET tenant_id = u.org_id, scope = CASE WHEN u.org_id IS NULL THEN 'platform' ELSE 'tenant' END
  FROM users u WHERE u.id = t.user_id;
UPDATE refresh_tokens SET last_mfa_at = created_at WHERE auth_method IS DISTINCT FROM 'password';

-- rbac checks on every request that the session behind an access token is still live (sign-out and tenant switch end it at once).
CREATE INDEX refresh_tokens_family_live ON refresh_tokens (family_id) WHERE revoked_at IS NULL;

-- Devices a person has signed in from (new-device notification). Only a hash of a random device cookie is stored.
CREATE TABLE user_devices (
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_hash bytea NOT NULL,
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  ip          inet,
  user_agent  text,
  PRIMARY KEY (user_id, device_hash)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON user_devices TO sentrail_app;

-- Lookups that run when the tenant is not known yet (sign-in, tenant picker). Owned by sentrail_auth (BYPASSRLS), narrow column grants.
GRANT SELECT (user_id, tenant_id, role_id, status) ON tenant_memberships TO sentrail_auth;
GRANT SELECT (user_id, role_id, status) ON platform_staff TO sentrail_auth;
GRANT SELECT (id, name) ON roles TO sentrail_auth;
GRANT SELECT (id, legal_name, slug, status, environment, brand_color) ON organizations TO sentrail_auth;
GRANT SELECT (id, status, session_version, role_id, mfa_enabled, auth_method) ON users TO sentrail_auth;
GRANT CREATE ON SCHEMA public TO sentrail_auth;

CREATE FUNCTION membership_lookup(u uuid) RETURNS TABLE(tenant_id uuid, tenant_name text, slug text, tenant_status text,
                                                       role_id uuid, role_name text, status text)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT m.tenant_id, o.legal_name, o.slug, o.status, m.role_id, r.name, m.status
  FROM tenant_memberships m JOIN organizations o ON o.id = m.tenant_id JOIN roles r ON r.id = m.role_id
  WHERE m.user_id = u ORDER BY o.legal_name $$;
CREATE FUNCTION platform_staff_lookup(u uuid) RETURNS TABLE(role_id uuid, role_name text, status text)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT s.role_id, r.name, s.status FROM platform_staff s JOIN roles r ON r.id = s.role_id WHERE s.user_id = u $$;
-- The signed-in user's own state for every request. A person with memberships in several tenants has one users row tied to one
-- organization (until phase 3 reworks row-level security), so this must not depend on the tenant context.
CREATE FUNCTION session_user_lookup(u uuid) RETURNS TABLE(status text, session_version int, role_id uuid, mfa_enabled boolean, keycloak boolean)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT status, session_version, role_id, mfa_enabled, auth_method = 'keycloak' FROM users WHERE id = u $$;
ALTER FUNCTION session_user_lookup(uuid) OWNER TO sentrail_auth;
ALTER FUNCTION membership_lookup(uuid) OWNER TO sentrail_auth;
ALTER FUNCTION platform_staff_lookup(uuid) OWNER TO sentrail_auth;
REVOKE CREATE ON SCHEMA public FROM sentrail_auth;
GRANT EXECUTE ON FUNCTION membership_lookup(uuid), platform_staff_lookup(uuid), session_user_lookup(uuid) TO sentrail_app;
