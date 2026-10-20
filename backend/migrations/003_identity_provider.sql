-- Keycloak (OIDC) sign-in, tenant display and session management.

ALTER TABLE organizations
  ADD COLUMN slug         text UNIQUE,
  ADD COLUMN environment  text NOT NULL DEFAULT 'production' CHECK (environment IN ('production','sandbox')),
  ADD COLUMN brand_color  text NOT NULL DEFAULT '#0F6E56' CHECK (brand_color ~ '^#[0-9A-Fa-f]{6}$'),
  ADD COLUMN sso_domain   citext UNIQUE,          -- verified email domain, e.g. northwindremit.ca
  ADD COLUMN sso_idp_alias text,                  -- Keycloak identity provider alias for that domain
  ADD COLUMN sso_enforced boolean NOT NULL DEFAULT false,
  ADD COLUMN sso_domain_pending citext,           -- set by the org admin, moves to sso_domain once DNS proves ownership
  ADD COLUMN domain_verify_token text;            -- value for the DNS TXT record

ALTER TABLE users
  ADD COLUMN idp_subject  text UNIQUE,            -- Keycloak "sub"; links the identity to this user
  ADD COLUMN auth_method  text NOT NULL DEFAULT 'local' CHECK (auth_method IN ('local','keycloak'));

-- Short-lived OIDC login state (state, nonce, PKCE verifier). No personal data. Not tenant-scoped.
CREATE TABLE oidc_login_states (
  state_hash    bytea PRIMARY KEY,
  nonce         text NOT NULL,
  code_verifier text NOT NULL,
  return_to     text NOT NULL DEFAULT '/',
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL DEFAULT now() + interval '10 minutes'
);
CREATE INDEX ON oidc_login_states (expires_at);

-- Sessions shown on "Where you're signed in"
ALTER TABLE refresh_tokens
  ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN auth_method text;

-- Login-time lookups that run before the tenant is known
CREATE FUNCTION idp_lookup(sub text) RETURNS TABLE(id uuid, org_id uuid) LANGUAGE sql SECURITY DEFINER
  SET search_path = public AS $$ SELECT id, org_id FROM users WHERE idp_subject = sub $$;
CREATE FUNCTION sso_domain_lookup(d text) RETURNS TABLE(org_id uuid, idp_alias text, enforced boolean)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS
  $$ SELECT id, sso_idp_alias, sso_enforced FROM organizations WHERE sso_domain = d::citext AND status IN ('active','trial') $$;
CREATE FUNCTION org_display(o uuid) RETURNS TABLE(legal_name text, slug text, environment text, brand_color text)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS
  $$ SELECT legal_name, slug, environment, brand_color FROM organizations WHERE id = o $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON oidc_login_states TO sentrail_app;
GRANT EXECUTE ON FUNCTION idp_lookup(text), sso_domain_lookup(text), org_display(uuid) TO sentrail_app;

-- An organization can read and update only its own row; platform staff can manage all.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY org_self ON organizations
  USING (id = NULLIF(current_setting('app.org_id', true), '')::uuid OR current_setting('app.platform', true) = 'on')
  WITH CHECK (id = NULLIF(current_setting('app.org_id', true), '')::uuid OR current_setting('app.platform', true) = 'on');
