-- Sign-in lookups run before the tenant is known, so they must see across tenants.
-- They're owned by sentrail_auth (BYPASSRLS, no login), which can read only these columns.
GRANT USAGE ON SCHEMA public TO sentrail_auth;
GRANT CREATE ON SCHEMA public TO sentrail_auth;        -- needed only to take ownership; revoked below
GRANT SELECT (id, org_id, email_bidx, idp_subject) ON users TO sentrail_auth;
GRANT SELECT (id, org_id, user_id, token_hash, expires_at, accepted_at) ON invitations TO sentrail_auth;
GRANT SELECT (org_id, prefix, key_hash, scopes, revoked_at) ON api_keys TO sentrail_auth;
GRANT SELECT (id, legal_name, slug, environment, brand_color, sso_domain, sso_idp_alias, sso_enforced, status)
  ON organizations TO sentrail_auth;

ALTER FUNCTION auth_lookup(bytea)        OWNER TO sentrail_auth;
ALTER FUNCTION invitation_lookup(bytea)  OWNER TO sentrail_auth;
ALTER FUNCTION api_key_lookup(text)      OWNER TO sentrail_auth;
ALTER FUNCTION user_org_lookup(uuid)     OWNER TO sentrail_auth;
ALTER FUNCTION idp_lookup(text)          OWNER TO sentrail_auth;
ALTER FUNCTION sso_domain_lookup(text)   OWNER TO sentrail_auth;
ALTER FUNCTION org_display(uuid)         OWNER TO sentrail_auth;

REVOKE CREATE ON SCHEMA public FROM sentrail_auth;
