-- Access model v2, phase 9: a person's role and status now live only in their memberships (tenant_memberships, platform_staff).
-- users.role_id and the trigger that copied it into the membership tables are gone. Reversible: migrations/down/018_drop_user_role_column.sql.
SELECT set_config('app.platform', 'on', true);

-- Before anything is dropped, every person must already have their place recorded in the membership tables (migration 009 backfilled it and
-- the trigger kept it in step). Refuse to continue rather than lose a role.
DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM users u
   WHERE u.org_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM tenant_memberships m WHERE m.user_id = u.id AND m.tenant_id = u.org_id);
  IF n > 0 THEN RAISE EXCEPTION '% tenant users have no membership in their home tenant; fix before migrating', n; END IF;
  SELECT count(*) INTO n FROM users u WHERE u.org_id IS NULL AND NOT EXISTS (SELECT 1 FROM platform_staff s WHERE s.user_id = u.id);
  IF n > 0 THEN RAISE EXCEPTION '% platform users have no platform_staff row; fix before migrating', n; END IF;
END $$;

DROP TRIGGER users_sync_access_model ON users;
DROP FUNCTION users_sync_access_model();

-- Is the person allowed in anywhere? Needed when one membership is suspended: the account itself is only suspended when no active place is left.
-- Runs outside any tenant scope (a tenant admin can't see the person's other memberships otherwise).
GRANT SELECT (user_id, status) ON tenant_memberships TO sentrail_auth;
GRANT SELECT (user_id, status) ON platform_staff TO sentrail_auth;
GRANT CREATE ON SCHEMA public TO sentrail_auth;
CREATE FUNCTION person_has_active_place(u uuid) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM tenant_memberships WHERE user_id = u AND status = 'active')
      OR EXISTS (SELECT 1 FROM platform_staff WHERE user_id = u AND status = 'active') $$;
ALTER FUNCTION person_has_active_place(uuid) OWNER TO sentrail_auth;

DROP FUNCTION session_user_lookup(uuid);
CREATE FUNCTION session_user_lookup(u uuid) RETURNS TABLE(status text, session_version int, mfa_enabled boolean, keycloak boolean)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT status, session_version, mfa_enabled, auth_method = 'keycloak' FROM users WHERE id = u $$;
ALTER FUNCTION session_user_lookup(uuid) OWNER TO sentrail_auth;
REVOKE CREATE ON SCHEMA public FROM sentrail_auth;
GRANT EXECUTE ON FUNCTION person_has_active_place(uuid), session_user_lookup(uuid) TO sentrail_app;

ALTER TABLE users DROP COLUMN role_id;      -- also removes the column grant given to sentrail_auth in migration 010
