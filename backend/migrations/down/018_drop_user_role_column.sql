-- Reverts 018_drop_user_role_column.sql: users.role_id comes back (filled from the memberships) and the sync trigger with it.
SELECT set_config('app.platform', 'on', true);

ALTER TABLE users ADD COLUMN role_id uuid REFERENCES roles(id);
UPDATE users u SET role_id = s.role_id FROM platform_staff s WHERE s.user_id = u.id AND u.org_id IS NULL;
UPDATE users u SET role_id = m.role_id FROM tenant_memberships m WHERE m.user_id = u.id AND m.tenant_id = u.org_id AND u.org_id IS NOT NULL;
-- (anyone without a place keeps NULL: the old schema required a role, so the NOT NULL is not restored)

DROP FUNCTION session_user_lookup(uuid);
GRANT CREATE ON SCHEMA public TO sentrail_auth;
GRANT SELECT (role_id) ON users TO sentrail_auth;
CREATE FUNCTION session_user_lookup(u uuid) RETURNS TABLE(status text, session_version int, role_id uuid, mfa_enabled boolean, keycloak boolean)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT status, session_version, role_id, mfa_enabled, auth_method = 'keycloak' FROM users WHERE id = u $$;
ALTER FUNCTION session_user_lookup(uuid) OWNER TO sentrail_auth;
DROP FUNCTION person_has_active_place(uuid);
REVOKE CREATE ON SCHEMA public FROM sentrail_auth;
GRANT EXECUTE ON FUNCTION session_user_lookup(uuid) TO sentrail_app;

-- While the old model is still live (users.org_id / users.role_id, until the cut-over), every change to a user keeps the new tables in step.
CREATE FUNCTION users_sync_access_model() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.org_id IS NULL THEN
    IF TG_OP = 'INSERT' THEN
      INSERT INTO platform_staff (user_id, role_id, status) VALUES (NEW.id, NEW.role_id, NEW.status)
        ON CONFLICT (user_id) DO NOTHING;
    ELSIF NEW.role_id IS DISTINCT FROM OLD.role_id OR NEW.status IS DISTINCT FROM OLD.status THEN
      INSERT INTO platform_staff (user_id, role_id, status) VALUES (NEW.id, NEW.role_id, NEW.status)
        ON CONFLICT (user_id) DO UPDATE SET role_id = EXCLUDED.role_id, status = EXCLUDED.status;
    END IF;
  ELSIF TG_OP = 'INSERT' OR NEW.org_id IS DISTINCT FROM OLD.org_id THEN
    INSERT INTO tenant_memberships (user_id, tenant_id, role_id, status, last_active_at)
      VALUES (NEW.id, NEW.org_id, NEW.role_id, NEW.status, NEW.last_login_at)
      ON CONFLICT (user_id, tenant_id) DO NOTHING;
  ELSIF NEW.role_id IS DISTINCT FROM OLD.role_id OR NEW.status IS DISTINCT FROM OLD.status THEN
    -- A real change of role or status in the old model is copied over (and a missing membership is created).
    INSERT INTO tenant_memberships (user_id, tenant_id, role_id, status, last_active_at)
      VALUES (NEW.id, NEW.org_id, NEW.role_id, NEW.status, NEW.last_login_at)
      ON CONFLICT (user_id, tenant_id) DO UPDATE SET role_id = EXCLUDED.role_id, status = EXCLUDED.status,
                                                     last_active_at = EXCLUDED.last_active_at;
  ELSE
    -- Anything else (a login updates last_login_at) only touches the activity time of a membership that exists. It must never
    -- change or re-create a membership: memberships are edited and removed directly in the new model.
    UPDATE tenant_memberships SET last_active_at = NEW.last_login_at WHERE user_id = NEW.id AND tenant_id = NEW.org_id;
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER users_sync_access_model AFTER INSERT OR UPDATE OF org_id, role_id, status, last_login_at ON users
  FOR EACH ROW EXECUTE FUNCTION users_sync_access_model();
