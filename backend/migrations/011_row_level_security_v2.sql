-- Access model v2, phase 3: row-level security that knows WHO is acting, restricted (need-to-know) cases, a locked Platform owner role.
-- Reversible: migrations/down/011_row_level_security_v2.sql.
--
-- pg.tx(org, actor=<person>) sets app.actor. A policy then lets a row through when its tenant is the session's tenant AND the actor has an
-- active membership there (or a live owner access session). With no actor (an API key, sign-in lookups, scripts) the tenant scoping alone
-- applies, as before. Platform mode additionally needs the actor to be active platform staff (or no actor).
SELECT set_config('app.platform', 'on', true);
SELECT set_config('app.role_sync', 'on', true);

-- ---------- 1. Restricted cases ----------
ALTER TABLE alerts ADD COLUMN restricted boolean NOT NULL DEFAULT false,
                   ADD COLUMN restricted_by uuid REFERENCES users(id) ON DELETE SET NULL,
                   ADD COLUMN restricted_at timestamptz;

CREATE TABLE case_access_grants (
  org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  alert_id   text NOT NULL,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  granted_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, alert_id, user_id),
  FOREIGN KEY (org_id, alert_id) REFERENCES alerts(org_id, id) ON DELETE CASCADE
);
CREATE INDEX ON tenant_access_sessions (owner_user_id, tenant_id, status);
-- "every view of a restricted case is logged" and the once-an-hour rule for ordinary cases look events up by person and case
CREATE INDEX audit_events_case_views ON audit_events (org_id, actor_id, target, at DESC) WHERE action = 'case_viewed';

-- ---------- 2. The Platform owner role is locked in the database too ----------
UPDATE roles SET is_locked = true WHERE id = '00000000-0000-0000-0000-000000000002';

-- ---------- 3. Helper functions (owned by sentrail_auth: they read membership tables without being filtered by them) ----------
GRANT SELECT (owner_user_id, tenant_id, status, expires_at) ON tenant_access_sessions TO sentrail_auth;
GRANT SELECT (role_id, perm) ON role_permissions TO sentrail_auth;
GRANT SELECT (org_id, alert_id, user_id) ON case_access_grants TO sentrail_auth;
GRANT SELECT (id, org_id, restricted, screening_id, customer_id) ON alerts TO sentrail_auth;
GRANT CREATE ON SCHEMA public TO sentrail_auth;

CREATE FUNCTION app_actor() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.actor', true), '')::uuid $$;

CREATE FUNCTION actor_may_access(t uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app_actor() IS NULL
      OR EXISTS (SELECT 1 FROM tenant_memberships m WHERE m.user_id = app_actor() AND m.tenant_id = t AND m.status = 'active')
      OR EXISTS (SELECT 1 FROM tenant_access_sessions s WHERE s.owner_user_id = app_actor() AND s.tenant_id = t
                 AND s.status = 'active' AND s.expires_at > now()) $$;

CREATE FUNCTION actor_is_platform() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app_actor() IS NULL OR EXISTS (SELECT 1 FROM platform_staff s WHERE s.user_id = app_actor() AND s.status = 'active') $$;

-- Does the actor hold this tenant permission through an active membership? (An owner inside a live access session acts with
-- Tenant admin rights, which include every tenant permission.) No actor = a system context.
CREATE FUNCTION actor_has_perm(t uuid, p text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app_actor() IS NULL
      OR EXISTS (SELECT 1 FROM tenant_memberships m JOIN role_permissions rp ON rp.role_id = m.role_id
                 WHERE m.user_id = app_actor() AND m.tenant_id = t AND m.status = 'active' AND rp.perm = p)
      OR EXISTS (SELECT 1 FROM tenant_access_sessions s WHERE s.owner_user_id = app_actor() AND s.tenant_id = t
                 AND s.status = 'active' AND s.expires_at > now()) $$;

-- A case is visible unless it is restricted and the actor neither holds cases.restricted.view nor was named.
CREATE FUNCTION case_visible(o uuid, a text, restricted boolean) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT NOT restricted OR actor_has_perm(o, 'cases.restricted.view')
      OR EXISTS (SELECT 1 FROM case_access_grants g WHERE g.org_id = o AND g.alert_id = a AND g.user_id = app_actor()) $$;

CREATE FUNCTION alert_visible(o uuid, a text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((SELECT case_visible(o, a, x.restricted) FROM alerts x WHERE x.org_id = o AND x.id = a), true) $$;

CREATE FUNCTION screening_visible(o uuid, sid text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT NOT EXISTS (SELECT 1 FROM alerts x WHERE x.org_id = o AND x.screening_id = sid AND NOT case_visible(o, x.id, x.restricted)) $$;

-- Customer history lives outside the alert table, so searches must also skip customers whose only cases are restricted ones the actor can't see.
CREATE FUNCTION customer_hidden(o uuid, c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM alerts x WHERE x.org_id = o AND x.customer_id = c AND NOT case_visible(o, x.id, x.restricted)) $$;

ALTER FUNCTION app_actor() OWNER TO sentrail_auth;
ALTER FUNCTION customer_hidden(uuid, text) OWNER TO sentrail_auth;
ALTER FUNCTION actor_may_access(uuid) OWNER TO sentrail_auth;
ALTER FUNCTION actor_is_platform() OWNER TO sentrail_auth;
ALTER FUNCTION actor_has_perm(uuid, text) OWNER TO sentrail_auth;
ALTER FUNCTION case_visible(uuid, text, boolean) OWNER TO sentrail_auth;
ALTER FUNCTION alert_visible(uuid, text) OWNER TO sentrail_auth;
ALTER FUNCTION screening_visible(uuid, text) OWNER TO sentrail_auth;
REVOKE CREATE ON SCHEMA public FROM sentrail_auth;
GRANT EXECUTE ON FUNCTION app_actor(), actor_may_access(uuid), actor_is_platform(), actor_has_perm(uuid, text),
                         case_visible(uuid, text, boolean), alert_visible(uuid, text), screening_visible(uuid, text), customer_hidden(uuid, text) TO sentrail_app;

-- ---------- 4. Policies ----------
DO $$
DECLARE t text; platform_ok boolean; extra text; own text; pred text;
BEGIN
  FOREACH t IN ARRAY ARRAY['org_features','security_settings','roles','users','invitations','api_keys',
                           'alerts','str_drafts','screenings','screening_policy','audit_events'] LOOP
    EXECUTE format('DROP POLICY tenant_isolation ON %I', t);
    platform_ok := t IN ('org_features','security_settings','roles','users','invitations','audit_events');
    extra := CASE t WHEN 'alerts'     THEN ' AND case_visible(org_id, id, restricted)'
                    WHEN 'str_drafts' THEN ' AND alert_visible(org_id, alert_id)'
                    WHEN 'screenings' THEN ' AND screening_visible(org_id, id)' ELSE '' END;
    own   := CASE t WHEN 'users' THEN ' OR id = app_actor()' ELSE '' END;     -- a person always reaches their own row, in any tenant they belong to
    pred  := format($q$((org_id = NULLIF(current_setting('app.org_id', true), '')::uuid AND actor_may_access(org_id)%s)
                       OR (current_setting('app.platform', true) = 'on' AND %L::boolean AND actor_is_platform())%s)$q$, extra, platform_ok, own);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING %s WITH CHECK %s', t, pred, pred);
  END LOOP;

  FOREACH t IN ARRAY ARRAY['tenant_memberships','tenant_access_sessions'] LOOP
    EXECUTE format('DROP POLICY tenant_isolation ON %I', t);
    pred := $q$((tenant_id = NULLIF(current_setting('app.org_id', true), '')::uuid AND actor_may_access(tenant_id))
                OR (current_setting('app.platform', true) = 'on' AND actor_is_platform()))$q$;
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING %s WITH CHECK %s', t, pred, pred);
  END LOOP;

  FOREACH t IN ARRAY ARRAY['platform_staff','platform_approvals'] LOOP
    EXECUTE format('DROP POLICY platform_only ON %I', t);
    pred := $q$(current_setting('app.platform', true) = 'on' AND actor_is_platform())$q$;
    EXECUTE format('CREATE POLICY platform_only ON %I USING %s WITH CHECK %s', t, pred, pred);
  END LOOP;
END $$;

DROP POLICY org_self ON organizations;
CREATE POLICY org_self ON organizations
  USING ((id = NULLIF(current_setting('app.org_id', true), '')::uuid AND actor_may_access(id))
         OR (current_setting('app.platform', true) = 'on' AND actor_is_platform()))
  WITH CHECK ((id = NULLIF(current_setting('app.org_id', true), '')::uuid AND actor_may_access(id))
              OR (current_setting('app.platform', true) = 'on' AND actor_is_platform()));

-- Named-user grants for restricted cases
ALTER TABLE case_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE case_access_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON case_access_grants
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid AND actor_may_access(org_id))
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid AND actor_may_access(org_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON case_access_grants TO sentrail_app;
