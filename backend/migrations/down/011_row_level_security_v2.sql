-- Reverts 011_row_level_security_v2.sql: policies go back to "tenant = app.org_id" (plus platform mode), restricted cases and the helper functions go.
-- Cases that were marked restricted become ordinary cases again.
SELECT set_config('app.platform', 'on', true);
SELECT set_config('app.role_sync', 'on', true);

DO $$
DECLARE t text; platform_ok boolean; pred text;
BEGIN
  FOREACH t IN ARRAY ARRAY['org_features','security_settings','roles','users','invitations','api_keys',
                           'alerts','str_drafts','screenings','screening_policy','audit_events'] LOOP
    EXECUTE format('DROP POLICY tenant_isolation ON %I', t);
    platform_ok := t IN ('org_features','security_settings','roles','users','invitations','audit_events');
    pred := format($q$(org_id = NULLIF(current_setting('app.org_id', true), '')::uuid
                       OR (current_setting('app.platform', true) = 'on' AND %L::boolean))$q$, platform_ok);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING %s WITH CHECK %s', t, pred, pred);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['tenant_memberships','tenant_access_sessions'] LOOP
    EXECUTE format('DROP POLICY tenant_isolation ON %I', t);
    pred := $q$(tenant_id = NULLIF(current_setting('app.org_id', true), '')::uuid OR current_setting('app.platform', true) = 'on')$q$;
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING %s WITH CHECK %s', t, pred, pred);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['platform_staff','platform_approvals'] LOOP
    EXECUTE format('DROP POLICY platform_only ON %I', t);
    pred := $q$(current_setting('app.platform', true) = 'on')$q$;
    EXECUTE format('CREATE POLICY platform_only ON %I USING %s WITH CHECK %s', t, pred, pred);
  END LOOP;
END $$;

DROP POLICY org_self ON organizations;
CREATE POLICY org_self ON organizations
  USING (id = NULLIF(current_setting('app.org_id', true), '')::uuid OR current_setting('app.platform', true) = 'on')
  WITH CHECK (id = NULLIF(current_setting('app.org_id', true), '')::uuid OR current_setting('app.platform', true) = 'on');

DROP TABLE case_access_grants;      -- its policy uses actor_may_access, so it goes before the functions
DROP FUNCTION customer_hidden(uuid, text);
DROP FUNCTION screening_visible(uuid, text);
DROP FUNCTION alert_visible(uuid, text);
DROP FUNCTION case_visible(uuid, text, boolean);
DROP FUNCTION actor_has_perm(uuid, text);
DROP FUNCTION actor_is_platform();
DROP FUNCTION actor_may_access(uuid);
DROP FUNCTION app_actor();
REVOKE SELECT (owner_user_id, tenant_id, status, expires_at) ON tenant_access_sessions FROM sentrail_auth;
REVOKE SELECT (role_id, perm) ON role_permissions FROM sentrail_auth;
REVOKE SELECT (id, org_id, restricted, screening_id, customer_id) ON alerts FROM sentrail_auth;

DROP INDEX audit_events_case_views;
DROP INDEX tenant_access_sessions_owner_user_id_tenant_id_status_idx;
ALTER TABLE alerts DROP COLUMN restricted, DROP COLUMN restricted_by, DROP COLUMN restricted_at;
UPDATE roles SET is_locked = false WHERE id = '00000000-0000-0000-0000-000000000002';
