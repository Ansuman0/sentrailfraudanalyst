-- Access model v2, phase 7: SCIM, access reviews, dormant memberships, audit export and streaming, export controls, anomaly alerts,
-- tenant data removal. Reversible: migrations/down/015_governance_and_data_controls.sql.
SELECT set_config('app.platform', 'on', true);

-- ---------- Plans: SCIM and audit streaming are Enterprise features ----------
ALTER TABLE org_features DROP CONSTRAINT org_features_feature_check;
ALTER TABLE org_features ADD CONSTRAINT org_features_feature_check
  CHECK (feature IN ('screening','alerts','ai','trace','statements','export','scim','audit_streaming'));
UPDATE plans SET features = features || ARRAY['scim','audit_streaming'] WHERE key = 'enterprise' AND NOT features @> ARRAY['scim'];
INSERT INTO org_features (org_id, feature, in_plan, enabled)
  SELECT o.id, f, o.plan = 'enterprise', o.plan = 'enterprise' FROM organizations o, unnest(ARRAY['scim','audit_streaming']) f
  ON CONFLICT DO NOTHING;

-- ---------- Per-tenant settings (each one is enforced and has a proof in tests/test_settings_enforcement_e2e.py) ----------
ALTER TABLE security_settings
  ADD COLUMN dormant_days                int     NOT NULL DEFAULT 90 CHECK (dormant_days BETWEEN 30 AND 365),
  ADD COLUMN access_review_days          int     NOT NULL DEFAULT 90 CHECK (access_review_days BETWEEN 30 AND 365),
  ADD COLUMN export_limit_per_hour       int     NOT NULL DEFAULT 20 CHECK (export_limit_per_hour BETWEEN 1 AND 1000),
  ADD COLUMN anomaly_searches_per_hour   int     NOT NULL DEFAULT 100 CHECK (anomaly_searches_per_hour BETWEEN 5 AND 10000),
  ADD COLUMN anomaly_exports_per_hour    int     NOT NULL DEFAULT 10 CHECK (anomaly_exports_per_hour BETWEEN 1 AND 1000),
  ADD COLUMN alert_new_country           boolean NOT NULL DEFAULT true;

ALTER TABLE tenant_memberships ADD COLUMN reactivated_at timestamptz;          -- a reactivated person is not dormant again at once

-- ---------- SCIM 2.0 ----------
CREATE TABLE scim_tokens (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  prefix       text NOT NULL UNIQUE,
  token_hash   bytea NOT NULL,
  label        text NOT NULL,
  created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at   timestamptz
);
CREATE INDEX ON scim_tokens (tenant_id);
CREATE TABLE scim_groups (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  display_name text NOT NULL,
  external_id  text,
  role_id      uuid REFERENCES roles(id) ON DELETE SET NULL,             -- the role everyone in the group gets (never a locked role)
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, display_name)
);
CREATE TABLE scim_group_members (
  group_id  uuid NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
  user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX ON scim_group_members (tenant_id, user_id);
ALTER TABLE users ADD COLUMN scim_external_id text;                        -- the provider's own id for the person

-- ---------- Access reviews ----------
CREATE TABLE access_reviews (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid REFERENCES organizations(id) ON DELETE CASCADE,       -- NULL = the platform's own staff
  title          text NOT NULL,
  status         text NOT NULL DEFAULT 'open' CHECK (status IN ('open','signed_off','cancelled')),
  opened_at      timestamptz NOT NULL DEFAULT now(),
  opened_by      uuid REFERENCES users(id) ON DELETE SET NULL,
  due_at         timestamptz NOT NULL,
  signed_off_at  timestamptz,
  signed_off_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  last_reminder_at timestamptz
);
CREATE INDEX ON access_reviews (tenant_id, status);
CREATE TABLE access_review_items (
  review_id   uuid NOT NULL REFERENCES access_reviews(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id   uuid REFERENCES organizations(id) ON DELETE CASCADE,
  role_name   text NOT NULL,                                                   -- the role the person held when the review opened
  decision    text CHECK (decision IN ('keep','change','remove')),
  new_role_id uuid REFERENCES roles(id),
  note        text,
  decided_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  decided_at  timestamptz,
  PRIMARY KEY (review_id, user_id)
);

-- ---------- Audit streaming to a customer's SIEM ----------
CREATE TABLE audit_streams (
  tenant_id       uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  url             text NOT NULL,
  secret_enc      text NOT NULL,
  enabled         boolean NOT NULL DEFAULT true,
  last_seq        bigint NOT NULL DEFAULT 0,                                   -- everything up to here has been delivered
  failures        int NOT NULL DEFAULT 0,
  last_error      text,
  last_success_at timestamptz,
  created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);

-- ---------- Export controls: files are stored encrypted, fetched once within 15 minutes ----------
CREATE TABLE export_links (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind         text NOT NULL,
  filename     text NOT NULL,
  content_type text NOT NULL,
  content_enc  text,
  token_hash   bytea NOT NULL UNIQUE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL DEFAULT now() + interval '15 minutes',
  used_at      timestamptz
);
CREATE INDEX ON export_links (tenant_id);

-- ---------- Anomaly alerts: which countries a person has signed in from ----------
CREATE TABLE user_countries (
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  country       text NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, country)
);

-- ---------- Job runner bookkeeping (what ran last, and how it went) ----------
CREATE TABLE job_runs (
  name        text PRIMARY KEY,
  last_run_at timestamptz NOT NULL,
  last_ok     boolean NOT NULL,
  last_detail text
);

-- ---------- Row-level security for the new tenant tables ----------
DO $$
DECLARE t text; pred text;
BEGIN
  FOREACH t IN ARRAY ARRAY['scim_tokens','scim_groups','scim_group_members','access_review_items','access_reviews','audit_streams','export_links'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    pred := $q$((tenant_id = NULLIF(current_setting('app.org_id', true), '')::uuid AND actor_may_access(tenant_id))
                OR (tenant_id IS NULL AND current_setting('app.platform', true) = 'on' AND actor_is_platform()))$q$;
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING %s WITH CHECK %s', t, pred, pred);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON scim_tokens, scim_groups, scim_group_members, access_reviews, access_review_items, audit_streams,
  export_links, user_countries, job_runs TO sentrail_app;

-- SCIM calls arrive with a bearer token and no tenant yet: look the token up the way API keys are.
GRANT SELECT (tenant_id, prefix, token_hash, revoked_at) ON scim_tokens TO sentrail_auth;
GRANT CREATE ON SCHEMA public TO sentrail_auth;
CREATE FUNCTION scim_token_lookup(p text) RETURNS TABLE(tenant_id uuid, token_hash bytea)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT tenant_id, token_hash FROM scim_tokens WHERE prefix = p AND revoked_at IS NULL $$;
ALTER FUNCTION scim_token_lookup(text) OWNER TO sentrail_auth;
REVOKE CREATE ON SCHEMA public FROM sentrail_auth;
GRANT EXECUTE ON FUNCTION scim_token_lookup(text) TO sentrail_app;

-- ---------- Tenant data removal (the only way the append-only audit log is ever cut) ----------
-- Runs as the table owner. Refuses unless the tenant is deleted and its retention period has passed.
CREATE FUNCTION purge_tenant_audit(o uuid) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE n bigint;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM organizations WHERE id = o AND status = 'deleted' AND deletion_due_at <= now()) THEN
    RAISE EXCEPTION 'tenant % is not due for data removal', o;
  END IF;
  ALTER TABLE audit_events DISABLE TRIGGER audit_no_update;
  DELETE FROM audit_events WHERE org_id = o;
  GET DIAGNOSTICS n = ROW_COUNT;
  ALTER TABLE audit_events ENABLE TRIGGER audit_no_update;
  RETURN n;
END $$;
REVOKE ALL ON FUNCTION purge_tenant_audit(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_tenant_audit(uuid) TO sentrail_app;
