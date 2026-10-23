-- Access model v2, phase 1: memberships, one Platform owner, locked Tenant admin, new permissions, tenant lifecycle columns.
-- Reversible: migrations/down/009_access_model_v2.sql restores everything from the av2_backup_* snapshots taken below.
-- The permission catalogue (app/access/catalogue.py) finishes the job: scripts/migrate.py runs its sync after this file.
-- Tenants are still the `organizations` table (decision 2026-10-23: keep the physical names; "tenant" is used in new tables and the API).
SELECT set_config('app.platform', 'on', true);
SELECT set_config('app.role_sync', 'on', true);

-- ---------- 1. Snapshots, so the down migration can restore the previous model ----------
CREATE TABLE av2_backup_roles                AS SELECT id, org_id, name, is_system FROM roles;
CREATE TABLE av2_backup_role_permissions     AS SELECT role_id, perm FROM role_permissions;
CREATE TABLE av2_backup_users                AS SELECT id AS user_id, org_id, role_id FROM users;
CREATE TABLE av2_backup_templates            AS SELECT name, scope, description, sort FROM role_templates;
CREATE TABLE av2_backup_template_permissions AS SELECT template, perm FROM role_template_permissions;
CREATE TABLE av2_backup_permissions          AS SELECT key, description, scope, grp FROM permissions;
REVOKE ALL ON av2_backup_roles, av2_backup_role_permissions, av2_backup_users, av2_backup_templates,
              av2_backup_template_permissions, av2_backup_permissions FROM PUBLIC;

-- ---------- 2. Permissions: step-up flag, the new keys, the rename orgs.manage -> platform.tenants.manage ----------
ALTER TABLE permissions ADD COLUMN step_up boolean NOT NULL DEFAULT false;
INSERT INTO permissions (key, description, scope, grp) VALUES
 ('cases.restricted.view',   'Cases marked restricted (need-to-know)',                     'tenant',   'Customer data'),
 ('audit.export',            'Export or stream the tenant audit log',                      'tenant',   'Governance'),
 ('users.pii.reveal',        'Reveal a member''s email (reason required)',                 'tenant',   'Administration'),
 ('security.manage',         'Two-factor policy, timeouts, passwords, IP allowlist, retention, SSO', 'tenant', 'Administration'),
 ('apikeys.manage',          'Create, list, rotate and revoke API keys',                   'tenant',   'Administration'),
 ('access.review',           'Run and sign off access reviews',                            'tenant',   'Governance'),
 ('teams.manage',            'Create teams and queues',                                    'tenant',   'Administration'),
 ('platform.tenants.manage', 'Create and manage tenants',                                  'platform', 'Tenants'),
 ('platform.tenants.delete', 'Delete a tenant (second-owner approval)',                    'platform', 'Tenants'),
 ('platform.tenant.access',  'Enter a tenant through an access session',                   'platform', 'Tenants'),
 ('platform.owners.manage',  'Add, change or suspend platform owners',                     'platform', 'Platform team')
ON CONFLICT (key) DO NOTHING;

CREATE TABLE permission_aliases (
  old_key  text PRIMARY KEY,
  new_keys text[] NOT NULL
);
INSERT INTO permission_aliases VALUES ('orgs.manage', '{platform.tenants.manage}'), ('orgs.delete', '{platform.tenants.delete}');
GRANT SELECT ON permission_aliases TO sentrail_app;

INSERT INTO role_permissions SELECT role_id, 'platform.tenants.manage' FROM role_permissions WHERE perm = 'orgs.manage' ON CONFLICT DO NOTHING;
DELETE FROM role_permissions          WHERE perm = 'orgs.manage';
DELETE FROM role_template_permissions WHERE perm = 'orgs.manage';
DELETE FROM permissions               WHERE key  = 'orgs.manage';

-- users.manage used to cover email reveal, security settings and API keys. Whoever held it keeps all of that.
INSERT INTO role_permissions
  SELECT rp.role_id, k FROM role_permissions rp CROSS JOIN unnest(ARRAY['users.pii.reveal','security.manage','apikeys.manage']) k
  WHERE rp.perm = 'users.manage' ON CONFLICT DO NOTHING;

-- ---------- 3. Roles: scope, locked flag ----------
ALTER TABLE roles ADD COLUMN scope text NOT NULL DEFAULT 'tenant' CHECK (scope IN ('platform','tenant')),
                  ADD COLUMN is_locked boolean NOT NULL DEFAULT false;
UPDATE roles SET scope = 'platform' WHERE org_id IS NULL;
ALTER TABLE roles ADD CONSTRAINT roles_scope_matches_org CHECK ((scope = 'platform') = (org_id IS NULL));
CREATE FUNCTION roles_set_scope() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.scope := CASE WHEN NEW.org_id IS NULL THEN 'platform' ELSE 'tenant' END; RETURN NEW; END $$;
CREATE TRIGGER roles_set_scope BEFORE INSERT ON roles FOR EACH ROW EXECUTE FUNCTION roles_set_scope();

-- ---------- 4. One Platform owner role (the former Platform admin is merged into it) ----------
UPDATE users SET role_id = '00000000-0000-0000-0000-000000000002', session_version = session_version + 1
  WHERE role_id = '00000000-0000-0000-0000-000000000001';
INSERT INTO role_permissions SELECT '00000000-0000-0000-0000-000000000002', key FROM permissions WHERE scope = 'platform' ON CONFLICT DO NOTHING;
DELETE FROM roles WHERE id = '00000000-0000-0000-0000-000000000001';

-- ---------- 5. Tenant admin: renamed, locked, holds every tenant permission ----------
UPDATE roles SET name = 'Tenant admin', is_system = true, is_locked = true WHERE org_id IS NOT NULL AND name = 'Organization admin';
INSERT INTO role_permissions SELECT r.id, p.key FROM roles r CROSS JOIN permissions p
  WHERE r.is_locked AND p.scope = 'tenant' ON CONFLICT DO NOTHING;
UPDATE users SET session_version = session_version + 1 WHERE role_id IN (SELECT id FROM roles WHERE is_locked);

-- Built-in tenant roles follow the new templates (the intended changes, listed in the phase 1 report):
DELETE FROM role_permissions WHERE perm = 'screening.override'
  AND role_id IN (SELECT id FROM roles WHERE is_system AND org_id IS NOT NULL AND name = 'Compliance analyst');
INSERT INTO role_permissions SELECT r.id, k FROM roles r CROSS JOIN unnest(ARRAY['cases.restricted.view','teams.manage']) k
  WHERE r.is_system AND r.org_id IS NOT NULL AND r.name = 'Compliance officer' ON CONFLICT DO NOTHING;
INSERT INTO role_permissions SELECT r.id, 'audit.export' FROM roles r
  WHERE r.is_system AND r.org_id IS NOT NULL AND r.name = 'Auditor (read-only)' ON CONFLICT DO NOTHING;
UPDATE users SET session_version = session_version + 1
  WHERE role_id IN (SELECT id FROM roles WHERE is_system AND org_id IS NOT NULL
                    AND name IN ('Compliance analyst','Compliance officer','Auditor (read-only)'));

-- Templates: rename Organization admin, drop Platform admin (the catalogue sync writes the rest).
INSERT INTO role_templates SELECT 'Tenant admin', scope, description, sort FROM role_templates WHERE name = 'Organization admin' ON CONFLICT DO NOTHING;
DELETE FROM role_templates WHERE name IN ('Organization admin', 'Platform admin');

-- ---------- 6. Tenants (organizations): lifecycle, jurisdiction, owner-access setting ----------
ALTER TABLE organizations
  ADD COLUMN jurisdiction  text NOT NULL DEFAULT 'CA',
  ADD COLUMN owner_access  text NOT NULL DEFAULT 'allow' CHECK (owner_access IN ('allow','require_approval','deny')),
  ADD COLUMN deleted_at    timestamptz;
ALTER TABLE organizations DROP CONSTRAINT organizations_status_check;
ALTER TABLE organizations ADD CONSTRAINT organizations_status_check
  CHECK (status IN ('pending','active','trial','suspended','deleted'));     -- 'trial' kept for existing rows
CREATE FUNCTION organizations_slug_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.slug IS NOT NULL AND NEW.slug IS DISTINCT FROM OLD.slug THEN RAISE EXCEPTION 'A tenant slug cannot be changed'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER organizations_slug_immutable BEFORE UPDATE OF slug ON organizations
  FOR EACH ROW EXECUTE FUNCTION organizations_slug_immutable();

-- ---------- 7. Memberships and platform staff ----------
CREATE TABLE tenant_memberships (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  role_id           uuid NOT NULL REFERENCES roles(id),
  status            text NOT NULL DEFAULT 'invited' CHECK (status IN ('invited','active','suspended')),
  invited_by        uuid REFERENCES users(id) ON DELETE SET NULL,
  invite_expires_at timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  last_active_at    timestamptz,
  UNIQUE (user_id, tenant_id)
);
CREATE INDEX ON tenant_memberships (tenant_id);

CREATE TABLE platform_staff (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  role_id uuid NOT NULL REFERENCES roles(id),
  status  text NOT NULL DEFAULT 'invited' CHECK (status IN ('invited','active','suspended'))
);

CREATE TABLE tenant_access_sessions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id uuid NOT NULL REFERENCES users(id),
  tenant_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  reason        text NOT NULL,
  status        text NOT NULL DEFAULT 'requested' CHECK (status IN ('requested','approved','active','ended','denied')),
  approved_by   uuid REFERENCES users(id),
  requested_at  timestamptz NOT NULL DEFAULT now(),
  started_at    timestamptz,
  expires_at    timestamptz,
  extended      boolean NOT NULL DEFAULT false,
  ended_at      timestamptz
);
CREATE INDEX ON tenant_access_sessions (tenant_id, status);

CREATE TABLE platform_approvals (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  action       text NOT NULL,
  payload      jsonb NOT NULL DEFAULT '{}',
  requested_by uuid NOT NULL REFERENCES users(id),
  approved_by  uuid REFERENCES users(id),
  status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','expired')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  decided_at   timestamptz,
  expires_at   timestamptz NOT NULL,
  CONSTRAINT approval_two_people CHECK (approved_by IS NULL OR approved_by <> requested_by)
);

-- Row-level security (phase 3 replaces these with membership-aware policies).
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['tenant_memberships','tenant_access_sessions'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = NULLIF(current_setting('app.org_id', true), '')::uuid OR current_setting('app.platform', true) = 'on')
      WITH CHECK (tenant_id = NULLIF(current_setting('app.org_id', true), '')::uuid OR current_setting('app.platform', true) = 'on')$p$, t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['platform_staff','platform_approvals'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY platform_only ON %I
      USING (current_setting('app.platform', true) = 'on') WITH CHECK (current_setting('app.platform', true) = 'on')$p$, t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_memberships, platform_staff, tenant_access_sessions, platform_approvals TO sentrail_app;

-- Backfill: one membership per tenant user, one staff row per platform user.
INSERT INTO tenant_memberships (user_id, tenant_id, role_id, status, invited_by, invite_expires_at, created_at, last_active_at)
  SELECT u.id, u.org_id, u.role_id, u.status, i.invited_by, CASE WHEN u.status = 'invited' THEN i.expires_at END, u.created_at, u.last_login_at
  FROM users u
  LEFT JOIN LATERAL (SELECT invited_by, expires_at FROM invitations WHERE user_id = u.id AND accepted_at IS NULL
                     ORDER BY expires_at DESC LIMIT 1) i ON true
  WHERE u.org_id IS NOT NULL;
INSERT INTO platform_staff (user_id, role_id, status) SELECT id, role_id, status FROM users WHERE org_id IS NULL;

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

-- ---------- 8. Locked roles (created last so the statements above are not blocked) ----------
-- The catalogue sync and tenant deletion set app.role_sync = 'on'; no API path does.
CREATE FUNCTION roles_locked_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF current_setting('app.role_sync', true) = 'on' THEN RETURN COALESCE(NEW, OLD); END IF;
  IF OLD.is_locked THEN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'The % role is locked and cannot be deleted', OLD.name; END IF;
    IF NEW.name <> OLD.name OR NEW.is_locked <> OLD.is_locked OR NEW.org_id IS DISTINCT FROM OLD.org_id THEN
      RAISE EXCEPTION 'The % role is locked and cannot be changed', OLD.name;
    END IF;
  END IF;
  RETURN COALESCE(NEW, OLD);
END $$;
CREATE TRIGGER roles_locked_guard BEFORE UPDATE OR DELETE ON roles FOR EACH ROW EXECUTE FUNCTION roles_locked_guard();

CREATE FUNCTION role_permissions_locked_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF current_setting('app.role_sync', true) = 'on' THEN RETURN COALESCE(NEW, OLD); END IF;
  IF EXISTS (SELECT 1 FROM roles WHERE id = OLD.role_id AND is_locked) THEN
    RAISE EXCEPTION 'The permissions of a locked role cannot be changed';
  END IF;
  RETURN COALESCE(NEW, OLD);
END $$;
CREATE TRIGGER role_permissions_locked_guard BEFORE UPDATE OR DELETE ON role_permissions
  FOR EACH ROW EXECUTE FUNCTION role_permissions_locked_guard();
