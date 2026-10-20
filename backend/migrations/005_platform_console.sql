-- SaaS platform console: permission scopes, role templates per login type, plans, platform security baseline.
SELECT set_config('app.platform', 'on', true);

-- ---------- Every permission belongs to one login type ----------
ALTER TABLE permissions ADD COLUMN scope text NOT NULL DEFAULT 'tenant' CHECK (scope IN ('platform','tenant'));
ALTER TABLE permissions ADD COLUMN grp text NOT NULL DEFAULT 'General';
UPDATE permissions SET grp = CASE
  WHEN key IN ('cases.view','cases.decide','wallet.trace','screening.override') THEN 'Customer data'
  WHEN key IN ('str.draft','str.approve','data.export') THEN 'Reporting'
  WHEN key IN ('policy.edit','audit.view') THEN 'Governance'
  WHEN key IN ('users.manage','roles.manage','features.manage') THEN 'Administration' ELSE grp END;
UPDATE permissions SET scope='platform', grp='Tenants', description='Create organizations and change their plan'
  WHERE key='orgs.manage';
INSERT INTO permissions (key, description, scope, grp) VALUES
 ('platform.support',         'Support tenants: see user list and resend invitations', 'platform', 'Tenants'),
 ('platform.users.manage',    'Invite and manage platform staff',                                      'platform', 'Platform team'),
 ('platform.roles.manage',    'Edit platform roles',                                                   'platform', 'Platform team'),
 ('platform.plans.manage',    'Manage plans and which features they include',                          'platform', 'Plans and policy'),
 ('platform.security.manage', 'Set the security baseline every tenant must meet',                      'platform', 'Plans and policy'),
 ('platform.audit.view',      'View the platform audit log',                                           'platform', 'Oversight');

-- A role can only hold permissions of its own login type: platform roles never get customer data.
CREATE FUNCTION check_perm_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE role_scope text; perm_scope text;
BEGIN
  SELECT CASE WHEN org_id IS NULL THEN 'platform' ELSE 'tenant' END INTO role_scope FROM roles WHERE id = NEW.role_id;
  SELECT scope INTO perm_scope FROM permissions WHERE key = NEW.perm;
  IF role_scope IS DISTINCT FROM perm_scope THEN
    RAISE EXCEPTION 'permission % is for % roles, not % roles', NEW.perm, perm_scope, role_scope;
  END IF;
  RETURN NEW;
END $$;
DELETE FROM role_permissions WHERE role_id = '00000000-0000-0000-0000-000000000001' AND perm = 'features.manage';
CREATE TRIGGER role_perm_scope BEFORE INSERT OR UPDATE ON role_permissions
  FOR EACH ROW EXECUTE FUNCTION check_perm_scope();

-- ---------- Role templates (seed data by login type) ----------
CREATE TABLE role_templates (
  name        text PRIMARY KEY,
  scope       text NOT NULL CHECK (scope IN ('platform','tenant')),
  description text NOT NULL,
  sort        int NOT NULL
);
CREATE TABLE role_template_permissions (
  template text REFERENCES role_templates(name) ON DELETE CASCADE,
  perm     text REFERENCES permissions(key),
  PRIMARY KEY (template, perm)
);
INSERT INTO role_templates VALUES
 ('Platform owner',      'platform', 'Full control of the platform. Holds the break-glass login', 1),
 ('Platform admin',      'platform', 'Runs tenants, plans and the platform team',                  2),
 ('Platform support',    'platform', 'Helps tenants with sign-in. Never sees customer data',       3),
 ('Platform auditor',    'platform', 'Reads the platform audit log',                               4),
 ('Organization admin',  'tenant',   'Manages people, roles, features and security for one organization', 1),
 ('Compliance officer',  'tenant',   'Works cases, approves STRs and sets screening policy',      2),
 ('Compliance analyst',  'tenant',   'Works alerts and drafts STRs for approval',                  3),
 ('Auditor (read-only)', 'tenant',   'Reads cases and the audit log',                              4);
INSERT INTO role_template_permissions VALUES
 ('Platform owner','orgs.manage'),('Platform owner','platform.support'),('Platform owner','platform.users.manage'),
 ('Platform owner','platform.roles.manage'),('Platform owner','platform.plans.manage'),('Platform owner','platform.security.manage'),
 ('Platform owner','platform.audit.view'),
 ('Platform admin','orgs.manage'),('Platform admin','platform.support'),('Platform admin','platform.users.manage'),
 ('Platform admin','platform.plans.manage'),('Platform admin','platform.audit.view'),
 ('Platform support','platform.support'),
 ('Platform auditor','platform.audit.view'),
 ('Organization admin','users.manage'),('Organization admin','roles.manage'),('Organization admin','features.manage'),('Organization admin','audit.view'),
 ('Compliance officer','cases.view'),('Compliance officer','cases.decide'),('Compliance officer','wallet.trace'),
 ('Compliance officer','screening.override'),('Compliance officer','str.draft'),('Compliance officer','str.approve'),
 ('Compliance officer','data.export'),('Compliance officer','policy.edit'),('Compliance officer','audit.view'),
 ('Compliance analyst','cases.view'),('Compliance analyst','cases.decide'),('Compliance analyst','wallet.trace'),
 ('Compliance analyst','screening.override'),('Compliance analyst','str.draft'),
 ('Auditor (read-only)','cases.view'),('Auditor (read-only)','audit.view');

-- Platform roles are real rows (org_id NULL). The existing 000...001 becomes "Platform admin".
INSERT INTO roles (id, org_id, name, is_system) VALUES
 ('00000000-0000-0000-0000-000000000002', NULL, 'Platform owner',   true),
 ('00000000-0000-0000-0000-000000000003', NULL, 'Platform support', true),
 ('00000000-0000-0000-0000-000000000004', NULL, 'Platform auditor', true);
DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE org_id IS NULL);
INSERT INTO role_permissions
  SELECT r.id, t.perm FROM roles r JOIN role_template_permissions t ON t.template = r.name WHERE r.org_id IS NULL;

-- ---------- Plans ----------
CREATE TABLE plans (
  key        text PRIMARY KEY,
  name       text NOT NULL,
  features   text[] NOT NULL,
  max_users  int,
  sort       int NOT NULL
);
INSERT INTO plans VALUES
 ('starter',      'Starter',      '{alerts,trace}',                              5,    1),
 ('professional', 'Professional', '{screening,alerts,ai,trace,statements}',      25,   2),
 ('enterprise',   'Enterprise',   '{screening,alerts,ai,trace,statements,export}', NULL, 3);
UPDATE organizations SET plan = lower(plan);
ALTER TABLE organizations ADD CONSTRAINT organizations_plan_fk FOREIGN KEY (plan) REFERENCES plans(key);

-- ---------- Platform security baseline: tenants can be stricter, never looser ----------
CREATE TABLE platform_settings (
  id                         boolean PRIMARY KEY DEFAULT true CHECK (id),
  min_password_len_floor     int NOT NULL DEFAULT 14 CHECK (min_password_len_floor >= 12),
  max_idle_timeout_min       int NOT NULL DEFAULT 30 CHECK (max_idle_timeout_min BETWEEN 5 AND 60),
  max_session_hours          int NOT NULL DEFAULT 12 CHECK (max_session_hours BETWEEN 1 AND 24),
  retention_years_floor      int NOT NULL DEFAULT 5 CHECK (retention_years_floor >= 5),
  passkeys_allowed           boolean NOT NULL DEFAULT true,
  platform_staff_passkey_only boolean NOT NULL DEFAULT true,   -- phishing-resistant sign-in for staff
  allowed_regions            text[] NOT NULL DEFAULT '{ca-central,ca-east}',
  updated_at                 timestamptz NOT NULL DEFAULT now()
);
INSERT INTO platform_settings DEFAULT VALUES;

CREATE FUNCTION enforce_platform_floor() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE f platform_settings;
BEGIN
  SELECT * INTO f FROM platform_settings;
  IF NEW.min_password_len < f.min_password_len_floor THEN
    RAISE EXCEPTION 'Minimum password length can''t be below the platform minimum of %', f.min_password_len_floor; END IF;
  IF NEW.idle_timeout_min > f.max_idle_timeout_min THEN
    RAISE EXCEPTION 'Inactivity timeout can''t be above the platform maximum of % minutes', f.max_idle_timeout_min; END IF;
  IF NEW.retention_years < f.retention_years_floor THEN
    RAISE EXCEPTION 'Retention can''t be below the platform minimum of % years', f.retention_years_floor; END IF;
  NEW.mfa_required := true;   -- two-factor is always on; the platform doesn't allow turning it off
  RETURN NEW;
END $$;
CREATE TRIGGER security_floor BEFORE INSERT OR UPDATE ON security_settings
  FOR EACH ROW EXECUTE FUNCTION enforce_platform_floor();

-- Platform staff invitations have no organization
ALTER TABLE invitations ALTER COLUMN org_id DROP NOT NULL;

GRANT SELECT ON permissions, role_templates, role_template_permissions TO sentrail_app;
GRANT SELECT, UPDATE ON plans TO sentrail_app;
GRANT SELECT, UPDATE ON platform_settings TO sentrail_app;
