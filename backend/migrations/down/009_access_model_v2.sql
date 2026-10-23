-- Reverts 009_access_model_v2.sql from its av2_backup_* snapshots. Run by `python -m scripts.migrate --down`.
-- Roles, role permissions, users' roles, templates, permissions and organization columns return to their state at the time of the
-- migration. Custom roles created afterwards keep their name and the permissions that still exist; users created afterwards keep their role.
-- Also run `python -m scripts.reencrypt_identity --down` first if identity data was moved to per-user encryption.
SELECT set_config('app.platform', 'on', true);
SELECT set_config('app.role_sync', 'on', true);

-- Guards and sync trigger first, so the restore below is not blocked.
DROP TRIGGER role_permissions_locked_guard ON role_permissions;
DROP FUNCTION role_permissions_locked_guard();
DROP TRIGGER roles_locked_guard ON roles;
DROP FUNCTION roles_locked_guard();
DROP TRIGGER users_sync_access_model ON users;
DROP FUNCTION users_sync_access_model();

DROP TABLE platform_approvals, tenant_access_sessions, platform_staff, tenant_memberships;

-- Organizations
ALTER TABLE organizations DROP CONSTRAINT organizations_status_check;
UPDATE organizations SET status = 'suspended' WHERE status = 'deleted';
ALTER TABLE organizations ADD CONSTRAINT organizations_status_check CHECK (status IN ('pending','active','trial','suspended'));
DROP TRIGGER organizations_slug_immutable ON organizations;
DROP FUNCTION organizations_slug_immutable();
ALTER TABLE organizations DROP COLUMN jurisdiction, DROP COLUMN owner_access, DROP COLUMN deleted_at;

-- Roles: bring back the removed ones, restore names, drop the new columns.
ALTER TABLE roles DROP CONSTRAINT roles_scope_matches_org;
DROP TRIGGER roles_set_scope ON roles;
DROP FUNCTION roles_set_scope();
INSERT INTO roles (id, org_id, name, is_system)
  SELECT id, org_id, name, is_system FROM av2_backup_roles WHERE id NOT IN (SELECT id FROM roles);
UPDATE roles r SET name = b.name, is_system = b.is_system FROM av2_backup_roles b WHERE r.id = b.id;
ALTER TABLE roles DROP COLUMN scope, DROP COLUMN is_locked;

-- Permissions: old keys back first (so role_permissions can reference them), new keys out.
INSERT INTO permissions (key, description, scope, grp)
  SELECT key, description, scope, grp FROM av2_backup_permissions WHERE key NOT IN (SELECT key FROM permissions);
-- Templates
DELETE FROM role_templates;
INSERT INTO role_templates SELECT name, scope, description, sort FROM av2_backup_templates;
INSERT INTO role_template_permissions SELECT template, perm FROM av2_backup_template_permissions;

DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM av2_backup_roles);          -- backed-up roles get their old set back
INSERT INTO role_permissions SELECT role_id, perm FROM av2_backup_role_permissions
  WHERE role_id IN (SELECT id FROM roles) ON CONFLICT DO NOTHING;
DELETE FROM role_permissions WHERE perm NOT IN (SELECT key FROM av2_backup_permissions);  -- new keys on roles created later
DELETE FROM permissions WHERE key NOT IN (SELECT key FROM av2_backup_permissions);
ALTER TABLE permissions DROP COLUMN step_up;
DROP TABLE permission_aliases;

-- Users go back to their previous roles.
UPDATE users u SET role_id = b.role_id, session_version = u.session_version + 1
  FROM av2_backup_users b WHERE u.id = b.user_id AND u.role_id <> b.role_id;
UPDATE users SET session_version = session_version + 1;      -- every session reloads its permissions

DROP TABLE av2_backup_roles, av2_backup_role_permissions, av2_backup_users, av2_backup_templates,
           av2_backup_template_permissions, av2_backup_permissions;
