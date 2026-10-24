-- Access model v2, phase 9: the permission aliases (old names that satisfied renamed permissions) are gone.
-- Reversible: migrations/down/017_drop_permission_aliases.sql.
SELECT set_config('app.platform', 'on', true);
-- Defensive: no role may still hold an old name (migration 009 renamed them; this only matters for a database restored from before it).
INSERT INTO role_permissions SELECT role_id, 'platform.tenants.manage' FROM role_permissions WHERE perm = 'orgs.manage' ON CONFLICT DO NOTHING;
INSERT INTO role_permissions SELECT role_id, 'platform.tenants.delete' FROM role_permissions WHERE perm = 'orgs.delete' ON CONFLICT DO NOTHING;
DELETE FROM role_permissions WHERE perm IN ('orgs.manage', 'orgs.delete');
DELETE FROM role_template_permissions WHERE perm IN ('orgs.manage', 'orgs.delete');
DELETE FROM permissions WHERE key IN ('orgs.manage', 'orgs.delete');
DROP TABLE permission_aliases;
