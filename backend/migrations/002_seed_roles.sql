-- Platform role. Org system roles are created per organization by admin_api.provision_org().
SELECT set_config('app.platform', 'on', true);   -- row-level security is forced, even for the owner
INSERT INTO roles (id, org_id, name, is_system) VALUES
  ('00000000-0000-0000-0000-000000000001', NULL, 'Platform admin', true);
INSERT INTO role_permissions VALUES
  ('00000000-0000-0000-0000-000000000001','orgs.manage'),
  ('00000000-0000-0000-0000-000000000001','features.manage');
