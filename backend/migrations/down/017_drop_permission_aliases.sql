-- Reverts 017_drop_permission_aliases.sql: the (empty of use) alias table comes back with its two rows.
SELECT set_config('app.platform', 'on', true);
CREATE TABLE permission_aliases (
  old_key  text PRIMARY KEY,
  new_keys text[] NOT NULL
);
INSERT INTO permission_aliases VALUES ('orgs.manage', '{platform.tenants.manage}'), ('orgs.delete', '{platform.tenants.delete}');
GRANT SELECT ON permission_aliases TO sentrail_app;
