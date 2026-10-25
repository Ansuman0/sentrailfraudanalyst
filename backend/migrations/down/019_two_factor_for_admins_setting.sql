-- Reverts 019_two_factor_for_admins_setting.sql.
SELECT set_config('app.platform', 'on', true);
ALTER TABLE platform_settings DROP COLUMN require_two_factor_admins;
