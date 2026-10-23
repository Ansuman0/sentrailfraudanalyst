-- Reverts 010_sessions_and_devices.sql. Existing sessions keep working (they simply lose their tenant and two-factor timestamps).
DROP FUNCTION membership_lookup(uuid);
DROP FUNCTION platform_staff_lookup(uuid);
DROP FUNCTION session_user_lookup(uuid);
REVOKE SELECT (id, status, session_version, role_id, mfa_enabled, auth_method) ON users FROM sentrail_auth;
REVOKE SELECT (user_id, tenant_id, role_id, status) ON tenant_memberships FROM sentrail_auth;
REVOKE SELECT (user_id, role_id, status) ON platform_staff FROM sentrail_auth;
REVOKE SELECT (id, name) ON roles FROM sentrail_auth;
DROP INDEX refresh_tokens_family_live;
DROP TABLE user_devices;
ALTER TABLE refresh_tokens DROP COLUMN last_mfa_at, DROP COLUMN tenant_id, DROP COLUMN scope;
