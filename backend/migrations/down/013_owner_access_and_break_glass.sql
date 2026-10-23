-- Reverts 013_owner_access_and_break_glass.sql (open access sessions are ended first).
SELECT set_config('app.platform', 'on', true);
UPDATE tenant_access_sessions SET status = 'ended', ended_at = now() WHERE status IN ('requested', 'approved', 'active');
ALTER TABLE refresh_tokens DROP COLUMN access_session_id;
DROP INDEX one_open_access_per_owner_tenant;
ALTER TABLE tenant_access_sessions DROP COLUMN decided_at, DROP COLUMN legal_hold, DROP COLUMN ended_reason, DROP COLUMN request_expires_at;
ALTER TABLE organizations DROP COLUMN legal_hold, DROP COLUMN legal_hold_reason, DROP COLUMN legal_hold_at;
DROP INDEX one_break_glass_account;
ALTER TABLE users DROP CONSTRAINT break_glass_is_platform;
ALTER TABLE users DROP COLUMN break_glass, DROP COLUMN must_rotate, DROP COLUMN password_changed_at;
