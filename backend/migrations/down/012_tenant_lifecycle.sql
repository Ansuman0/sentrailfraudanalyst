-- Reverts 012_tenant_lifecycle.sql.
ALTER TABLE platform_approvals DROP COLUMN reason;
ALTER TABLE organizations DROP COLUMN status_reason, DROP COLUMN status_changed_at, DROP COLUMN deletion_due_at;
ALTER TABLE users DROP COLUMN mfa_mandatory;
