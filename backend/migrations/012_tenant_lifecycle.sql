-- Access model v2, phase 4: tenant lifecycle (pending -> active <-> suspended -> deleted), mandatory two-factor for people enrolled as Tenant admin,
-- and a reason on approvals. Reversible: migrations/down/012_tenant_lifecycle.sql.
SELECT set_config('app.platform', 'on', true);

ALTER TABLE users ADD COLUMN mfa_mandatory boolean NOT NULL DEFAULT false;    -- set when someone accepts an invitation as Tenant admin

ALTER TABLE organizations
  ADD COLUMN status_reason text,                  -- why it was suspended or deleted (also in both audit logs)
  ADD COLUMN status_changed_at timestamptz,
  ADD COLUMN deletion_due_at timestamptz;         -- deleted tenants: data is removed after this date (the retention period); phase 7 runs the removal

ALTER TABLE platform_approvals ADD COLUMN reason text;
