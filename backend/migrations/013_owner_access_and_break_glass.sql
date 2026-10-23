-- Access model v2, phase 5: owner access sessions (approval, legal hold, extension), the sealed break-glass owner, password rotation.
-- Reversible: migrations/down/013_owner_access_and_break_glass.sql.
SELECT set_config('app.platform', 'on', true);

-- Break-glass: exactly one sealed owner account. Using it alerts every owner and forces a password change afterwards.
ALTER TABLE users
  ADD COLUMN break_glass         boolean NOT NULL DEFAULT false,
  ADD COLUMN must_rotate         boolean NOT NULL DEFAULT false,     -- the next thing this person must do is change their password
  ADD COLUMN password_changed_at timestamptz;
ALTER TABLE users ADD CONSTRAINT break_glass_is_platform CHECK (NOT break_glass OR org_id IS NULL);
CREATE UNIQUE INDEX one_break_glass_account ON users ((true)) WHERE break_glass;

-- A tenant under a recorded legal hold can be entered by an owner even when its setting is "deny" (a second owner approved the hold).
ALTER TABLE organizations
  ADD COLUMN legal_hold        boolean NOT NULL DEFAULT false,
  ADD COLUMN legal_hold_reason text,
  ADD COLUMN legal_hold_at     timestamptz;

ALTER TABLE tenant_access_sessions
  ADD COLUMN decided_at         timestamptz,
  ADD COLUMN legal_hold         boolean NOT NULL DEFAULT false,
  ADD COLUMN ended_reason       text,
  ADD COLUMN request_expires_at timestamptz;
-- one open request or session per owner and tenant
CREATE UNIQUE INDEX one_open_access_per_owner_tenant ON tenant_access_sessions (owner_user_id, tenant_id)
  WHERE status IN ('requested', 'approved', 'active');

-- the session of an owner inside a tenant carries its access session id through refreshes
ALTER TABLE refresh_tokens ADD COLUMN access_session_id uuid;
