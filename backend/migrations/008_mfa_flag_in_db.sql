-- Two-factor is chosen by each person (decision 2026-10-17); the database records whether they did.
--   users.mfa_enabled     : true only after the person confirmed a code from their authenticator app.
--   users.mfa_enabled_at  : when they did. Kept by a trigger so no code path (API, script, manual SQL) can leave it wrong.
-- The CHECK makes "enabled" without a stored authenticator secret impossible.
SELECT set_config('app.platform', 'on', true);

ALTER TABLE users ADD COLUMN mfa_enabled_at timestamptz;
UPDATE users SET mfa_enabled_at = COALESCE(last_login_at, created_at) WHERE mfa_enabled;

CREATE OR REPLACE FUNCTION users_mfa_stamp() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT NEW.mfa_enabled THEN
    NEW.mfa_enabled_at := NULL;
  ELSIF TG_OP = 'INSERT' OR NOT OLD.mfa_enabled OR NEW.mfa_enabled_at IS NULL THEN
    NEW.mfa_enabled_at := now();
  ELSE
    NEW.mfa_enabled_at := OLD.mfa_enabled_at;       -- already on: the original date stands
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER users_mfa_stamp BEFORE INSERT OR UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION users_mfa_stamp();

ALTER TABLE users ADD CONSTRAINT users_mfa_has_secret CHECK (NOT mfa_enabled OR totp_secret_enc IS NOT NULL);
