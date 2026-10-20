-- Two-factor becomes a per-organization choice (decision 2026-10-16, see memory/PROJECT_MEMORY.md).
--   users.mfa_enabled            : this person has confirmed an authenticator app (TOTP).
--   security_settings.mfa_required: everyone in the organization must set it up; when false they may skip it.
-- Platform staff and organization admins must always set it up, and users without it can't take sensitive
-- actions. Both rules are enforced by the API (app/security/rbac.py), not here.
SELECT set_config('app.platform', 'on', true);

ALTER TABLE users ADD COLUMN mfa_enabled boolean NOT NULL DEFAULT false;
-- Anyone who already finished TOTP enrollment keeps it. (A secret on an 'invited' user was never confirmed.)
UPDATE users SET mfa_enabled = true WHERE totp_secret_enc IS NOT NULL AND status <> 'invited';
UPDATE users SET totp_secret_enc = NULL WHERE NOT mfa_enabled;

-- Optional by default, for new and existing organizations.
ALTER TABLE security_settings ALTER COLUMN mfa_required SET DEFAULT false;

-- The platform floor no longer forces mfa_required = true; it still enforces the other minimums.
CREATE OR REPLACE FUNCTION enforce_platform_floor() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE f platform_settings;
BEGIN
  SELECT * INTO f FROM platform_settings;
  IF NEW.min_password_len < f.min_password_len_floor THEN
    RAISE EXCEPTION 'Minimum password length can''t be below the platform minimum of %', f.min_password_len_floor; END IF;
  IF NEW.idle_timeout_min > f.max_idle_timeout_min THEN
    RAISE EXCEPTION 'Inactivity timeout can''t be above the platform maximum of % minutes', f.max_idle_timeout_min; END IF;
  IF NEW.retention_years < f.retention_years_floor THEN
    RAISE EXCEPTION 'Retention can''t be below the platform minimum of % years', f.retention_years_floor; END IF;
  RETURN NEW;
END $$;

UPDATE security_settings SET mfa_required = false;

-- How each refresh-token session signed in, so a refresh keeps the same assurance level.
-- Existing values: 'password+totp', 'keycloak'. New: 'password' (no second factor).
