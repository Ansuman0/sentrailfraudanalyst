-- Fixes from the code review (see CHANGES.md).
SELECT set_config('app.platform', 'on', true);

-- ---------- Alerts: a fixed set of states and a link back to the screening that raised them ----------
ALTER TABLE alerts ADD COLUMN screening_id text;
ALTER TABLE alerts ADD CONSTRAINT alerts_status_check
  CHECK (status IN ('open','pending_info','escalated','closed','awaiting_approval','str_filed'));

-- ---------- Screenings: idempotent retries, fiat value used for thresholds, full stored answer ----------
ALTER TABLE screenings
  ADD COLUMN client_ref  text,                       -- ramp's own transfer id; retries return the stored answer
  ADD COLUMN asset       text,
  ADD COLUMN fiat_value  numeric(20,2),              -- value compared with the travel-rule and wallet-proof thresholds
  ADD COLUMN result      jsonb,                      -- the exact answer the ramp received
  ADD COLUMN override_reason text,
  ADD COLUMN override_at timestamptz;
ALTER TABLE screenings ADD CONSTRAINT screenings_client_ref_unique UNIQUE (org_id, client_ref);
ALTER TABLE screenings ADD CONSTRAINT screenings_override_check CHECK (override IS NULL OR override IN ('release','block'));

-- ---------- API keys: a label and timestamps so they can be listed and revoked ----------
ALTER TABLE api_keys
  ADD COLUMN label      text,
  ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();

-- ---------- Sign-in throttling keyed by (email blind index, client IP) ----------
-- Unknown emails are throttled exactly like known ones, so a 429 no longer reveals that an account exists,
-- and someone guessing from one network can't lock the real owner out from theirs.
-- Holds only hashes and IPs, no tenant data, so it isn't tenant-scoped.
CREATE TABLE login_throttle (
  key_hash     bytea NOT NULL,
  ip           text  NOT NULL DEFAULT '',
  failed       int   NOT NULL DEFAULT 0,
  locked_until timestamptz,
  updated_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (key_hash, ip)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON login_throttle TO sentrail_app;
