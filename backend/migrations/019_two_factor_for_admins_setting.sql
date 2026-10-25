-- Access model v2: whether two-factor is MANDATORY for Tenant admins and platform staff (other than the platform owner) is a platform
-- setting. Default on (the secure default); a demo or a first roll-out can turn it off so people enable two-factor later from My account.
-- Turning it off is a loosening of the baseline, so it needs a second owner's approval. Reversible: migrations/down/019_*.sql.
SELECT set_config('app.platform', 'on', true);
ALTER TABLE platform_settings ADD COLUMN require_two_factor_admins boolean NOT NULL DEFAULT true;
