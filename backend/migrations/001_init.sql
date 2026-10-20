-- Sentrail schema. PostgreSQL 15+.
-- Run as the owner role; the API connects as sentrail_app, which is NOT the owner,
-- so row-level security always applies to it.

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;

DO $$ BEGIN
  CREATE ROLE sentrail_app LOGIN;  -- password set by scripts/migrate.py from APP_DB_PASSWORD
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ---------- Tenancy ----------
CREATE TABLE organizations (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  legal_name    text NOT NULL,
  business_type text NOT NULL,
  registration  text NOT NULL,                 -- FINTRAC MSB number or RPAA id
  data_region   text NOT NULL DEFAULT 'ca-central',
  plan          text NOT NULL DEFAULT 'professional',
  status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','trial','suspended')),
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE org_features (
  org_id   uuid REFERENCES organizations(id) ON DELETE CASCADE,
  feature  text NOT NULL CHECK (feature IN ('screening','alerts','ai','trace','statements','export')),
  in_plan  boolean NOT NULL DEFAULT true,     -- set by platform admin
  enabled  boolean NOT NULL DEFAULT true,     -- toggled by org admin, only if in_plan
  PRIMARY KEY (org_id, feature)
);

CREATE TABLE security_settings (
  org_id            uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  mfa_required      boolean NOT NULL DEFAULT true,
  sso_enabled       boolean NOT NULL DEFAULT false,
  oidc_issuer       text,
  oidc_client_id    text,
  idle_timeout_min  int NOT NULL DEFAULT 15 CHECK (idle_timeout_min BETWEEN 5 AND 60),
  min_password_len  int NOT NULL DEFAULT 14 CHECK (min_password_len >= 12),
  ip_allowlist      cidr[] NOT NULL DEFAULT '{}',
  retention_years   int NOT NULL DEFAULT 5 CHECK (retention_years >= 5)
);

-- ---------- Roles and permissions ----------
CREATE TABLE permissions (key text PRIMARY KEY, description text NOT NULL);
INSERT INTO permissions VALUES
 ('cases.view','View alerts, cases and transfers'), ('cases.decide','Close alerts, request info'),
 ('wallet.trace','Trace wallets'), ('screening.override','Release or block held transfers'),
 ('str.draft','Run AI investigation and draft STRs'), ('str.approve','Approve and file STRs'),
 ('data.export','Export case data'), ('policy.edit','Change screening policy'),
 ('audit.view','View audit log'), ('users.manage','Invite and manage users'),
 ('roles.manage','Edit roles and permissions'), ('features.manage','Turn features on or off'),
 ('orgs.manage','Create and manage organizations');

CREATE TABLE roles (
  id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id    uuid REFERENCES organizations(id) ON DELETE CASCADE,  -- NULL = platform role
  name      text NOT NULL,
  is_system boolean NOT NULL DEFAULT false,
  UNIQUE (org_id, name)
);
CREATE TABLE role_permissions (
  role_id uuid REFERENCES roles(id) ON DELETE CASCADE,
  perm    text REFERENCES permissions(key),
  PRIMARY KEY (role_id, perm)
);

-- ---------- Identity (personal data encrypted at the application layer) ----------
CREATE TABLE users (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid REFERENCES organizations(id) ON DELETE CASCADE,   -- NULL for platform staff
  role_id          uuid NOT NULL REFERENCES roles(id),
  email_enc        text NOT NULL,           -- AES-256-GCM ciphertext "kv:nonce:ct"
  email_bidx       bytea NOT NULL,          -- HMAC-SHA256 blind index for lookup
  name_enc         text,
  phone_enc        text,
  password_hash    text,                    -- argon2id; NULL when SSO-only
  totp_secret_enc  text,
  totp_last_step   bigint NOT NULL DEFAULT 0,          -- blocks code replay
  status           text NOT NULL DEFAULT 'invited' CHECK (status IN ('invited','active','suspended')),
  failed_logins    int NOT NULL DEFAULT 0,
  locked_until     timestamptz,
  session_version  int NOT NULL DEFAULT 1,             -- bump to kill every session
  last_login_at    timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (email_bidx)
);
CREATE INDEX ON users (org_id);

CREATE TABLE recovery_codes (
  user_id   uuid REFERENCES users(id) ON DELETE CASCADE,
  code_hash text NOT NULL,
  used_at   timestamptz
);

CREATE TABLE invitations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  bytea NOT NULL UNIQUE,        -- SHA-256 of the emailed token; token itself never stored
  invited_by  uuid REFERENCES users(id),
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz
);

CREATE TABLE refresh_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id   uuid NOT NULL,                -- rotation chain; reuse revokes the family
  token_hash  bytea NOT NULL UNIQUE,
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz,
  user_agent  text,
  ip          inet
);

CREATE TABLE api_keys (                     -- machine access for the on/off-ramp (/screen)
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  prefix     text NOT NULL UNIQUE,          -- shown in UI, e.g. "sk_live_7h2k"
  key_hash   bytea NOT NULL,
  scopes     text[] NOT NULL DEFAULT '{screen}',
  created_by uuid REFERENCES users(id),
  revoked_at timestamptz
);

-- ---------- Compliance data ----------
CREATE TABLE alerts (
  id           text NOT NULL,
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  customer_id  text NOT NULL,
  score        int NOT NULL,
  band         text NOT NULL,
  reasons      jsonb NOT NULL,
  channel      text,
  status       text NOT NULL DEFAULT 'open',
  assigned_to  uuid REFERENCES users(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id)
);
CREATE TABLE str_drafts (
  org_id       uuid NOT NULL,
  alert_id     text NOT NULL,
  ai_draft_enc text,
  final_enc    text,
  drafted_by   uuid REFERENCES users(id),
  approved_by  uuid REFERENCES users(id),
  status       text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','awaiting_approval','approved')),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, alert_id),
  FOREIGN KEY (org_id, alert_id) REFERENCES alerts(org_id, id) ON DELETE CASCADE,
  CONSTRAINT four_eyes CHECK (approved_by IS NULL OR approved_by <> drafted_by)
);
CREATE TABLE screenings (
  id          text PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  customer_id text NOT NULL,
  direction   text NOT NULL,
  address     text NOT NULL,
  amount      numeric(20,6) NOT NULL,
  score       int NOT NULL,
  decision    text NOT NULL CHECK (decision IN ('release','hold','block')),
  reasons     jsonb NOT NULL,
  override    text,
  override_by uuid REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE screening_policy (
  org_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  policy jsonb NOT NULL
);

-- ---------- Tamper-evident audit log ----------
CREATE TABLE audit_events (
  seq        bigserial PRIMARY KEY,
  org_id     uuid,                          -- NULL = platform event
  at         timestamptz NOT NULL DEFAULT now(),
  actor_id   uuid,
  actor_role text,
  action     text NOT NULL,
  target     text,
  detail     jsonb NOT NULL DEFAULT '{}',
  ip         inet,
  prev_hash  bytea NOT NULL,
  hash       bytea NOT NULL
);
CREATE INDEX ON audit_events (org_id, seq);

CREATE FUNCTION audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_events is append-only'; END $$;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_immutable();

-- ---------- Row-level security: every query is scoped to app.org_id ----------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['org_features','security_settings','roles','users','invitations','api_keys',
                           'alerts','str_drafts','screenings','screening_policy','audit_events'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid
             OR (current_setting('app.platform', true) = 'on' AND %s))
      WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid
             OR (current_setting('app.platform', true) = 'on' AND %s))$p$,
      t,
      -- platform staff may touch org metadata, never customer or case data
      CASE WHEN t IN ('org_features','security_settings','roles','users','invitations','audit_events') THEN 'true' ELSE 'false' END,
      CASE WHEN t IN ('org_features','security_settings','roles','users','invitations','audit_events') THEN 'true' ELSE 'false' END);
  END LOOP;
END $$;

-- users lookup by blind index must work before tenant is known (login)
CREATE FUNCTION auth_lookup(bidx bytea) RETURNS TABLE(id uuid, org_id uuid) LANGUAGE sql SECURITY DEFINER
  SET search_path = public AS $$ SELECT id, org_id FROM users WHERE email_bidx = bidx $$;
-- token lookups during invitation acceptance and refresh happen before the tenant is known
CREATE FUNCTION invitation_lookup(th bytea) RETURNS TABLE(id uuid, org_id uuid, user_id uuid, expires_at timestamptz, accepted_at timestamptz)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS
  $$ SELECT id, org_id, user_id, expires_at, accepted_at FROM invitations WHERE token_hash = th $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentrail_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM sentrail_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO sentrail_app;
GRANT EXECUTE ON FUNCTION auth_lookup(bytea), invitation_lookup(bytea) TO sentrail_app;

CREATE FUNCTION api_key_lookup(p text) RETURNS TABLE(org_id uuid, key_hash bytea, scopes text[])
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS
  $$ SELECT org_id, key_hash, scopes FROM api_keys WHERE prefix = p AND revoked_at IS NULL $$;
GRANT EXECUTE ON FUNCTION api_key_lookup(text) TO sentrail_app;

CREATE FUNCTION user_org_lookup(u uuid) RETURNS TABLE(org_id uuid) LANGUAGE sql SECURITY DEFINER
  SET search_path = public AS $$ SELECT org_id FROM users WHERE id = u $$;
GRANT EXECUTE ON FUNCTION user_org_lookup(uuid) TO sentrail_app;
