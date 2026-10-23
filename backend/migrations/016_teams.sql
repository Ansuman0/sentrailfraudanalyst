-- Access model v2, phase 8: teams and queues (optional, behind the TEAMS flag). Reversible: migrations/down/016_teams.sql.
SELECT set_config('app.platform', 'on', true);

CREATE TABLE teams (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);
CREATE TABLE team_members (
  team_id uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  PRIMARY KEY (team_id, user_id)
);
CREATE INDEX ON team_members (org_id, user_id);
ALTER TABLE alerts ADD COLUMN team_id uuid REFERENCES teams(id) ON DELETE SET NULL;   -- the queue an alert sits in (never widens who can see it)
CREATE INDEX ON alerts (org_id, team_id);

DO $$
DECLARE t text; pred text;
BEGIN
  FOREACH t IN ARRAY ARRAY['teams','team_members'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    pred := $q$(org_id = NULLIF(current_setting('app.org_id', true), '')::uuid AND actor_may_access(org_id))$q$;
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING %s WITH CHECK %s', t, pred, pred);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON teams, team_members TO sentrail_app;
