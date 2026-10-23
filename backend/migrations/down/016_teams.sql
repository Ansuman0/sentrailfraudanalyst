-- Reverts 016_teams.sql. Teams and queue assignments are lost.
SELECT set_config('app.platform', 'on', true);
ALTER TABLE alerts DROP COLUMN team_id;
DROP TABLE team_members, teams;
