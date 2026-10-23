-- Reverts 015_governance_and_data_controls.sql. SCIM tokens and groups, access reviews, streams and export links are lost.
SELECT set_config('app.platform', 'on', true);
DROP FUNCTION purge_tenant_audit(uuid);
DROP FUNCTION scim_token_lookup(text);
DROP TABLE job_runs, user_countries, export_links, audit_streams, access_review_items, access_reviews, scim_group_members, scim_groups, scim_tokens;
ALTER TABLE users DROP COLUMN scim_external_id;
ALTER TABLE tenant_memberships DROP COLUMN reactivated_at;
ALTER TABLE security_settings DROP COLUMN dormant_days, DROP COLUMN access_review_days, DROP COLUMN export_limit_per_hour,
  DROP COLUMN anomaly_searches_per_hour, DROP COLUMN anomaly_exports_per_hour, DROP COLUMN alert_new_country;
DELETE FROM org_features WHERE feature IN ('scim','audit_streaming');
ALTER TABLE org_features DROP CONSTRAINT org_features_feature_check;
ALTER TABLE org_features ADD CONSTRAINT org_features_feature_check CHECK (feature IN ('screening','alerts','ai','trace','statements','export'));
UPDATE plans SET features = array_remove(array_remove(features, 'scim'), 'audit_streaming');
