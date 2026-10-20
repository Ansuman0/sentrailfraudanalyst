-- Runs once when the Postgres container is first created (as the bootstrap superuser).
-- Sentrail and Keycloak get separate databases and separate owners.
CREATE ROLE sentrail_owner LOGIN CREATEROLE PASSWORD 'replaced-by-01_set_passwords.sh';
CREATE DATABASE sentrail OWNER sentrail_owner;
-- Owns the sign-in lookup functions. Bypasses row-level security, can't log in,
-- and is granted SELECT on only the columns those lookups read (migrations/004).
CREATE ROLE sentrail_auth NOLOGIN BYPASSRLS;
GRANT sentrail_auth TO sentrail_owner;
CREATE ROLE keycloak LOGIN PASSWORD 'replaced-by-01_set_passwords.sh';
CREATE DATABASE keycloak OWNER keycloak;
\c sentrail
GRANT ALL ON SCHEMA public TO sentrail_owner;
