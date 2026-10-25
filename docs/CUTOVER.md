# Cut-over to the access model v2

How to move a live Sentrail database (the AWS demo today) from the old single-role model to memberships, and how to back out. Written for the
person running the deployment. **Nothing in this file has been done to the live database yet.** The code is on branch `access-v2/phase-1` and
the migrations (009 to 018) have only ever run on local and test databases.

## What changes

| | Before | After |
|---|---|---|
| Who someone is and what they can do | one organization and one role per person (`users.org_id`, `users.role_id`) | a **membership** per organization (role and status each) and a platform staff row for Sentrail staff; `users.role_id` no longer exists |
| Roles | Organization admin, Platform admin ... | locked **Tenant admin**, Compliance officer / analyst, Auditor; one **Platform owner** (Platform admin is merged into it), support, auditor |
| Permissions | mixed names, no step-up | one catalogue (19 tenant + 10 platform permissions), step-up flags, no aliases |
| Sign-in | one organization per account | one sign-in, a tenant picker when someone belongs to several, step-up for sensitive actions |
| Database | row-level security by organization | + membership checks, restricted cases, owner access sessions |
| Containers | api, web, postgres, keycloak ... | + **worker** (background jobs) |
| Migrations | 001 to 008 | **009 to 018**, all reversible (`python -m scripts.migrate --down`, last one first) |

Things people will notice: analysts no longer override held screenings (a deliberate template change), Platform admins become Platform owners,
API keys, security settings and email reveal are separate permissions (granted to everyone who could use `users.manage`, so nobody loses access),
two-factor is mandatory for Tenant admins and for every platform person except the break-glass owner.

## Before you start

1. **A backup you have restored at least once.** An EBS snapshot of the data volume *and* a logical dump:
   `pg_dump -Fc -h 127.0.0.1 -p <forwarded port> -U sentrail_owner sentrail > sentrail-before-cutover.dump` (Session Manager port-forward, see
   [DEPLOYMENT_AWS.md](DEPLOYMENT_AWS.md)). Keep both until the cut-over has been quiet for a week.
2. **Decide the sign-in mode.** If `AUTH_MODE=keycloak` is still set in Secrets Manager (`sentrail/prod/env`) the demo users were created in Keycloak;
   they keep working. To move to the local password + TOTP sign-in the demo uses elsewhere, set `AUTH_MODE=local`, then re-seed the demo people with a
   password you choose (`python -m scripts.seed --demo`, with `SEED_DEMO_PASSWORD` in your shell, never in a file).
3. **Environment.** Nothing is mandatory. Optional: `TEAMS=true` (teams and queues), `TRUST_COUNTRY_HEADER=true` (only behind a proxy that sets
   `CF-IPCountry`), `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGINS` (default to `APP_URL`).
4. A quiet window of about 30 minutes. The migrations take seconds; the point is to be able to look.

## Rehearse on a copy (do this first)

Goal: prove the migrations and the checks on **your real data** before touching the live database.

```
# 1. restore the dump into a scratch database, KEEPING the object owners (the sign-in lookups belong to sentrail_auth: restoring them as
#    another owner makes them blind). On the project's compose postgres, as the superuser:
psql -h 127.0.0.1 -U sentrail_owner -c "CREATE ROLE sentrail_app LOGIN"       # (only on a server that has never run the app: migration 001 normally creates it)
psql -h 127.0.0.1 -U postgres -c "CREATE DATABASE sentrail_rehearsal OWNER sentrail_owner"
pg_restore -h 127.0.0.1 -U postgres -d sentrail_rehearsal sentrail-before-cutover.dump

# 2. migrate it exactly as the deployment will
cd backend
OWNER_DATABASE_URL=postgresql://sentrail_owner:...@127.0.0.1/sentrail_rehearsal python -m scripts.migrate

# 3. check it (read-only; prints no personal data, needs no encryption keys)
DATABASE_URL=postgresql://sentrail_app:...@127.0.0.1/sentrail_rehearsal python -m scripts.cutover_check
```
Do **not** copy the production encryption keys to your machine for this. Without them the people and cases in the copy can't be decrypted
locally (a Users list over the old demo organizations answers an error: that is expected); everything the check and the migrations do works on
the stored structure. Sign-in on the copy works for people created locally (for example `python -m scripts.seed --demo --replace`).

`cutover_check` confirms: every migration applied; every person has a place (membership or platform staff row); every active organization has an
active Tenant admin; at least one active Platform owner; at most one break-glass account; no retired permission or role; locked roles hold every
permission; **every audit chain (platform and each organization) still verifies**. Any FAIL is a reason to stop and read the message: migration 018
itself refuses to run if a person would lose their role.

Then, still on the copy: start the API against it, sign in as a Tenant admin and an owner, open Users, Roles, Access reviews, Organizations, and
run `python -m scripts.run_jobs` once. Try the way back too: `python -m scripts.migrate --down` repeatedly (it reverts one migration per call, newest
first, 018 down to 009), `cutover_check` is not expected to pass on an old schema; check that sign-in works on the old code, then migrate forward again.

## The cut-over

1. Tell people there will be a short interruption. Take the snapshot and dump (above) now, not earlier.
2. Merge `access-v2/phase-1` into `main` and push. The deploy workflow builds the images, runs `docker compose run --rm migrate` (migrations 009 to 018
   and the permission catalogue sync), and starts the api, web and the new **worker**.
3. Check, in this order:
   * `docker compose logs migrate` ends with `database is up to date`;
   * `docker compose exec api python -m scripts.cutover_check` prints `ALL CHECKS PASSED`;
   * sign in as a Tenant admin (two-factor), as a Compliance analyst, and as a Platform owner; open one screen of each;
   * `GET /readyz` is healthy and `docker compose ps` shows the worker running; after five minutes `job_runs` has a row per job.
4. **Owners: register a passkey** (Sentrail asks at next sign-in). Only when every owner has one, turn on *passkeys only for platform staff* under
   Security baseline (it is off by default so nobody is locked out).
5. Create the break-glass account if there is none (`python -m scripts.create_break_glass`, see [RUNBOOK_ACCESS.md](RUNBOOK_ACCESS.md)).
6. Demo people: the common demo password is in `.demo-credentials.txt` (git-ignored, not on the server). Apply it with
   `docker compose ... exec -T -e SEED_DEMO_PASSWORD=<the password> api python -m scripts.seed --demo --replace` (the secret needs `ENV=dev`
   for demo seeding). `--replace` deletes the existing demo people (and their Keycloak users in Keycloak mode) and creates them again with that
   password and the same roles; the organizations and their data stay. Everyone except the platform owner sets up two-factor at first sign-in.
   If you also choose `AUTH_MODE=local`, set it in Secrets Manager and redeploy before running this.

## Backing out

| Situation | Do |
|---|---|
| The migration step failed | The deployment stops before the new containers start (migrations run in one transaction each). Fix forward on the rehearsal copy, or redeploy the previous image tag; the database is either untouched or at a migration boundary. |
| Something is wrong within the first hour and almost nothing new was created | Redeploy the previous image tag, then `python -m scripts.migrate --down` from the **new** image until it reports `schema_migrations is back at 008...` (018 first). People keep their roles (018's down fills `users.role_id` back from the memberships). New things made since (access reviews, SCIM tokens, teams ...) are lost. |
| Anything else | Restore the snapshot taken in step 1 and redeploy the previous image tag. You lose everything written since. |

## After a quiet week

Delete the snapshot and dump (they hold personal data). Nothing else is left to remove: the flag, the aliases and the old role column are already
gone from the code (commits on the branch, one per step, so any of them can be reviewed or reverted on its own).

## Checklist

| Done | Item |
|---|---|
| [ ] | snapshot + dump taken and a restore of the dump tried |
| [ ] | rehearsal on a copy: migrate, `cutover_check`, sign-in, way back |
| [ ] | merged and deployed; `migrate` log clean |
| [ ] | `cutover_check` passes on production |
| [ ] | each role signed in once; worker running; `job_runs` filling |
| [ ] | owners registered passkeys; passkey-only switched on |
| [ ] | break-glass created and sealed |
| [ ] | demo people re-seeded with a chosen password (if `AUTH_MODE` changed) |
