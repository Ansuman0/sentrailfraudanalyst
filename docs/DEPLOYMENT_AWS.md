# Deploying to AWS from GitHub

Status: **written, not yet run.** Nothing here has been applied to a real AWS account or executed by GitHub Actions
(K-12 in [memory/KNOWN_ISSUES.md](../memory/KNOWN_ISSUES.md)). Expect to fix small things on the first run.

```
GitHub (main) ─ plan ─ test ─ build ─┬─ sentrail-api  ─┐
                                     └─ sentrail-web  ─┴─▶ Amazon ECR
                      deploy job ── OIDC role ──▶ S3 (compose bundle) + SSM Run Command ──▶ EC2 host
                                                          scripts/deploy.sh: pull from ECR, recreate changed services
EC2 host (Ubuntu, Docker): Caddy :80/:443 ─▶ web | api | keycloak      Postgres, data volumes on the host disk
```

The backend (`sentrail-api`, also runs migrations) and the frontend (`sentrail-web`) are separate images with separate versions.
A version is the commit SHA the image was built from.

## Using it

| You want | Do |
|---|---|
| Deploy what changed | Push to `main`. Only services whose folder changed (`backend/`, `frontend/`) are tested, built and deployed. Changes to compose, `infra/` or `scripts/deploy.sh` alone redeploy what is running, nothing is built. |
| Deploy one service on demand | Actions → **deploy** → Run workflow (branch `main`) → `service` = backend / frontend / both, `action` = deploy |
| See what you can go back to | `action` = **list-versions** → job summary lists the newest images in ECR |
| Roll back one service | `service` = backend (or frontend), `action` = **rollback**, `version` empty → previous version of that service. Repeat to go back further |
| Roll back to a specific version | same, with `version` = a commit SHA from list-versions |
| Approval before production | GitHub → Settings → Environments → `production` → Required reviewers |

The host keeps the last 20 versions per service in `/opt/sentrail/versions/{api,web}`; a version is recorded only after it is healthy.
Rollbacks never touch the database: migrations are forward-only (see [DATABASE.md](DATABASE.md)), so roll the backend back
only to a version that works with the current schema. Frontend rollbacks are always safe.

First deploy must be `service = both` (the host has no history yet).

## One-time setup

### 1. AWS resources (Terraform, `infra/aws/`)
Needs AWS credentials with admin rights for this one step, and Terraform ≥ 1.5.
```
cd infra/aws
cp terraform.tfvars.example terraform.tfvars      # set aws_region; route53_zone_id if the DNS is in Route 53
terraform init && terraform validate && terraform plan
terraform apply
terraform output github_variables
```
Creates: EC2 `t3.large` (Ubuntu 22.04, 60 GB encrypted disk, IMDSv2, no SSH, managed through SSM), Elastic IP, security group
(80 and 443 only), two ECR repositories, a private S3 bucket for deploy bundles, an empty Secrets Manager secret
`sentrail/prod/env`, daily disk snapshots kept 14 days, the GitHub OIDC provider (skip with `create_github_oidc_provider=false`
if your account already has one) and the deploy role. Cost is roughly one `t3.large` plus the disk; stop nothing you don't have to,
the database lives on that disk (termination protection is on).

### 2. The production `.env` goes into Secrets Manager
Build it from [.env.example](../.env.example) on your machine, **not** by copying your laptop's `.env`, then store it:
```
aws secretsmanager put-secret-value --secret-id sentrail/prod/env --secret-string file://prod.env
```
(delete `prod.env` afterwards.) Required values, checked by the deploy script before anything starts:

- `ENV=production` (`dev` only for a sandbox that needs `--demo` data), `AUTH_MODE=keycloak` or `local`
- `APP_URL=https://sentrail.qatech.world`, `API_URL=https://api.sentrail.qatech.world`, `KEYCLOAK_URL=https://auth.sentrail.qatech.world`
- fresh `POSTGRES_SUPERUSER_PASSWORD`, `SENTRAIL_OWNER_PASSWORD`, `APP_DB_PASSWORD`, `KEYCLOAK_DB_PASSWORD`,
  `KEYCLOAK_CLIENT_SECRET`, `KEYCLOAK_ADMIN_CLIENT_SECRET`, `KEYCLOAK_ADMIN_USER`, `KEYCLOAK_ADMIN_PASSWORD`
- `ACME_EMAIL=you@yourmail` (Let's Encrypt contact), `MAIL_FROM`, SMTP settings if you send email
- keys: `python -m scripts.generate_keys` output (`SENTRAIL_DATA_KEYS`, `SENTRAIL_INDEX_KEY`, `SENTRAIL_JWT_PRIVATE_KEY`) for a sandbox;
  real data needs OpenBao transit instead (`BAO_*`, `SENTRAIL_WRAPPED_*`). **Losing the data keys makes the encrypted data unreadable: back them up separately.**
- no `CADDYFILE=` line (that is the local-certificate setting) and no `localhost` URLs. The script refuses both.

Passwords in the secret are used when the Postgres volume is first created; changing them later does not change the database
([LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md) troubleshooting). To change `.env` later, update the secret and run the deploy workflow.

### 3. GitHub settings
Settings → Secrets and variables → Actions → **Variables** (none of these are secret; no AWS keys are stored in GitHub):

| Variable | Value |
|---|---|
| `AWS_REGION`, `AWS_DEPLOY_ROLE_ARN`, `EC2_INSTANCE_ID`, `ECR_REGISTRY`, `DEPLOY_BUCKET`, `SECRET_ID` | from `terraform output github_variables` |
| `API_URL` | `https://api.sentrail.qatech.world` (baked into the web image at build time and used by the smoke test) |
| `APP_URL` | `https://sentrail.qatech.world` |

Settings → Environments → New environment `production` (optionally with required reviewers).
Settings → Branches: protect `main` (require the `ci` checks) so that only tested code reaches the deploy workflow.
The AWS role trusts only this repository's `main` branch and the `production` environment.

### 4. Domain hosting (qatech.world) — what to configure
Public names, all pointing at the **Elastic IP** (`terraform output elastic_ip`):

| Type | Name | Value | TTL |
|---|---|---|---|
| A | `sentrail.qatech.world` | Elastic IP | 300 |
| A | `api.sentrail.qatech.world` | Elastic IP | 300 |
| A | `auth.sentrail.qatech.world` | Elastic IP | 300 |

- **DNS in Route 53:** put the zone ID in `route53_zone_id` and Terraform creates the three records.
- **DNS at the registrar (GoDaddy, Namecheap, …):** add the three A records there. If you added `sentrail` as a subdomain, `api.sentrail`
  and `auth.sentrail` are the host names to enter (the provider appends `.qatech.world`). Nothing else changes (no nameserver change needed).
- **Do not** put the names behind Cloudflare's orange-cloud proxy at first: certificate issuance needs the names to reach the host directly.
- Remove any older records for those names (an AAAA to somewhere else breaks issuance); no CAA records, or allow `letsencrypt.org`.
- Certificates: nothing to configure. Caddy gets and renews Let's Encrypt certificates for the three names by itself, needing ports 80 and 443
  open to the internet and the A records in place **before** the first deploy (check with `nslookup api.sentrail.qatech.world`).
  Let's Encrypt allows 5 failed validations per hour: fix DNS first, then deploy.
- Email (invitations): in the DNS of `qatech.world` add the SPF, DKIM and DMARC records your mail provider (SES or other) gives you,
  or invitations go to spam. Not part of this pipeline.
- Keycloak's redirect URI and the CORS origin come from `API_URL` / `APP_URL` in the secret, so no change in Keycloak is needed when the names match.

### 5. First deploy
1. DNS records in place and resolving (step 4), secret stored (step 2), variables set (step 3).
2. Actions → **deploy** → Run workflow → `service = both`, `action = deploy`. First run takes 15–25 minutes (the API image is large; Keycloak imports its realm).
3. Sandbox only: re-run with `seed_demo` ticked (needs `ENV=dev`) for the master and demo logins. For a real environment keep `ENV=production`, never use `--demo`, and create the master login with the seed script (master only; see the seed section of [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md)).
4. Check: `https://sentrail.qatech.world` loads, `https://api.sentrail.qatech.world/readyz` is OK, sign-in keeps its cookie after a reload,
   and `https://auth.sentrail.qatech.world/realms/sentrail/.well-known/openid-configuration` answers.

## Operating it

- Logs/shell on the host, no SSH: `aws ssm start-session --target <instance id>`, then `cd /opt/sentrail && docker compose --env-file .env --env-file .deploy.env -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.aws.yml logs -f api`.
- What is running: `cat /opt/sentrail/.deploy.env` (never `.env`).
- Backups: daily disk snapshots (14 days) cover Postgres and the API data volume. Restore = new volume from snapshot. Add `infra/postgres/backup.sh` for logical, encrypted dumps before real data.
- Ollama and the observability stack are **not** deployed (the API image is already large). AI drafts need `AI_PROVIDER=openai_compatible` with an https endpoint
  and `AI_ALLOW_EXTERNAL=true` ([AI.md](AI.md)), or a separate GPU host.

## Known limits
- One host, one Postgres on its disk: no high availability. Move to RDS (`sslmode=verify-full`) and ECS/ALB when uptime matters.
- A deploy recreates the `api` container: a few seconds of downtime. No blue/green.
- Not run end to end yet; Keycloak production mode behind Caddy is also untested ([DEPLOYMENT_DNS.md](DEPLOYMENT_DNS.md)).
- `openbao/openbao:latest` and `ollama/ollama:latest` are unpinned in `docker-compose.yml` (K-06); they are not started on AWS.
