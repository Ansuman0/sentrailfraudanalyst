# Deploying to Google Cloud from GitHub

Status: **written, not yet run.** Terraform validates (`terraform validate`), the deploy script passes `bash -n` and the workflow is
valid YAML; nothing has been applied to a real GCP project or executed by GitHub Actions. Expect small fixes on the first run.
It mirrors [DEPLOYMENT_AWS.md](DEPLOYMENT_AWS.md): same images, same compose files, same version/rollback behaviour.

```
GitHub (main, manual run) ─ plan ─ test ─ build ─┬─ sentrail-api  ─┐
                                                 └─ sentrail-web  ─┴─▶ Artifact Registry
                  deploy job ── Workload Identity Federation ──▶ IAP SSH ──▶ GCE VM
                                                        scripts/deploy-gcp.sh: pull, recreate changed services
GCE VM (Ubuntu 22.04, Docker): Caddy :80/:443 ─▶ web | api | keycloak      Postgres + data volumes on the boot disk
```

Default size: `e2-standard-2` (2 vCPU, **8 GB RAM**) with a **30 GB** `pd-balanced` boot disk. Both are variables
(`machine_type`, `boot_disk_gb`). 30 GB is tight for Postgres plus Docker images: watch `df -h` and grow the disk before it fills.

## Files

| File | Purpose |
|---|---|
| `infra/gcp/*.tf`, `user_data.sh` | VM, static IP, firewall (80/443 public, SSH only from IAP), Artifact Registry, Secret Manager secret, daily snapshots (14 days), Workload Identity Federation and the deploy service account |
| `docker-compose.gcp.yml` | Overlay: run the Artifact Registry images instead of building on the server |
| `scripts/deploy-gcp.sh` | Runs on the VM: reads the secret, validates it, pulls, starts, health-checks, records versions |
| `.github/workflows/deploy-gcp.yml` | Test, build, push, deploy, roll back, list versions (manual run; the push trigger is commented out) |
| `.github/workflows/ci.yml` | Tests, reused by the deploy workflow (cloud-neutral) |

## One-time setup

### 1. GCP resources (Terraform, `infra/gcp/`)
Needs Terraform ≥ 1.5 and credentials with Owner (or equivalent) on the project for this one step (`gcloud auth application-default login`).
```
cd infra/gcp
cp terraform.tfvars.example terraform.tfvars      # set project_id (and dns_zone_name if DNS is in Cloud DNS)
terraform init && terraform validate && terraform plan
terraform apply
terraform output github_variables
terraform output static_ip
```
The VM has `deletion_protection` on and its boot disk is kept if the VM is deleted: the database lives there.

### 2. The production `.env` goes into Secret Manager
Build it as described in [DEPLOYMENT_AWS.md](DEPLOYMENT_AWS.md) step 2 (same required values; fresh passwords and keys, `ENV=production`,
public https URLs, no `CADDYFILE=` line, never your laptop's `.env`), then:
```
gcloud secrets versions add sentrail-prod-env --data-file=prod.env --project <project>
```
Delete `prod.env` afterwards. Back up the data keys separately: losing them makes the encrypted data unreadable.

### 3. GitHub settings
Settings → Secrets and variables → Actions → **Variables** (nothing secret; no GCP keys are stored in GitHub):

| Variable | Value |
|---|---|
| `GCP_PROJECT`, `GCP_REGION`, `GCP_ZONE`, `GCP_VM`, `GCP_REGISTRY`, `GCP_SECRET_ID`, `GCP_DEPLOY_SA`, `GCP_WIF_PROVIDER` | from `terraform output github_variables` |
| `API_URL` | `https://api.sentrail.qatech.world` (baked into the web image; used by the smoke test) |
| `APP_URL` | `https://sentrail.qatech.world` |

Create the Environment `production` (optionally with required reviewers). The provider only accepts tokens from `main` of
`var.github_repo` (default `Rajanbadri07/sentrail`: change it if the repository lives elsewhere).

### 4. DNS
Three A records (`sentrail`, `api.sentrail`, `auth.sentrail` on `qatech.world`) → `terraform output static_ip`, in place **before** the first deploy
(Caddy gets the Let's Encrypt certificates itself; ports 80/443 are open). Details and cautions: step 4 of [DEPLOYMENT_AWS.md](DEPLOYMENT_AWS.md).

### 5. First deploy
Actions → **deploy-gcp** → Run workflow → `service = both`, `action = deploy` (15–25 minutes). Sandbox only: re-run with `seed_demo` (needs `ENV=dev`).
Check `https://sentrail.qatech.world`, `https://api.sentrail.qatech.world/readyz` and the Keycloak discovery URL.

## Using it
Same as AWS: deploy `both`/`backend`/`frontend`, `rollback` (empty version = previous), `list-versions`. History is on the VM in
`/opt/sentrail/versions/{api,web}` (last 20). Rollbacks never touch the database; roll the backend back only to a version that works with the current schema.
To deploy on every push to `main`, uncomment the `push:` trigger in `deploy-gcp.yml` after the first manual run works.

## Operating it
- Shell, no public SSH: `gcloud compute ssh sentrail --zone <zone> --tunnel-through-iap`, then
  `cd /opt/sentrail && sudo docker compose --env-file .env --env-file .deploy.env -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.gcp.yml logs -f api`.
- Running versions: `cat /opt/sentrail/.deploy.env` (never `.env`).
- Backups: daily disk snapshots (14 days). Add `infra/postgres/backup.sh` for logical, encrypted dumps before real data.
- Ollama and the observability stack are not deployed (see the AWS doc for AI drafts).

## Known limits
One VM, one Postgres on its disk, no high availability (move to Cloud SQL and Cloud Run/GKE when uptime matters); a deploy recreates the `api`
container (a few seconds of downtime); never run end to end; `snap install google-cloud-cli` on first boot needs internet access from the VM.
