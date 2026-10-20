# Hosting on qatech.world (AWS or GCP)

Every public name starts with `sentrail` and ends with `qatech.world`.

| Name | Serves | Port behind the load balancer |
|---|---|---|
| `sentrail.qatech.world` | React app (the `web` image) | 80 |
| `api.sentrail.qatech.world` | FastAPI (`api` image) | 8000 |
| `auth.sentrail.qatech.world` | Keycloak | 8080 |
| `sentrail.qatech.world` (mail records only) | Outgoing email, `no-reply@sentrail.qatech.world` | |

The web app and the API are the same site (`qatech.world`), so the refresh cookie and CORS work across them.
Postgres, OpenBao and Ollama stay private: no DNS name, no public IP.

## Hosting on one VM with Docker (your plan)

Any VM works (AWS EC2, GCP Compute Engine, a VPS): Ubuntu 22.04+, 4 vCPU / 8 GB RAM minimum (more if you run Ollama),
Docker with the compose plugin.

1. **DNS.** At the place `qatech.world` is managed, add three A records to the VM's public IP:
   `sentrail`, `api.sentrail` and `auth.sentrail` (so `sentrail.qatech.world`, `api.sentrail.qatech.world`,
   `auth.sentrail.qatech.world`). No load balancer or cloud certificate is needed.
2. **Firewall.** Allow 80 and 443 (and 22 from your IP only). Nothing else: Postgres, OpenBao and the other services are
   bound to `127.0.0.1` or the Docker network.
3. **Config.** Copy the project to the VM, create `.env` from `.env.example` with the production block (section 1) and
   `ACME_EMAIL=you@yourmail`. Generate every password and key fresh on the VM (`python -m scripts.dev_env`, or by hand);
   do not copy your laptop's `.env`.
4. **Start.**
   ```
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   ```
   [docker-compose.prod.yml](../docker-compose.prod.yml) adds Caddy ([infra/caddy/Caddyfile](../infra/caddy/Caddyfile)),
   which gets the Let's Encrypt certificates itself, plus Keycloak production mode behind the proxy and restart policies.
5. **Seed.** Sandbox: set `ENV=dev` in `.env` so `--demo` is allowed, then run
   `docker compose exec api python -m scripts.seed --demo` once. That creates the master login
   (`owner@sentrail.qatech.world`) and the demo users with `SEED_ADMIN_PASSWORD` / `SEED_DEMO_PASSWORD`. With `ENV=dev` the API
   serves `/docs` and returns invite links in responses; fine for a sandbox, not for real data. For a real environment use
   `ENV=production` and seed the master login only (no `--demo`).
6. **Check** with section 5 below. If a certificate isn't issued, `docker compose logs caddy` usually shows DNS not yet
   pointing at the VM.

Sandbox: the dev-mode `openbao` and keys in `.env` are acceptable. Before real data, run OpenBao properly (set the
`SENTRAIL_WRAPPED_*` keys) and back up the `pgdata` volume and `backend/data/`.

## 1. App settings

In the production `.env` (or the cloud secret store):

```
ENV=production
APP_URL=https://sentrail.qatech.world
API_URL=https://api.sentrail.qatech.world
KEYCLOAK_URL=https://auth.sentrail.qatech.world
MAIL_FROM=no-reply@sentrail.qatech.world
```

`docker-compose.yml` passes these on: `KC_HOSTNAME` is `KEYCLOAK_URL`, the Keycloak client redirect URI is
`API_URL/auth/oidc/callback`, and the allowed web origin is `APP_URL`. The web image bakes `API_URL` in at build time,
so build it after setting the value. Never run `--demo` seed in production.

## 2. Point DNS at the host

Where the domain's DNS lives decides the first step:

- **Domain registered elsewhere (GoDaddy, Namecheap, ...):** create a hosted zone for `qatech.world` in the cloud you pick,
  then change the registrar's nameservers to the four the cloud gives you. Or keep DNS at the registrar and add the
  records below there.
- **AWS:** Route 53 hosted zone. **GCP:** Cloud DNS managed zone.

Records (all three names point at the same load balancer, which routes by host name):

| Type | Name | Value |
|---|---|---|
| A / AAAA alias (Route 53) or A (Cloud DNS) | `sentrail.qatech.world` | load balancer |
| same | `api.sentrail.qatech.world` | load balancer |
| same | `auth.sentrail.qatech.world` | load balancer |

If the registrar only allows CNAME, use `CNAME api.sentrail -> <load balancer DNS name>`; the bare `sentrail.qatech.world`
is a subdomain too, so a CNAME works there as well.

## 3. HTTPS certificate

One certificate covering `sentrail.qatech.world` and `*.sentrail.qatech.world`.

- **AWS:** ACM in the same region as the load balancer (us-east-1 if you use CloudFront). Validate by DNS; with Route 53
  it is one click.
- **GCP:** Google-managed certificate on the HTTPS load balancer (or Certificate Manager for the wildcard), DNS-validated.

## 4. Run the services

| | AWS | GCP |
|---|---|---|
| Containers | ECS Fargate (or EC2 with compose) | Cloud Run (or GCE with compose) |
| Front door | Application Load Balancer, host-based rules to the three target groups | External HTTPS load balancer, URL map by host |
| Database | RDS PostgreSQL 16, `sslmode=verify-full` | Cloud SQL PostgreSQL 16 |
| Secrets | Secrets Manager | Secret Manager |
| Keys | OpenBao transit (keep the `SENTRAIL_WRAPPED_*` keys, leave the dev keys empty) | same |

Open only 443 to the internet. Keycloak needs `KC_PROXY_HEADERS=xforwarded` (or the proxy setting of your Keycloak version)
because TLS ends at the load balancer. Check that after the first deploy; it is untested here.

## 5. Check

1. `https://sentrail.qatech.world` loads and `https://api.sentrail.qatech.world/readyz` returns OK.
2. Sign in; the refresh cookie is `Secure` and kept after a reload.
3. `https://auth.sentrail.qatech.world/realms/sentrail/.well-known/openid-configuration` lists that issuer.
4. Email: add SPF, DKIM (from your mail provider, SES or similar) and a DMARC record for `sentrail.qatech.world`,
   or invitation emails land in spam.

## Not done yet

Terraform and a GitHub Actions pipeline for AWS now exist ([DEPLOYMENT_AWS.md](DEPLOYMENT_AWS.md)), but nothing here has been deployed or tested against a real cloud.

## Run on Docker Desktop with the domain (local)

1. As Administrator, add this line to `C:\Windows\System32\drivers\etc\hosts`:
   `127.0.0.1 sentrail.qatech.world api.sentrail.qatech.world auth.sentrail.qatech.world`
2. In `.env`: `APP_URL`, `API_URL`, `KEYCLOAK_URL` as in section 1 and `CADDYFILE=./infra/caddy/Caddyfile.local`
   (Caddy's own certificate authority; the refresh cookie is `Secure`, so the app needs HTTPS even locally).
3. `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build postgres migrate keycloak api web caddy`,
   then `docker compose exec api python -m scripts.seed --demo`.
4. Open https://sentrail.qatech.world. The browser warns about the certificate until you trust Caddy's root:
   `docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .` and import it into "Trusted Root Certification Authorities".
