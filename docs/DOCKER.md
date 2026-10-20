# Docker

`docker-compose.yml` services: `postgres` (16, healthcheck, volume `pgdata`, init scripts in `infra/postgres/init`), `migrate`
(one-shot `python -m scripts.migrate`), `keycloak` (26.0, `start-dev --import-realm`, realm in `infra/keycloak/`),
`openbao` (dev mode only), `ollama` (volume `ollama`), `api` (built from `backend/Dockerfile`).

The API image: Python 3.11-slim, non-root user (uid 10001), no `.env` in the image (`.dockerignore`), read-only root
filesystem with `/tmp` as tmpfs, `no-new-privileges`, healthcheck on `/readyz`. Ports bind to `127.0.0.1` only.

```bash
docker compose up -d postgres              # what local development needs
docker compose up -d --build               # everything (needs a filled .env: python -m scripts.dev_env)
docker compose ps
docker compose logs -f api
docker compose restart api
docker compose stop                        # stop, keep data
docker compose down -v                     # stop AND delete database/model volumes
docker compose exec ollama ollama pull qwen2.5:14b
```

`web` (added 2026-10-17; built and run 2026-10-17: healthy, non-root uid 101, read-only filesystem, deep links fall back to the app, assets cached immutably): `frontend/Dockerfile` builds with Node 20 and serves with unprivileged nginx
(non-root, port 8080 published as `127.0.0.1:5173`, read-only, CSP `connect-src` set from `API_URL`). `VITE_API_BASE_URL`
is baked in at build time from `API_URL`. `APP_URL` must stay `http://localhost:5173`. Stop `npm run dev` first (same port). The image renders its nginx config from `nginx.conf.template` at start-up, so `/etc/nginx/conf.d` is a tmpfs owned by uid 101 (a root-owned tmpfs made the container serve nothing).

Observability profile (`loki`, `alloy`, `grafana`, written 2026-10-17, **never started**): `docker compose --profile observability up -d`;
see [OBSERVABILITY.md](OBSERVABILITY.md). Alloy mounts the Docker socket read-only (dev only).

Not done yet: pinned `openbao`/`ollama` tags (K-06), a production Keycloak (`start --optimized`
behind TLS), (K-01: the observability profile is untested). The full stack has not been run end to end in this environment (K-09).
