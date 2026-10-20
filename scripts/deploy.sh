#!/bin/bash
# Runs ON the EC2 host (started by the GitHub deploy workflow through AWS Systems Manager). Not for laptops.
# Inputs (environment): ECR_REGISTRY, AWS_REGION, SECRET_ID, and per service API_TAG / WEB_TAG:
#   ""        keep the version that is running now
#   previous  go back to the version before the current one (rollback)
#   <tag>     deploy or roll back to exactly this image tag (a commit SHA)
# Optional SEED_DEMO=1. Never prints .env: its values are secrets.
# Version history per service: /opt/sentrail/versions/{api,web}, one tag per line, last line = running version.
set -euo pipefail
cd /opt/sentrail
: "${ECR_REGISTRY:?}" "${AWS_REGION:?}" "${SECRET_ID:?}"
export AWS_DEFAULT_REGION="$AWS_REGION"
mkdir -p versions; touch versions/api versions/web

fail() { echo "ERROR: $*" >&2; exit 1; }
cur() { tail -n 1 "versions/$1"; }

# resolve <service> <request> -> prints the tag to run
resolve() {
  local svc=$1 req=${2:-} n
  case "$req" in
    "")       cur "$svc" ;;
    previous) n=$(wc -l < "versions/$svc"); [ "$n" -ge 2 ] || fail "no previous $svc version recorded on this host"
              sed -n "$((n-1))p" "versions/$svc" ;;
    *)        echo "$req" ;;
  esac
}
API_NEW=$(resolve api "${API_TAG:-}"); WEB_NEW=$(resolve web "${WEB_TAG:-}")
[ -n "$API_NEW" ] && [ -n "$WEB_NEW" ] || fail "first deploy must include both services (choose service = both)"
echo "== backend: $(cur api || true) -> $API_NEW | frontend: $(cur web || true) -> $WEB_NEW"

echo "== fetching .env from Secrets Manager ($SECRET_ID)"
umask 077
aws secretsmanager get-secret-value --secret-id "$SECRET_ID" --query SecretString --output text > .env.new

# Refuse a configuration that would deploy a broken or unsafe stack.
val() { grep -E "^$1=" .env.new | tail -1 | cut -d= -f2- | sed 's/[[:space:]]*#.*$//; s/[[:space:]]*$//'; }
for k in ENV APP_URL API_URL KEYCLOAK_URL ACME_EMAIL POSTGRES_SUPERUSER_PASSWORD SENTRAIL_OWNER_PASSWORD APP_DB_PASSWORD \
         KEYCLOAK_DB_PASSWORD KEYCLOAK_CLIENT_SECRET KEYCLOAK_ADMIN_CLIENT_SECRET KEYCLOAK_ADMIN_USER KEYCLOAK_ADMIN_PASSWORD; do
  [ -n "$(val $k)" ] || { rm -f .env.new; fail "$k is empty in the secret"; }
done
case "$(val APP_URL)$(val API_URL)$(val KEYCLOAK_URL)" in *localhost*|*127.0.0.1*|*http://*)
  rm -f .env.new; fail "APP_URL / API_URL / KEYCLOAK_URL must be public https URLs";; esac
if grep -qE '^CADDYFILE=.*local' .env.new; then rm -f .env.new; fail "CADDYFILE points at the local-certificate file"; fi
mv .env.new .env

printf 'ECR_REGISTRY=%s\nAPI_TAG=%s\nWEB_TAG=%s\n' "$ECR_REGISTRY" "$API_NEW" "$WEB_NEW" > .deploy.env

if [[ "$ECR_REGISTRY" == *"amazonaws.com"* ]]; then
  echo "== logging in to AWS ECR, pulling images"
  aws ecr get-login-password | docker login --username AWS --password-stdin "$ECR_REGISTRY" >/dev/null
else
  echo "== pulling images from registry: $ECR_REGISTRY (Docker Hub or custom)"
fi
DC=(docker compose --env-file .env --env-file .deploy.env -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.aws.yml)
SERVICES=(postgres migrate keycloak api web caddy)       # not openbao/ollama/observability: see docs/DEPLOYMENT_AWS.md
"${DC[@]}" pull api web migrate

echo "== starting (only services whose image changed are recreated; migrations run before the API)"
"${DC[@]}" up -d --no-build --remove-orphans "${SERVICES[@]}"

rollback_on_failure() {
  local failed_svc=$1
  echo "CRITICAL: $failed_svc failed to become healthy or crashed after deploy!" >&2
  "${DC[@]}" logs --tail 80 "$failed_svc"
  local prev_api; prev_api=$(resolve api previous 2>/dev/null || true)
  local prev_web; prev_web=$(resolve web previous 2>/dev/null || true)
  if [ -n "$prev_api" ] || [ -n "$prev_web" ]; then
    echo "== AUTO-RECOVERY: Reverting to last known working version (api: ${prev_api:-$API_NEW}, web: ${prev_web:-$WEB_NEW}) ==" >&2
    printf 'ECR_REGISTRY=%s\nAPI_TAG=%s\nWEB_TAG=%s\n' "$ECR_REGISTRY" "${prev_api:-$API_NEW}" "${prev_web:-$WEB_NEW}" > .deploy.env
    "${DC[@]}" pull api web 2>/dev/null || true
    "${DC[@]}" up -d --no-build --remove-orphans "${SERVICES[@]}"
    echo "Auto-recovery deployed previous healthy containers." >&2
  fi
  exit 1
}

wait_healthy() {   # <service>
  local cid s i; cid=$("${DC[@]}" ps -q "$1")
  for i in $(seq 1 60); do
    s=$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo starting)
    [ "$s" = healthy ] && return 0
    sleep 5
  done
  echo "ERROR: $1 not healthy after 5 minutes" >&2
  return 1
}
wait_healthy api || { "${DC[@]}" logs --tail 80 migrate; rollback_on_failure api; }
wait_healthy web || rollback_on_failure web
curl -fsS http://127.0.0.1:8000/readyz >/dev/null && echo "readyz OK"

if [ "${SEED_DEMO:-0}" = 1 ]; then
  [ "$(val ENV)" = dev ] || fail "SEED_DEMO needs ENV=dev in the secret"
  "${DC[@]}" exec -T api python -m scripts.seed --demo > /dev/null && echo "demo data seeded (credentials not printed)"
fi

# Record the versions only now that they are healthy. A rollback to "previous" drops the version it leaves, so a second
# rollback keeps going back instead of flipping between two versions.
record() {   # <service> <tag> <requested>
  local f="versions/$1" n
  if [ "$3" = previous ]; then n=$(wc -l < "$f"); head -n $((n-1)) "$f" > "$f.tmp"; mv "$f.tmp" "$f"
  elif [ "$(cur "$1")" != "$2" ]; then echo "$2" >> "$f"; fi
  tail -n 20 "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}
record api "$API_NEW" "${API_TAG:-}"; record web "$WEB_NEW" "${WEB_TAG:-}"
docker image prune -f >/dev/null
echo "== running now: backend $(cur api), frontend $(cur web)"
