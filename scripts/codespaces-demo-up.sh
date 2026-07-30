#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Always refresh runtime configuration. GitHub injects newly added or rotated
# Codespaces secrets into this process even when .env.codespaces already exists.
bash scripts/codespaces-demo-prepare.sh

if [[ ! -s .codespaces-secrets/cloudflare-tunnel-token ]]; then
  echo "Cloudflare Tunnel token is missing. Add CLOUDFLARE_TUNNEL_TOKEN as a Codespaces secret and rebuild."
  exit 1
fi

# The verified adapters live outside the repository so they survive rebuilds
# and are never committed. Mount them for metadata validation even while the
# GPU endpoint is intentionally left unconfigured.
export ADAPTER_RUNTIME_ROOT="${ADAPTER_RUNTIME_ROOT:-/workspaces/prewise-qwen35-9b-four-adapters/runtime}"
export ADAPTER_MANIFEST_PATH="${ADAPTER_MANIFEST_PATH:-/app/server/adapters/qwen35-backend-manifest.json}"

docker compose \
  --env-file .env.codespaces \
  -f docker-compose.production.yml \
  -f docker-compose.codespaces.yml \
  up -d --build --remove-orphans

# nginx resolves Docker service names when its worker starts. Recreate it after
# backend so a backend container replacement cannot leave a stale upstream IP.
docker compose \
  --env-file .env.codespaces \
  -f docker-compose.production.yml \
  -f docker-compose.codespaces.yml \
  up -d --force-recreate --no-deps api-gateway

echo "Waiting for the Prewise API..."
for attempt in {1..60}; do
  if curl --fail --silent http://127.0.0.1:8000/v1/health >/dev/null; then
    break
  fi
  if [[ "$attempt" == "60" ]]; then
    docker compose --env-file .env.codespaces -f docker-compose.production.yml -f docker-compose.codespaces.yml ps
    echo "Backend did not become healthy in time."
    exit 1
  fi
  sleep 5
done

echo "Waiting for the Prewise web app..."
for attempt in {1..60}; do
  if curl --fail --silent http://127.0.0.1:3000/ >/dev/null; then
    break
  fi
  if [[ "$attempt" == "60" ]]; then
    docker compose --env-file .env.codespaces -f docker-compose.production.yml -f docker-compose.codespaces.yml ps
    echo "Web app did not become ready in time."
    exit 1
  fi
  sleep 5
done

docker compose --env-file .env.codespaces -f docker-compose.production.yml -f docker-compose.codespaces.yml ps
echo "Prewise is running through the named Cloudflare Tunnel."
