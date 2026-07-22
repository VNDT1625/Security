#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [[ ! -f .env.codespaces ]]; then
  bash scripts/codespaces-demo-prepare.sh
fi

if [[ ! -s .codespaces-secrets/cloudflare-tunnel-token ]]; then
  echo "Cloudflare Tunnel token is missing. Add CLOUDFLARE_TUNNEL_TOKEN as a Codespaces secret and rebuild."
  exit 1
fi

docker compose \
  --env-file .env.codespaces \
  -f docker-compose.production.yml \
  -f docker-compose.codespaces.yml \
  up -d --build --remove-orphans

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

curl --fail --silent http://127.0.0.1:3000/ >/dev/null
docker compose --env-file .env.codespaces -f docker-compose.production.yml -f docker-compose.codespaces.yml ps
echo "Prewise is running through the named Cloudflare Tunnel."
