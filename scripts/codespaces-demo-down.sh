#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
docker compose \
  --env-file .env.codespaces \
  -f docker-compose.production.yml \
  -f docker-compose.codespaces.yml \
  down
