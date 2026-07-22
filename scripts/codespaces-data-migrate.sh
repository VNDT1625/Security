#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [[ ! -s .aisec-data/armor.db ]]; then
  echo "Upload the existing database to .aisec-data/armor.db first."
  exit 1
fi

docker compose --env-file .env.codespaces -f docker-compose.production.yml up -d postgres
docker compose --env-file .env.codespaces -f docker-compose.production.yml run --rm migrate
docker compose --profile data-migration --env-file .env.codespaces -f docker-compose.production.yml run --rm data-migrate
echo "Existing SQLite data has been copied and verified in PostgreSQL."
