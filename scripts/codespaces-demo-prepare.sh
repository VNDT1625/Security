#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
mkdir -p .aisec-backups .codespaces-secrets

if [[ ! -f .env.codespaces ]]; then
  umask 077
  random_secret() {
    openssl rand -hex 32
  }

  cat > .env.codespaces <<EOF
POSTGRES_DB=armor
POSTGRES_USER=armor
POSTGRES_PASSWORD=$(random_secret)
API_KEY_PEPPER=$(random_secret)
API_KEY=$(random_secret)
TELEMETRY_SENSOR_PEPPER=$(random_secret)
BACKEND_PORT=8000
WEB_PORT=3000
MCP_PORT=3001
NEXT_PUBLIC_API_BASE_URL=https://api.prewise.site
NEXT_PUBLIC_WS_BASE_URL=wss://api.prewise.site
CORS_ALLOW_ORIGINS=["https://prewise.site","https://www.prewise.site"]
ADAPTER_REGISTRY_ENABLED=true
LLM_PROVIDER=${LLM_PROVIDER:-auto}
ADAPTER_BASE_URL=${ADAPTER_BASE_URL:-}
ADAPTER_API_KEY=${ADAPTER_API_KEY:-}
LLM_BASE_URL=${LLM_BASE_URL:-}
LLM_API_KEY=${LLM_API_KEY:-}
LLM_MODEL=${LLM_MODEL:-}
MCP_PUBLIC_URL=https://api.prewise.site
MCP_ALLOWED_HOSTS=api.prewise.site,api.prewise.site:*
EOF
fi

if [[ -n "${CLOUDFLARE_TUNNEL_TOKEN:-}" ]]; then
  umask 077
  printf '%s' "$CLOUDFLARE_TUNNEL_TOKEN" > .codespaces-secrets/cloudflare-tunnel-token
  echo "Prepared the private Cloudflare Tunnel token file."
else
  echo "Add CLOUDFLARE_TUNNEL_TOKEN as a Codespaces secret, then rebuild this Codespace."
fi

echo "Run: bash scripts/codespaces-demo-up.sh"
