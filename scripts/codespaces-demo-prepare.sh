#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
mkdir -p .aisec-backups .codespaces-secrets

ENV_FILE=".env.codespaces"

upsert_env_value() {
  local key="$1"
  local value="$2"
  local temp_file

  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    echo "Refusing multiline value for ${key}."
    exit 1
  fi

  temp_file="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" != "${key}="* ]]; then
      printf '%s\n' "$line" >> "$temp_file"
    fi
  done < "$ENV_FILE"
  printf '%s=%s\n' "$key" "$value" >> "$temp_file"
  chmod 600 "$temp_file"
  mv "$temp_file" "$ENV_FILE"
}

env_value_is_set() {
  grep -Eq "^${1}=.+" "$ENV_FILE"
}

sync_codespaces_secret() {
  local key="$1"
  local value
  value="$(printenv "$key" 2>/dev/null || true)"
  if [[ -n "$value" ]]; then
    upsert_env_value "$key" "$value"
  fi
}

ensure_env_default() {
  local key="$1"
  local default_value="$2"
  if ! env_value_is_set "$key"; then
    upsert_env_value "$key" "$default_value"
  fi
}

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

# GitHub exposes Codespaces secrets as process environment variables. Sync them
# on every prepare/start so an existing .env.codespaces is not left stale after
# a secret is added or rotated. Secret values remain in ignored mode-0600 files.
for key in \
  GMAIL_OAUTH_CLIENT_ID \
  GMAIL_OAUTH_CLIENT_SECRET \
  GMAIL_TOKEN_ENCRYPTION_KEYS
do
  sync_codespaces_secret "$key"
done

sync_codespaces_secret GMAIL_OAUTH_REDIRECT_URI
sync_codespaces_secret GMAIL_WEB_RETURN_URL
ensure_env_default \
  GMAIL_OAUTH_REDIRECT_URI \
  "https://api.prewise.site/v1/integrations/gmail/callback"
ensure_env_default \
  GMAIL_WEB_RETURN_URL \
  "https://prewise.site/analyze?gmail=connected"

missing_gmail=()
for key in \
  GMAIL_OAUTH_CLIENT_ID \
  GMAIL_OAUTH_CLIENT_SECRET \
  GMAIL_TOKEN_ENCRYPTION_KEYS
do
  if ! env_value_is_set "$key"; then
    missing_gmail+=("$key")
  fi
done
if (( ${#missing_gmail[@]} > 0 )); then
  echo "Gmail OAuth remains disabled; add Codespaces secrets: ${missing_gmail[*]}"
else
  echo "Prepared Gmail OAuth configuration from Codespaces secrets."
fi

if [[ -n "${CLOUDFLARE_TUNNEL_TOKEN:-}" ]]; then
  umask 077
  printf '%s' "$CLOUDFLARE_TUNNEL_TOKEN" > .codespaces-secrets/cloudflare-tunnel-token
  echo "Prepared the private Cloudflare Tunnel token file."
else
  echo "Add CLOUDFLARE_TUNNEL_TOKEN as a Codespaces secret, then rebuild this Codespace."
fi

echo "Run: bash scripts/codespaces-demo-up.sh"
