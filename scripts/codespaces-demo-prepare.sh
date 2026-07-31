#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
mkdir -p .aisec-backups .codespaces-secrets
chmod 700 .codespaces-secrets

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

remove_env_value() {
  local key="$1"
  local temp_file

  temp_file="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" != "${key}="* ]]; then
      printf '%s\n' "$line" >> "$temp_file"
    fi
  done < "$ENV_FILE"
  chmod 600 "$temp_file"
  mv "$temp_file" "$ENV_FILE"
}

env_value_is_set() {
  local value
  value="$(sed -n "s/^${1}=//p" "$ENV_FILE" | tail -n 1)"
  [[ -n "$value" && "${value,,}" != "null" && "${value,,}" != "none" ]]
}

sync_codespaces_secret() {
  local key="$1"
  local value
  value="$(printenv "$key" 2>/dev/null || true)"
  if [[ -n "$value" ]]; then
    upsert_env_value "$key" "$value"
  fi
}

normalize_base64_env_value() {
  local key="$1"
  local pattern="$2"
  local value
  local decoded

  value="$(sed -n "s/^${key}=//p" "$ENV_FILE" | tail -n 1)"
  if [[ -z "$value" ]]; then
    return 0
  fi

  decoded="$(printf '%s' "$value" | base64 --decode 2>/dev/null || true)"
  if [[ -n "$decoded" && "$decoded" =~ $pattern ]]; then
    upsert_env_value "$key" "$decoded"
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
REQUIRE_EMAIL_VERIFICATION=false
EMAIL_VERIFICATION_CODE_TTL_MINUTES=10
EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS=60
EMAIL_VERIFICATION_MAX_ATTEMPTS=5
EXPOSE_EMAIL_VERIFICATION_CODE=false
ADAPTER_REGISTRY_ENABLED=true
LLM_PROVIDER=${LLM_PROVIDER:-auto}
ADAPTER_BASE_URL=${ADAPTER_BASE_URL:-}
ADAPTER_API_KEY=${ADAPTER_API_KEY:-}
LLM_BASE_URL=${LLM_BASE_URL:-}
LLM_API_KEY=${LLM_API_KEY:-}
LLM_MODEL=${LLM_MODEL:-}
EMAIL_ATTACHMENT_SANDBOX_ENABLED=true
MCP_PUBLIC_URL=https://api.prewise.site
MCP_ALLOWED_HOSTS=api.prewise.site,api.prewise.site:*
EOF
fi

# GitHub exposes Codespaces secrets as process environment variables. Sync email
# delivery and Gmail credentials on every prepare/start so an existing runtime
# file is not left stale after a secret is added or rotated.
for key in \
  RESEND_API_KEY \
  CLOUDFLARE_ACCOUNT_ID \
  CLOUDFLARE_API_TOKEN \
  PREWISE_EMAIL_FROM \
  REQUIRE_EMAIL_VERIFICATION \
  GMAIL_OAUTH_CLIENT_ID \
  GMAIL_OAUTH_CLIENT_SECRET \
  GMAIL_TOKEN_ENCRYPTION_KEYS \
  WHOISXML_API_KEY \
  IP2WHOIS_API_KEY \
  IPQS_PHONE_API_KEY \
  IPQS_PHONE_API_URL \
  PHONE_INTELLIGENCE_URL \
  GOOGLE_SAFE_BROWSING_API_KEY \
  METADEFENDER_API_KEY \
  MISP_ENABLED \
  MISP_BASE_URL \
  MISP_API_KEY \
  AWS_REGION \
  AWS_ACCESS_KEY_ID \
  AWS_SECRET_ACCESS_KEY \
  AWS_SESSION_TOKEN \
  AWS_SANDBOX_AMI_ID \
  AWS_SANDBOX_SUBNET_ID \
  AWS_SANDBOX_SECURITY_GROUP_ID \
  ADAPTER_BASE_URL \
  ADAPTER_API_KEY \
  LLM_PROVIDER \
  LLM_BASE_URL \
  LLM_API_KEY \
  LLM_MODEL \
  EMAIL_ATTACHMENT_SANDBOX_ENABLED
do
  sync_codespaces_secret "$key"
done

ensure_env_default REQUIRE_EMAIL_VERIFICATION false
ensure_env_default EMAIL_ATTACHMENT_SANDBOX_ENABLED true

sync_codespaces_secret GMAIL_OAUTH_REDIRECT_URI
sync_codespaces_secret GMAIL_WEB_RETURN_URL

# Secrets copied through the GitHub UI may be wrapped in one Base64 layer.
# Normalize only when the decoded value matches the strict shape expected for
# that setting; already-raw values are left untouched.
normalize_base64_env_value RESEND_API_KEY '^re_[A-Za-z0-9_]+'
normalize_base64_env_value CLOUDFLARE_ACCOUNT_ID '^[0-9a-f]{32}$'
normalize_base64_env_value CLOUDFLARE_API_TOKEN '^[A-Za-z0-9_-]{20,}$'
normalize_base64_env_value GMAIL_OAUTH_CLIENT_ID '^[A-Za-z0-9._-]+\.apps\.googleusercontent\.com$'
normalize_base64_env_value GMAIL_OAUTH_CLIENT_SECRET '^GOCSPX-[A-Za-z0-9_-]+$'
normalize_base64_env_value GMAIL_TOKEN_ENCRYPTION_KEYS '^[A-Za-z0-9_-]{43}=$'
normalize_base64_env_value GMAIL_OAUTH_REDIRECT_URI '^https://'
normalize_base64_env_value GMAIL_WEB_RETURN_URL '^https://'

if env_value_is_set CLOUDFLARE_ACCOUNT_ID && ! env_value_is_set CLOUDFLARE_API_TOKEN; then
  remove_env_value CLOUDFLARE_ACCOUNT_ID
elif env_value_is_set CLOUDFLARE_API_TOKEN && ! env_value_is_set CLOUDFLARE_ACCOUNT_ID; then
  remove_env_value CLOUDFLARE_API_TOKEN
fi

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
  for key in \
    GMAIL_OAUTH_CLIENT_ID \
    GMAIL_OAUTH_CLIENT_SECRET \
    GMAIL_TOKEN_ENCRYPTION_KEYS \
    GMAIL_OAUTH_REDIRECT_URI \
    GMAIL_WEB_RETURN_URL
  do
    remove_env_value "$key"
  done
  echo "Gmail OAuth remains disabled; add Codespaces secrets: ${missing_gmail[*]}"
else
  echo "Prepared Gmail OAuth configuration from Codespaces secrets."
fi

if [[ -n "${CLOUDFLARE_TUNNEL_TOKEN:-}" ]]; then
  umask 077
  tunnel_token="$CLOUDFLARE_TUNNEL_TOKEN"
  # Codespaces secrets are sometimes populated with the base64-wrapped value
  # copied from another secret store. Normalize exactly one wrapper layer
  # while still accepting the raw Cloudflare token format.
  if [[ "$tunnel_token" == ZXlK* ]]; then
    decoded_tunnel_token="$(printf '%s' "$tunnel_token" | base64 --decode 2>/dev/null || true)"
    if [[ "$decoded_tunnel_token" == eyJ* ]]; then
      tunnel_token="$decoded_tunnel_token"
    fi
  fi
  printf '%s' "$tunnel_token" > .codespaces-secrets/cloudflare-tunnel-token
  chmod 600 .codespaces-secrets/cloudflare-tunnel-token
  echo "Prepared the private Cloudflare Tunnel token file."
elif [[ -f .codespaces-secrets/cloudflare-tunnel-token ]]; then
  chmod 600 .codespaces-secrets/cloudflare-tunnel-token
  echo "Reused the existing private Cloudflare Tunnel token file."
else
  echo "Add CLOUDFLARE_TUNNEL_TOKEN as a Codespaces secret, then rebuild this Codespace."
fi

echo "Run: bash scripts/codespaces-demo-up.sh"
