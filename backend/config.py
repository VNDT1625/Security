"""Gateway configuration (pydantic-settings)."""

from __future__ import annotations

import base64
import binascii
from typing import Literal
from urllib.parse import urlsplit

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _is_https_or_loopback(url: str) -> bool:
    """Allow plain HTTP only when the endpoint cannot leave this machine."""
    parsed = urlsplit(url)
    return bool(parsed.hostname) and (parsed.scheme == "https" or (
        parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    ))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_env: Literal["development", "test", "production"] = "development"

    model_dir: str = "ai/models"
    deepfake_model_path: str = "ai/models/deepfake_image_q4.onnx"
    # Explanation provider selection. ``adapter`` uses the project's trained
    # LoRA server, ``local`` uses a user-controlled OpenAI-compatible/Ollama
    # server, and ``endpoint`` uses an external OpenAI-compatible API.
    # ``auto`` preserves the historic LLM_BASE_URL -> Ollama fallback behavior.
    llm_provider: Literal["auto", "adapter", "local", "endpoint"] = "auto"
    # External endpoint settings. They are intentionally separate from local
    # settings so an API key can never be sent to a local model by accident.
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""
    llm_timeout_seconds: float = 90
    llm_max_tokens: int = 500
    adapter_registry_enabled: bool = True
    adapter_manifest_path: str = "server/adapters/manifest.json"
    adapter_base_url: str = ""
    adapter_api_key: str = ""
    adapter_timeout_seconds: float = 15
    adapter_max_risk_contribution: float = 0.25
    legal_adapter_model: str = "prewise-legal-rag"
    # Backward-compatible local Ollama settings. Used only when LLM_BASE_URL is empty.
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b-instruct-q4_K_M"
    ip2whois_api_key: str = ""
    whoisxml_api_key: str = ""

    # Public-IP enrichment. Only globally routable IP literals are sent and
    # results are cached; the full URL and query string never leave this service.
    ip_geolocation_enabled: bool = True
    ip2location_api_key: str = ""
    ip_geolocation_timeout_seconds: float = 3.0
    ip_geolocation_cache_ttl_seconds: int = 21600

    # Optional external URL intelligence. Providers remain disabled until a
    # server-side key/explicit enable flag is configured.
    hudson_rock_api_url: str = ""
    hudson_rock_api_key: str = ""
    phishtank_api_url: str = ""
    phishtank_api_key: str = ""
    phishtank_enabled: bool = False
    ipqs_api_url: str = ""
    ipqs_api_key: str = ""
    google_web_risk_api_url: str = ""
    google_web_risk_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    apivoid_api_url: str = ""
    apivoid_api_key: str = ""
    phishdestroy_api_url: str = ""
    phishdestroy_api_key: str = ""
    phishdestroy_enabled: bool = False

    # Phone-number reputation for SMS assessment. The key stays server-side;
    # responses are reduced to non-identifying carrier/risk fields before they
    # are returned to clients.
    ipqs_phone_api_url: str = "https://www.ipqualityscore.com/api/json/phone"
    ipqs_phone_api_key: str = ""
    phone_intelligence_timeout_seconds: float = 8.0

    # Private attachment inspection. clamd must only be reachable on a trusted
    # service network because its TCP protocol has no authentication or TLS.
    clamav_host: str = ""
    clamav_port: int = 3310
    attachment_scan_timeout_seconds: float = 10.0
    tesseract_executable: str = ""
    tesseract_languages: str = "vie+eng"
    attachment_ocr_timeout_seconds: float = 12.0
    email_attachment_sandbox_enabled: bool = False
    email_attachment_active_scan_limit: int = 12
    email_ocr_image_limit: int = 5
    email_sandbox_file_limit: int = 1
    email_attachment_budget_seconds: float = 35.0
    email_analysis_timeout_seconds: float = 90.0

    # Gmail OAuth web-server flow. Encryption keys are comma-separated Fernet
    # keys; the first encrypts new values and the remaining keys allow rotation.
    gmail_oauth_client_id: str = ""
    gmail_oauth_client_secret: str = ""
    gmail_oauth_redirect_uri: str = ""
    gmail_token_encryption_keys: str = ""
    gmail_web_return_url: str = "http://localhost:3000/analyze?gmail=connected"
    gmail_api_timeout_seconds: float = 12.0

    # url.vet is a separately deployed service and is consumed over HTTP.
    urlvet_enabled: bool = False
    urlvet_api_url: str = "http://127.0.0.1:8080"
    urlvet_timeout_seconds: float = 12.0

    # Local threat-feed pipeline. Every source is opt-in and bounded.
    threat_feed_scheduler_enabled: bool = False
    threat_feed_scheduler_interval_minutes: int = 60
    threat_feed_request_timeout_seconds: float = 45.0
    threat_feed_max_download_bytes: int = 64 * 1024 * 1024
    threat_feed_max_records_per_source: int = 250_000
    threat_feed_retention_days: int = 30
    threat_feed_user_agent: str = "AI-Security-Armor/0.2 threat-feed-collector"
    threat_feed_allow_custom_endpoints: bool = False
    threat_feed_phishtank_enabled: bool = False
    threat_feed_phishtank_url: str = "https://data.phishtank.com/data/online-valid.csv.gz"
    threat_feed_phishtank_app_key: str = ""
    threat_feed_openphish_enabled: bool = False
    threat_feed_openphish_url: str = (
        "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    )
    threat_feed_urlhaus_enabled: bool = False
    threat_feed_urlhaus_url: str = (
        "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
    )
    threat_feed_urlhaus_auth_key: str = ""
    threat_feed_openphish_interval_hours: int = 12
    threat_feed_phishing_database_path: str = ".aisec-data/Phishing.Database"

    # Optional self-hosted MISP lookup.
    misp_enabled: bool = False
    misp_base_url: str = ""
    misp_api_key: str = ""
    misp_verify_tls: bool = True
    misp_timeout_seconds: float = 8.0
    misp_lookup_last: str = "90d"

    # Privacy-preserving endpoint consensus. Raw URLs and sensor IDs are not stored.
    telemetry_sensor_pepper: str = "dev-telemetry-pepper-change-in-production"
    telemetry_retention_days: int = 30
    telemetry_consensus_window_days: int = 14
    telemetry_min_independent_sensors: int = 2

    database_url: str = "sqlite:///./.aisec-data/armor.db"
    database_auto_create: bool = True
    database_echo: bool = False
    database_pool_size: int = 10
    database_max_overflow: int = 20
    database_pool_timeout: int = 30
    database_pool_recycle: int = 1800
    database_require_tls: bool = True
    seed_demo_user: bool = True
    api_key_pepper: str = "dev-api-key-pepper-change-in-production"
    api_key_last_used_write_interval_seconds: int = 300

    api_key: str = "dev-key-change-in-production"
    local_testing_unlimited: bool = False
    rate_limit_per_min: int = 60
    anonymous_daily_scan_limit: int = 1000
    anonymous_daily_ai_credit_limit: int = 5
    anonymous_daily_deep_scan_limit: int = 100
    max_upload_bytes: int = 10 * 1024 * 1024

    # Quick EXE Lab analysis. Local PE inspection is always available. Hash
    # lookup and sample upload are enabled only when a server-side key exists.
    metadefender_api_key: str = ""
    metadefender_base_url: str = "https://api.metadefender.com/v4"
    metadefender_timeout_seconds: float = 20.0

    shared_assessment_cache_enabled: bool = True
    shared_assessment_cache_ttl_seconds: int = 900

    # Operational data lifecycle. Scan records are retained for account history
    # and auditability, then purged with their evidence by the maintenance job.
    # Set the scheduler explicitly in production (one worker only) so horizontal
    # API replicas do not run redundant cleanup work.
    scan_history_retention_days: int = 90
    operational_maintenance_scheduler_enabled: bool = False
    operational_maintenance_interval_minutes: int = 360

    # SePay webhook authentication. Prefer HMAC-SHA256 using X-SePay-Signature.
    sepay_webhook_api_key: str = ""
    sepay_webhook_secret: str = ""
    sepay_bank_account: str = ""
    sepay_bank_name: str = ""
    sepay_account_name: str = ""
    sepay_qr_base_url: str = "https://vietqr.app/img"
    sepay_payment_expiry_minutes: int = 30
    sandbox_credit_price_vnd: int = 5000
    sandbox_session_minutes: int = 10

    # Optional Cloudflare Email Sending REST integration for release notices.
    cloudflare_account_id: str = ""
    cloudflare_api_token: str = ""
    prewise_email_from: str = ""
    release_email_timeout_seconds: float = 10.0
    release_email_max_attempts: int = 3
    release_unsubscribe_base_url: str = "https://api.prewise.site/v1/waitlist/unsubscribe"
    password_reset_web_url: str = "https://www.prewise.site/auth"

    # Disposable Windows EC2.  The legacy security group is intentionally the
    # agent-only/no-inbound group used by automatic detonation.  Interactive
    # sessions require a separate AMI and security group so enabling a browser
    # desktop never widens the attack surface of automatic workers.
    aws_region: str = "ap-southeast-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_session_token: str = ""
    aws_sandbox_ami_id: str = ""
    aws_sandbox_instance_type: str = "m7i-flex.large"
    aws_sandbox_max_ami_id: str = ""
    aws_sandbox_max_instance_type: str = "g4dn.xlarge"
    aws_sandbox_subnet_id: str = ""
    # Development/demo escape hatch for subnets without NAT. Production must
    # keep workers private and provide controlled outbound egress instead.
    aws_sandbox_associate_public_ip: bool = False
    free_sandbox_remote_url: str = ""
    free_sandbox_daily_minutes: int = 10
    pro_sandbox_session_minutes: int = 15
    max_sandbox_session_minutes: int = 30
    aws_sandbox_security_group_id: str = ""
    aws_sandbox_key_name: str = ""
    aws_sandbox_remote_port: int = 8443
    aws_sandbox_interactive_ami_id: str = ""
    aws_sandbox_interactive_max_ami_id: str = ""
    aws_sandbox_interactive_instance_type: str = "m7i-flex.large"
    aws_sandbox_interactive_max_instance_type: str = "g4dn.xlarge"
    aws_sandbox_interactive_security_group_id: str = ""
    # A remote target is accepted only from this administrator-controlled HTTPS
    # broker template or from the explicit EC2 tag below.  It is never inferred
    # from a public IP/DNS name. Supported template fields: session_id,
    # instance_id.  The target is stored without credentials; a browser URL is
    # issued later with an opaque, one-time access token.
    sandbox_remote_broker_url_template: str = ""
    aws_sandbox_remote_url_tag: str = ""
    sandbox_remote_broker_secret: str = ""
    # Dedicated, credential-free endpoint used by release preflight.  It must
    # describe the Prewise broker adapter, not the Guacamole/DCV desktop URL.
    sandbox_remote_broker_health_url: str = ""
    sandbox_remote_access_token_ttl_seconds: int = 60
    sandbox_agent_report_grace_seconds: int = 15
    sandbox_agent_bootstrap_timeout_seconds: int = 120
    sandbox_cloud_provision_timeout_minutes: int = 10
    sandbox_public_base_url: str = ""
    sandbox_sample_storage_path: str = ".aisec-data/cloud-sandbox-samples"
    sandbox_sample_retention_hours: int = 24

    # Public MCP transport is authenticated independently from the web gateway.
    mcp_allow_anonymous: bool = False
    mcp_api_key_rate_limit_per_min: int = 120
    mcp_anonymous_rate_limit_per_min: int = 10
    mcp_public_url: str = "https://api.prewise.site"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_oauth_access_token_minutes: int = 30
    mcp_oauth_refresh_token_days: int = 90

    risk_threshold_block: float = 0.85
    risk_threshold_warn: float = 0.50
    risk_threshold_allow: float = 0.15

    # Official product origins plus local development origins.
    cors_allow_origins: list[str] = [
        "https://prewise.site",
        "https://www.prewise.site",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        # Desktop renderer served by Vite during Electron development.
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        # Packaged Electron loads its renderer from a local file, which sends
        # the literal Origin header "null" for requests to the Core API.
        "null",
    ]
    # Chromium Private Network Access (PNA) is required when the local web UI
    # calls a backend bound to localhost. Keep disabled by default so a public
    # production origin cannot opt into private-network requests accidentally.
    cors_allow_private_network: bool = False

    @model_validator(mode="after")
    def validate_production_safety(self) -> Settings:
        if self.app_env != "production":
            return self
        unsafe = []
        if self.api_key_pepper == "dev-api-key-pepper-change-in-production":
            unsafe.append("API_KEY_PEPPER")
        if self.api_key == "dev-key-change-in-production":
            unsafe.append("API_KEY")
        if self.seed_demo_user:
            unsafe.append("SEED_DEMO_USER=false")
        if self.database_auto_create:
            unsafe.append("DATABASE_AUTO_CREATE=false")
        if not self.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            unsafe.append("DATABASE_URL=postgresql+psycopg://...")
        if self.database_require_tls and "sslmode=" not in self.database_url:
            unsafe.append("DATABASE_URL with sslmode=require or verify-full")
        if len(self.api_key_pepper.encode("utf-8")) < 32:
            unsafe.append("API_KEY_PEPPER>=32 bytes")
        if self.mcp_allow_anonymous:
            unsafe.append("MCP_ALLOW_ANONYMOUS=false")
        if self.mcp_api_key_rate_limit_per_min <= 0:
            unsafe.append("MCP_API_KEY_RATE_LIMIT_PER_MIN>0")
        if self.llm_base_url and not self.llm_api_key:
            unsafe.append("LLM_API_KEY when LLM_BASE_URL is configured")
        if self.llm_provider == "endpoint" and not _is_https_or_loopback(self.llm_base_url):
            unsafe.append(
                "LLM_BASE_URL=https://... (or http://127.0.0.1/... for a local router) "
                "when LLM_PROVIDER=endpoint"
            )
        if self.adapter_base_url and not (self.adapter_api_key or self.llm_api_key):
            unsafe.append("ADAPTER_API_KEY when ADAPTER_BASE_URL is configured")
        release_email_values = (
            self.cloudflare_account_id,
            self.cloudflare_api_token,
            self.prewise_email_from,
        )
        if any(release_email_values) and not all(release_email_values):
            unsafe.append(
                "all CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN and PREWISE_EMAIL_FROM values"
            )
        if self.prewise_email_from and (
            "@" not in self.prewise_email_from
            or self.prewise_email_from.startswith("@")
            or self.prewise_email_from.endswith("@")
        ):
            unsafe.append("PREWISE_EMAIL_FROM=valid sender address")
        unsubscribe = urlsplit(self.release_unsubscribe_base_url)
        if unsubscribe.scheme != "https" or not unsubscribe.hostname:
            unsafe.append("RELEASE_UNSUBSCRIBE_BASE_URL=https://...")
        reset_page = urlsplit(self.password_reset_web_url)
        if reset_page.scheme != "https" or not reset_page.hostname:
            unsafe.append("PASSWORD_RESET_WEB_URL=https://...")
        if not 1 <= self.release_email_max_attempts <= 5:
            unsafe.append("RELEASE_EMAIL_MAX_ATTEMPTS between 1 and 5")
        if not 1 <= self.release_email_timeout_seconds <= 30:
            unsafe.append("RELEASE_EMAIL_TIMEOUT_SECONDS between 1 and 30")
        gmail_values = (
            self.gmail_oauth_client_id,
            self.gmail_oauth_client_secret,
            self.gmail_oauth_redirect_uri,
            self.gmail_token_encryption_keys,
        )
        if any(gmail_values) and not all(gmail_values):
            unsafe.append("all GMAIL_OAUTH_* and GMAIL_TOKEN_ENCRYPTION_KEYS values")
        if self.gmail_token_encryption_keys:
            try:
                decoded_keys = [
                    base64.urlsafe_b64decode(item.strip().encode("ascii"))
                    for item in self.gmail_token_encryption_keys.split(",")
                    if item.strip()
                ]
                if not decoded_keys or any(len(item) != 32 for item in decoded_keys):
                    raise ValueError
            except (ValueError, UnicodeError, binascii.Error):
                unsafe.append("GMAIL_TOKEN_ENCRYPTION_KEYS=valid Fernet key(s)")
        if self.gmail_oauth_redirect_uri and not self.gmail_oauth_redirect_uri.startswith("https://"):
            unsafe.append("GMAIL_OAUTH_REDIRECT_URI=https://...")
        if any(gmail_values) and self.gmail_web_return_url and not self.gmail_web_return_url.startswith("https://"):
            unsafe.append("GMAIL_WEB_RETURN_URL=https://...")
        sepay_values = (
            self.sepay_webhook_secret or self.sepay_webhook_api_key,
            self.sepay_bank_account,
            self.sepay_bank_name,
            self.sepay_account_name,
        )
        if any(sepay_values) and not all(sepay_values):
            unsafe.append(
                "SePay webhook authentication plus SEPAY_BANK_ACCOUNT, "
                "SEPAY_BANK_NAME and SEPAY_ACCOUNT_NAME"
            )
        aws_sandbox_values = (
            self.aws_sandbox_ami_id,
            self.aws_sandbox_subnet_id,
            self.aws_sandbox_security_group_id,
        )
        if any(aws_sandbox_values) and not all(aws_sandbox_values):
            unsafe.append(
                "AWS_SANDBOX_AMI_ID, AWS_SANDBOX_SUBNET_ID and "
                "AWS_SANDBOX_SECURITY_GROUP_ID"
            )
        interactive_values = (
            self.aws_sandbox_interactive_ami_id,
            self.aws_sandbox_interactive_security_group_id,
            self.sandbox_remote_broker_url_template or self.aws_sandbox_remote_url_tag,
            self.sandbox_remote_broker_secret,
            self.sandbox_remote_broker_health_url,
        )
        if any(interactive_values) and not all(interactive_values):
            unsafe.append(
                "AWS_SANDBOX_INTERACTIVE_AMI_ID, "
                "AWS_SANDBOX_INTERACTIVE_SECURITY_GROUP_ID, a remote broker URL "
                "source, SANDBOX_REMOTE_BROKER_SECRET, and "
                "SANDBOX_REMOTE_BROKER_HEALTH_URL"
            )
        if self.sandbox_remote_broker_url_template and not _is_https_or_loopback(
            self.sandbox_remote_broker_url_template
        ):
            unsafe.append("SANDBOX_REMOTE_BROKER_URL_TEMPLATE=https://...")
        if self.sandbox_public_base_url:
            callback = urlsplit(self.sandbox_public_base_url)
            if callback.scheme != "https" or not callback.hostname:
                unsafe.append("SANDBOX_PUBLIC_BASE_URL=https://...")
        if self.sandbox_remote_broker_secret and len(
            self.sandbox_remote_broker_secret.encode("utf-8")
        ) < 32:
            unsafe.append("SANDBOX_REMOTE_BROKER_SECRET>=32 bytes")
        if self.sandbox_remote_broker_health_url:
            broker_health = urlsplit(self.sandbox_remote_broker_health_url)
            if (
                broker_health.scheme != "https"
                or not broker_health.hostname
                or broker_health.username
                or broker_health.password
                or broker_health.query
                or broker_health.fragment
            ):
                unsafe.append(
                    "SANDBOX_REMOTE_BROKER_HEALTH_URL=credential-free HTTPS URL"
                )
            elif broker_health.hostname.lower().endswith(".trycloudflare.com"):
                unsafe.append(
                    "SANDBOX_REMOTE_BROKER_HEALTH_URL=stable managed hostname"
                )
        if not 15 <= self.sandbox_remote_access_token_ttl_seconds <= 300:
            unsafe.append("SANDBOX_REMOTE_ACCESS_TOKEN_TTL_SECONDS between 15 and 300")
        if not 5 <= self.sandbox_agent_report_grace_seconds <= 30:
            unsafe.append("SANDBOX_AGENT_REPORT_GRACE_SECONDS between 5 and 30")
        if not 30 <= self.sandbox_agent_bootstrap_timeout_seconds <= 300:
            unsafe.append("SANDBOX_AGENT_BOOTSTRAP_TIMEOUT_SECONDS between 30 and 300")
        if not 2 <= self.sandbox_cloud_provision_timeout_minutes <= 30:
            unsafe.append("SANDBOX_CLOUD_PROVISION_TIMEOUT_MINUTES between 2 and 30")
        if self.misp_enabled and (
            not self.misp_base_url.startswith("https://") or not self.misp_api_key
        ):
            unsafe.append("MISP_BASE_URL=https://... and MISP_API_KEY when enabled")
        if (
            self.telemetry_sensor_pepper == "dev-telemetry-pepper-change-in-production"
            or len(self.telemetry_sensor_pepper.encode("utf-8")) < 32
        ):
            unsafe.append("TELEMETRY_SENSOR_PEPPER>=32 bytes")
        if unsafe:
            raise ValueError("Unsafe production configuration: " + ", ".join(unsafe))
        return self


settings = Settings()
