import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from backend.config import Settings


def test_production_rejects_development_defaults() -> None:
    with pytest.raises(ValidationError, match="Unsafe production configuration"):
        Settings(app_env="production")


def test_production_accepts_explicit_safe_configuration() -> None:
    settings = Settings(
        app_env="production",
        database_url="postgresql+psycopg://armor:secret@db.example/armor?sslmode=verify-full",
        api_key_pepper="a-production-pepper-value-that-is-long-enough",
        api_key="a-production-api-key-value",
        telemetry_sensor_pepper="a-production-telemetry-pepper-that-is-long-enough",
        seed_demo_user=False,
        database_auto_create=False,
    )
    assert settings.app_env == "production"


def test_production_remote_llm_requires_api_key() -> None:
    with pytest.raises(ValidationError, match="LLM_API_KEY"):
        Settings(
            app_env="production",
            database_url="postgresql+psycopg://armor:secret@db.example/armor?sslmode=require",
            api_key_pepper="a-production-pepper-value-that-is-long-enough",
            api_key="a-production-api-key-value",
            seed_demo_user=False,
            database_auto_create=False,
            llm_base_url="https://gpu.example/v1",
            llm_api_key="",
        )


def _safe_production_settings(**overrides):
    values = {
        "app_env": "production",
        "database_url": "postgresql+psycopg://armor:secret@db.example/armor?sslmode=verify-full",
        "api_key_pepper": "a-production-pepper-value-that-is-long-enough",
        "api_key": "a-production-api-key-value",
        "telemetry_sensor_pepper": "a-production-telemetry-pepper-that-is-long-enough",
        "seed_demo_user": False,
        "database_auto_create": False,
        # Keep provider validation tests deterministic even when a developer's
        # local .env contains real optional integration credentials.
        "sepay_webhook_api_key": "",
        "sepay_webhook_secret": "",
        "sepay_bank_account": "",
        "sepay_bank_name": "",
        "sepay_account_name": "",
        "aws_sandbox_ami_id": "",
        "aws_sandbox_subnet_id": "",
        "aws_sandbox_security_group_id": "",
        "misp_enabled": False,
        "misp_base_url": "",
        "misp_api_key": "",
    }
    values.update(overrides)
    return Settings(**values)


def test_production_accepts_complete_https_gmail_configuration() -> None:
    settings = _safe_production_settings(
        gmail_oauth_client_id="client-id",
        gmail_oauth_client_secret="client-secret",
        gmail_oauth_redirect_uri="https://api.example.com/v1/integrations/gmail/callback",
        gmail_token_encryption_keys=Fernet.generate_key().decode(),
        gmail_web_return_url="https://app.example.com/analyze?gmail=connected",
    )
    assert settings.gmail_oauth_client_id == "client-id"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"gmail_oauth_client_id": "client-id"},
            "all GMAIL_OAUTH",
        ),
        (
            {
                "gmail_oauth_client_id": "client-id",
                "gmail_oauth_client_secret": "client-secret",
                "gmail_oauth_redirect_uri": "http://api.example.com/callback",
                "gmail_token_encryption_keys": "not-a-fernet-key",
            },
            "GMAIL_TOKEN_ENCRYPTION_KEYS",
        ),
    ],
)
def test_production_rejects_unsafe_gmail_configuration(overrides, message) -> None:
    with pytest.raises(ValidationError, match=message):
        _safe_production_settings(**overrides)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"sepay_bank_account": "123"}, "SePay webhook authentication"),
        ({"aws_sandbox_ami_id": "ami-123"}, "AWS_SANDBOX_AMI_ID"),
        (
            {
                "misp_enabled": True,
                "misp_base_url": "http://misp.internal",
                "misp_api_key": "",
            },
            "MISP_BASE_URL=https://",
        ),
    ],
)
def test_production_rejects_partial_optional_provider_configuration(
    overrides, message
) -> None:
    with pytest.raises(ValidationError, match=message):
        _safe_production_settings(**overrides)


@pytest.mark.parametrize(
    "callback_url",
    [
        "http://api.example.com",
        "http://127.0.0.1:8000",
        "https://",
    ],
)
def test_production_rejects_unsafe_sandbox_agent_callback(callback_url) -> None:
    with pytest.raises(ValidationError, match="SANDBOX_PUBLIC_BASE_URL=https://"):
        _safe_production_settings(sandbox_public_base_url=callback_url)


def test_production_accepts_https_sandbox_agent_callback() -> None:
    settings = _safe_production_settings(
        sandbox_public_base_url="https://api.example.com",
    )

    assert settings.sandbox_public_base_url == "https://api.example.com"


def test_production_accepts_complete_release_email_configuration() -> None:
    configured = _safe_production_settings(
        cloudflare_account_id="account-id",
        cloudflare_api_token="token-kept-server-side",
        prewise_email_from="release@prewise.example",
        release_unsubscribe_base_url="https://api.prewise.example/v1/waitlist/unsubscribe",
    )
    assert configured.cloudflare_account_id == "account-id"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"cloudflare_account_id": "account-id"}, "all CLOUDFLARE_ACCOUNT_ID"),
        ({"release_unsubscribe_base_url": "http://api.example/unsubscribe"}, "RELEASE_UNSUBSCRIBE_BASE_URL"),
        ({"release_email_max_attempts": 10}, "RELEASE_EMAIL_MAX_ATTEMPTS"),
    ],
)
def test_production_rejects_unsafe_release_email_configuration(overrides, message) -> None:
    with pytest.raises(ValidationError, match=message):
        _safe_production_settings(**overrides)
