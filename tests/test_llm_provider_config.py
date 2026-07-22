import pytest
from pydantic import ValidationError

from backend.config import Settings


def _production_values(**overrides):
    values = {
        "app_env": "production",
        "database_url": "postgresql+psycopg://armor:secret@db.example/armor?sslmode=verify-full",
        "api_key_pepper": "a-production-pepper-value-that-is-long-enough",
        "api_key": "a-production-api-key-value",
        "telemetry_sensor_pepper": "a-production-telemetry-pepper-that-is-long-enough",
        "seed_demo_user": False,
        "database_auto_create": False,
    }
    values.update(overrides)
    return values


def test_production_allows_local_9router_endpoint_and_selected_model() -> None:
    settings = Settings(
        **_production_values(
            llm_provider="endpoint",
            llm_base_url="http://127.0.0.1:20128/v1",
            llm_api_key="sk_9router",
            llm_model="kr/claude-sonnet-4.5",
        )
    )

    assert settings.llm_model == "kr/claude-sonnet-4.5"


def test_production_rejects_non_https_non_local_endpoint() -> None:
    with pytest.raises(ValidationError, match="LLM_BASE_URL=https"):
        Settings(
            **_production_values(
                llm_provider="endpoint",
                llm_base_url="http://router.example/v1",
                llm_api_key="secret",
            )
        )
