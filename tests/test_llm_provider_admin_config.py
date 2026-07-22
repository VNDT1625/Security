from types import SimpleNamespace

import pytest

from backend.db import SessionLocal, initialize_database
from backend.models import LLMProviderSetting, User, UserLLMProviderSetting
from backend.services.llm_provider_config_service import (
    get_runtime_llm_config,
    normalize_provider_url,
    safe_config_payload,
    save_runtime_llm_config,
)


def test_endpoint_url_allows_loopback_http_but_rejects_remote_http() -> None:
    assert normalize_provider_url(
        "http://localhost:20128/v1/", provider="endpoint"
    ) == "http://localhost:20128/v1"
    with pytest.raises(ValueError, match="HTTPS"):
        normalize_provider_url("http://router.example/v1", provider="endpoint")


def test_admin_provider_key_is_encrypted_and_never_returned() -> None:
    initialize_database()
    secret = "sk-test-provider-secret"
    with SessionLocal() as db:
        previous = db.get(LLMProviderSetting, "default")
        previous_snapshot = None
        if previous is not None:
            previous_snapshot = {
                "provider": previous.provider,
                "base_url": previous.base_url,
                "model": previous.model,
                "api_key_ciphertext": previous.api_key_ciphertext,
                "updated_by_user_id": previous.updated_by_user_id,
            }
            db.delete(previous)
            db.commit()
        admin = db.query(User).first()
        assert admin is not None
        try:
            saved = save_runtime_llm_config(
                db,
                provider="endpoint",
                base_url="http://127.0.0.1:20128/v1",
                model="test-model",
                api_key=secret,
                clear_api_key=False,
                updated_by_user_id=admin.id,
            )
            record = db.get(LLMProviderSetting, "default")
            assert record is not None
            assert secret not in record.api_key_ciphertext
            assert get_runtime_llm_config(db).api_key == secret
            payload = safe_config_payload(saved)
            assert payload["apiKeyConfigured"] is True
            assert secret not in repr(payload)
        finally:
            current = db.get(LLMProviderSetting, "default")
            if current is not None:
                db.delete(current)
                db.commit()
            if previous_snapshot is not None:
                db.add(LLMProviderSetting(id="default", **previous_snapshot))
                db.commit()


def test_revoked_user_provider_falls_back_at_runtime() -> None:
    account = SimpleNamespace(
        provider="endpoint",
        base_url="https://personal.example/v1",
        model="personal-model",
        api_key_ciphertext="",
    )
    global_record = SimpleNamespace(
        provider="auto",
        base_url="",
        model="",
        api_key_ciphertext="",
        allowed_user_providers=["auto"],
        allowed_user_models=[],
    )

    class FakeDb:
        def get(self, model, key):
            if model is UserLLMProviderSetting:
                return account
            if model is LLMProviderSetting:
                return global_record
            return None

    config = get_runtime_llm_config(FakeDb(), user_id="user-1")  # type: ignore[arg-type]
    assert config.source == "database"
    assert config.provider == "auto"
