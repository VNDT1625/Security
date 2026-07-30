from types import SimpleNamespace

import pytest

from backend.config import settings
from backend.db import SessionLocal, initialize_database
from backend.models import LLMProviderSetting, User, UserLLMProviderSetting
from backend.services.llm_provider_config_service import (
    get_user_llm_policy,
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


@pytest.mark.parametrize("submitted_key", [None, "", "   "])
def test_admin_policy_only_save_preserves_environment_endpoint_key(
    monkeypatch, submitted_key: str | None
) -> None:
    secret = "sk-environment-provider-secret"
    monkeypatch.setattr(settings, "llm_provider", "endpoint")
    monkeypatch.setattr(settings, "llm_base_url", "https://llm.example/v1")
    monkeypatch.setattr(settings, "llm_model", "environment-model")
    monkeypatch.setattr(settings, "llm_api_key", secret)

    class FakeDb:
        record = None

        def get(self, model, key):
            if model is LLMProviderSetting and key == "default":
                return self.record
            return None

        def add(self, record):
            self.record = record

        def commit(self):
            return None

        def refresh(self, record):
            return None

    db = FakeDb()
    saved = save_runtime_llm_config(
        db,  # type: ignore[arg-type]
        provider="endpoint",
        base_url="https://llm.example/v1",
        model="environment-model",
        api_key=submitted_key,
        clear_api_key=False,
        updated_by_user_id="admin-1",
        allowed_user_providers=["endpoint"],
    )

    assert saved.api_key == secret
    assert db.record is not None
    assert secret not in db.record.api_key_ciphertext
    payload = safe_config_payload(saved)
    assert payload["apiKeyConfigured"] is True
    assert secret not in repr(payload)


def test_admin_save_does_not_reuse_environment_key_from_another_provider(monkeypatch) -> None:
    monkeypatch.setattr(settings, "llm_provider", "adapter")
    monkeypatch.setattr(settings, "llm_api_key", "sk-adapter-secret")

    db = SimpleNamespace(
        get=lambda model, key: None,
        add=lambda record: None,
        commit=lambda: None,
        refresh=lambda record: None,
    )

    with pytest.raises(ValueError, match="yêu cầu API key"):
        save_runtime_llm_config(
            db,  # type: ignore[arg-type]
            provider="endpoint",
            base_url="https://llm.example/v1",
            model="new-endpoint-model",
            api_key=None,
            clear_api_key=False,
            updated_by_user_id="admin-1",
            allowed_user_providers=["endpoint"],
        )


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


def test_user_policy_exposes_only_the_three_backend_modes() -> None:
    record = SimpleNamespace(
        allowed_user_providers=["auto", "endpoint", "adapter", "unknown", "local"],
        allowed_user_models=[],
    )

    class FakeDb:
        def get(self, model, key):
            return record if model is LLMProviderSetting else None

    policy = get_user_llm_policy(FakeDb())  # type: ignore[arg-type]
    assert policy["allowedProviders"] == ["endpoint", "adapter", "local"]
    assert "auto" not in policy["allowedProviders"]


def test_admin_cannot_publish_internal_auto_as_a_user_mode() -> None:
    db = SimpleNamespace(
        get=lambda model, key: None,
        add=lambda record: None,
    )
    with pytest.raises(ValueError, match="provider cá nhân"):
        save_runtime_llm_config(
            db,  # type: ignore[arg-type]
            provider="adapter",
            base_url="",
            model="",
            api_key=None,
            clear_api_key=False,
            updated_by_user_id="admin-1",
            allowed_user_providers=["auto"],
        )
