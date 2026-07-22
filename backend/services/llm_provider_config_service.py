"""Encrypted runtime configuration for global and per-user AI providers."""

from __future__ import annotations

import base64
import hmac
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session as DbSession

from backend.config import _is_https_or_loopback, settings
from backend.models import LLMProviderSetting, UserLLMProviderSetting

LLMProvider = Literal["auto", "adapter", "local", "endpoint"]
ALL_LLM_PROVIDERS: tuple[LLMProvider, ...] = ("auto", "adapter", "local", "endpoint")


@dataclass(frozen=True)
class RuntimeLLMConfig:
    provider: LLMProvider
    base_url: str
    model: str
    api_key: str
    source: Literal["environment", "database", "account"]

    @property
    def api_key_configured(self) -> bool:
        return bool(self.api_key)

    @property
    def configured(self) -> bool:
        if self.provider == "adapter":
            return bool(settings.adapter_base_url)
        if self.provider in {"endpoint", "local"}:
            return bool(self.base_url and self.model and (self.api_key or self.provider == "local"))
        return bool(self.base_url and self.model)


def _cipher() -> Fernet:
    derived = hmac.new(
        settings.api_key_pepper.encode("utf-8"),
        b"prewise:llm-provider-credential:v1",
        sha256,
    ).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def _encrypt(value: str) -> str:
    return _cipher().encrypt(value.encode("utf-8")).decode("ascii") if value else ""


def _decrypt(value: str) -> str:
    if not value:
        return ""
    try:
        return _cipher().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise ValueError("Không thể giải mã API key; hãy nhập lại khóa trong Cài đặt AI.") from exc


def normalize_provider_url(value: str, *, provider: LLMProvider) -> str:
    raw = value.strip().rstrip("/")
    if provider in {"auto", "adapter"} and not raw:
        return ""
    parsed = urlsplit(raw)
    if (
        not parsed.scheme
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not _is_https_or_loopback(raw)
    ):
        raise ValueError("Endpoint phải dùng HTTPS; HTTP chỉ được phép với localhost/127.0.0.1.")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def environment_llm_config() -> RuntimeLLMConfig:
    provider = settings.llm_provider
    if provider == "local":
        return RuntimeLLMConfig(
            provider="local",
            base_url=settings.ollama_base_url.rstrip("/") + "/v1",
            model=settings.ollama_model,
            api_key="",
            source="environment",
        )
    return RuntimeLLMConfig(
        provider=provider,
        base_url=settings.llm_base_url.rstrip("/"),
        model=settings.llm_model,
        api_key=settings.llm_api_key,
        source="environment",
    )


def get_runtime_llm_config(
    db: DbSession | None = None, *, user_id: str | None = None
) -> RuntimeLLMConfig:
    if db is None:
        # Import lazily to keep model/config imports acyclic.
        from backend.db import SessionLocal, initialize_database

        initialize_database()
        with SessionLocal() as session:
            return get_runtime_llm_config(session, user_id=user_id)
    if user_id:
        account_record = db.get(UserLLMProviderSetting, user_id)
        if account_record is not None:
            policy = get_user_llm_policy(db)
            provider_allowed = account_record.provider in policy["allowedProviders"]
            model_allowed = (
                not policy["allowedModels"]
                or account_record.model in policy["allowedModels"]
            )
            if provider_allowed and model_allowed:
                return RuntimeLLMConfig(
                    provider=account_record.provider,  # type: ignore[arg-type]
                    base_url=account_record.base_url,
                    model=account_record.model,
                    api_key=_decrypt(account_record.api_key_ciphertext),
                    source="account",
                )
    record = db.get(LLMProviderSetting, "default")
    if record is None:
        return environment_llm_config()
    return RuntimeLLMConfig(
        provider=record.provider,  # type: ignore[arg-type]
        base_url=record.base_url,
        model=record.model,
        api_key=_decrypt(record.api_key_ciphertext),
        source="database",
    )


def get_user_llm_policy(db: DbSession) -> dict[str, list[str]]:
    record = db.get(LLMProviderSetting, "default")
    providers = list(record.allowed_user_providers or []) if record else list(ALL_LLM_PROVIDERS)
    providers = [item for item in providers if item in ALL_LLM_PROVIDERS]
    if "auto" not in providers:
        providers.insert(0, "auto")
    models = list(record.allowed_user_models or []) if record else []
    return {
        "allowedProviders": list(dict.fromkeys(providers)),
        "allowedModels": list(dict.fromkeys(str(item).strip() for item in models if str(item).strip())),
    }


def validate_user_llm_choice(
    db: DbSession, *, provider: LLMProvider, model: str
) -> None:
    policy = get_user_llm_policy(db)
    if provider not in policy["allowedProviders"]:
        raise ValueError("Provider này đã bị admin vô hiệu hóa cho tài khoản cá nhân.")
    normalized_model = model.strip()
    if provider != "auto" and policy["allowedModels"] and normalized_model not in policy["allowedModels"]:
        raise ValueError("Model này không nằm trong danh sách admin cho phép.")


def save_user_llm_config(
    db: DbSession,
    *,
    user_id: str,
    provider: LLMProvider,
    base_url: str,
    model: str,
    api_key: str | None,
    clear_api_key: bool,
    commit: bool = True,
) -> RuntimeLLMConfig:
    validate_user_llm_choice(db, provider=provider, model=model)
    normalized_url = normalize_provider_url(base_url, provider=provider)
    normalized_model = model.strip()
    if provider in {"endpoint", "local"} and not normalized_model:
        raise ValueError("Hãy nhập model ID chính xác của endpoint.")
    record = db.get(UserLLMProviderSetting, user_id)
    if provider == "auto" and not normalized_url and not normalized_model and not api_key:
        if record is not None:
            db.delete(record)
            if commit:
                db.commit()
        return get_runtime_llm_config(db)
    current_key = _decrypt(record.api_key_ciphertext) if record else ""
    next_key = "" if clear_api_key else api_key.strip() if api_key is not None else current_key
    if provider == "endpoint" and not next_key:
        raise ValueError("Chế độ API endpoint yêu cầu API key.")
    if provider == "local":
        next_key = ""
    if record is None:
        record = UserLLMProviderSetting(user_id=user_id)
        db.add(record)
    record.provider = provider
    record.base_url = normalized_url
    record.model = normalized_model
    record.api_key_ciphertext = _encrypt(next_key)
    if commit:
        db.commit()
        db.refresh(record)
    else:
        db.flush()
    return RuntimeLLMConfig(
        provider=provider,
        base_url=normalized_url,
        model=normalized_model,
        api_key=next_key,
        source="account",
    )


def save_runtime_llm_config(
    db: DbSession,
    *,
    provider: LLMProvider,
    base_url: str,
    model: str,
    api_key: str | None,
    clear_api_key: bool,
    updated_by_user_id: str,
    allowed_user_providers: list[str] | None = None,
    allowed_user_models: list[str] | None = None,
) -> RuntimeLLMConfig:
    normalized_url = normalize_provider_url(base_url, provider=provider)
    normalized_model = model.strip()
    if provider in {"endpoint", "local"} and not normalized_model:
        raise ValueError("Hãy nhập model ID chính xác của endpoint.")
    record = db.get(LLMProviderSetting, "default")
    current_key = _decrypt(record.api_key_ciphertext) if record else ""
    next_key = "" if clear_api_key else api_key.strip() if api_key is not None else current_key
    if provider == "endpoint" and not next_key:
        raise ValueError("Chế độ API endpoint yêu cầu API key.")
    if provider == "local":
        next_key = ""
    if record is None:
        record = LLMProviderSetting(id="default")
        db.add(record)
    record.provider = provider
    record.base_url = normalized_url
    record.model = normalized_model
    record.api_key_ciphertext = _encrypt(next_key)
    if allowed_user_providers is not None:
        normalized_providers = list(dict.fromkeys(item.strip() for item in allowed_user_providers))
        if any(item not in ALL_LLM_PROVIDERS for item in normalized_providers):
            raise ValueError("Danh sách provider cá nhân không hợp lệ.")
        if "auto" not in normalized_providers:
            normalized_providers.insert(0, "auto")
        record.allowed_user_providers = normalized_providers
    if allowed_user_models is not None:
        record.allowed_user_models = list(
            dict.fromkeys(item.strip() for item in allowed_user_models if item.strip())
        )
    record.updated_by_user_id = updated_by_user_id
    db.commit()
    db.refresh(record)
    return get_runtime_llm_config(db)


def safe_config_payload(config: RuntimeLLMConfig) -> dict:
    return {
        "provider": config.provider,
        "baseUrl": config.base_url,
        "model": config.model,
        "apiKeyConfigured": config.api_key_configured,
        "configured": config.configured,
        "source": config.source,
    }


def test_runtime_llm_config(config: RuntimeLLMConfig) -> dict:
    if config.provider not in {"endpoint", "local"} or not config.base_url:
        raise ValueError("Chỉ kiểm tra được endpoint OpenAI-compatible hoặc local.")
    base = config.base_url if config.base_url.endswith("/v1") else config.base_url + "/v1"
    headers = {"Authorization": f"Bearer {config.api_key}"} if config.api_key else {}
    with httpx.Client(timeout=httpx.Timeout(15, connect=5)) as client:
        response = client.get(f"{base}/models", headers=headers)
        response.raise_for_status()
        payload = response.json()
        models = [
            str(item.get("id", ""))
            for item in payload.get("data", [])
            if isinstance(item, dict) and item.get("id")
        ] if isinstance(payload, dict) else []
        completion = client.post(
            f"{base}/chat/completions",
            headers=headers,
            json={
                "model": config.model,
                "messages": [{"role": "user", "content": "Reply only: OK"}],
                "temperature": 0,
                "max_tokens": 8,
                "stream": False,
            },
        )
        completion.raise_for_status()
    return {
        "ok": True,
        "modelAvailable": not models or config.model in models,
        "modelsCount": len(models),
        "completionOk": True,
    }
