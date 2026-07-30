"""Shared singletons for the gateway (model/service injection)."""

from __future__ import annotations

from functools import lru_cache

from sqlalchemy.orm import Session as DbSession

from ai.inference.engine import InferenceEngine
from backend.config import settings
from backend.services.adapter_registry import AdapterRegistry
from backend.services.deepfake_service import DeepfakeImageService
from backend.services.explanation_service import ExplanationService
from backend.services.inference_service import InferenceService
from backend.services.legal_answer_service import LegalAnswerService, OpenAIJSONGenerator
from backend.services.llm_provider_config_service import (
    RuntimeLLMConfig,
    get_runtime_llm_config,
    target_keeps_data_local,
)
from security.policy_engine import PolicyEngine


@lru_cache
def get_adapter_registry() -> AdapterRegistry:
    runtime = get_runtime_llm_config()
    return _build_adapter_registry(runtime)


def _build_adapter_registry(runtime: RuntimeLLMConfig) -> AdapterRegistry:
    use_generic_endpoint = runtime.provider in {"endpoint", "local"} or (
        runtime.provider == "auto" and bool(runtime.base_url)
    )
    return AdapterRegistry(
        settings.adapter_manifest_path,
        base_url=runtime.base_url if use_generic_endpoint else settings.adapter_base_url,
        api_key=runtime.api_key if use_generic_endpoint else settings.adapter_api_key,
        model_name=runtime.model if use_generic_endpoint else "",
        default_timeout_seconds=settings.adapter_timeout_seconds,
        enabled=settings.adapter_registry_enabled,
    )


@lru_cache
def get_inference_service() -> InferenceService:
    engine = InferenceEngine(model_dir=settings.model_dir)
    policy = PolicyEngine(
        block=settings.risk_threshold_block,
        warn=settings.risk_threshold_warn,
        allow=settings.risk_threshold_allow,
    )
    return InferenceService(
        engine=engine,
        policy=policy,
        adapter_registry=get_adapter_registry(),
        adapter_max_risk_contribution=settings.adapter_max_risk_contribution,
    )


@lru_cache
def get_explanation_service() -> ExplanationService:
    runtime = get_runtime_llm_config()
    return _build_explanation_service(runtime, get_adapter_registry())


def _build_explanation_service(
    runtime: RuntimeLLMConfig,
    adapter_registry: AdapterRegistry,
) -> ExplanationService:
    provider = runtime.provider
    if provider == "adapter":
        return ExplanationService(
            model=runtime.model or "prewise-security-v1",
            adapter_registry=adapter_registry,
            provider="adapter",
        )

    # Preserve existing deployments unless they make an explicit replacement:
    # the manifest-driven adapter remains the first choice in auto mode.
    if provider == "auto":
        use_external_fallback = bool(runtime.base_url)
        return ExplanationService(
            model=runtime.model if use_external_fallback else settings.ollama_model,
            base_url=(
                runtime.base_url
                if use_external_fallback
                else settings.ollama_base_url.rstrip("/") + "/v1"
            ),
            api_key=runtime.api_key if use_external_fallback else "",
            timeout_seconds=settings.llm_timeout_seconds,
            max_tokens=settings.llm_max_tokens,
            adapter_registry=adapter_registry,
            provider="auto",
            allow_user_question=use_external_fallback,
            # The fallback might be an external endpoint, so retain the
            # endpoint's data-minimisation contract in auto mode as well.
            allow_user_content=False,
        )

    use_external = provider == "endpoint"
    if use_external:
        base_url = runtime.base_url
        model = runtime.model
        api_key = runtime.api_key
    else:
        base_url = runtime.base_url or settings.ollama_base_url.rstrip("/") + "/v1"
        model = runtime.model or settings.ollama_model
        api_key = ""
    # "local" is a label the caller chose, not a property of the URL. Scanned
    # emails and messages may only be sent to a host that actually resolves to
    # this machine, so a provider labelled "local" but pointing at a remote
    # collector is treated as external for data-minimisation purposes.
    keeps_data_local = target_keeps_data_local(base_url)
    return ExplanationService(
        model=model,
        base_url=base_url,
        api_key=api_key,
        timeout_seconds=settings.llm_timeout_seconds,
        max_tokens=settings.llm_max_tokens,
        # A user-selected local or external model replaces the adapter server,
        # rather than silently falling back to it.
        adapter_registry=None,
        provider="endpoint" if use_external else "local",
        allow_user_content=not use_external and keeps_data_local,
        allow_user_question=True,
    )


def get_user_inference_service(
    db: DbSession, user_id: str | None
) -> InferenceService:
    """Resolve provider policy per request while sharing the heavy core models.

    Reading the lightweight provider record on every request makes an Admin
    update visible in every backend worker, not only the worker handling PUT.
    """
    runtime = get_runtime_llm_config(db, user_id=user_id)
    shared = get_inference_service()
    return InferenceService(
        engine=shared.engine,
        policy=shared.policy,
        adapter_registry=_build_adapter_registry(runtime),
        adapter_max_risk_contribution=settings.adapter_max_risk_contribution,
        action_risk_engine=shared.action_risk_engine,
        security_core_mode=shared.security_core_mode,
    )


def get_user_explanation_service(
    db: DbSession, user_id: str | None
) -> ExplanationService:
    runtime = get_runtime_llm_config(db, user_id=user_id)
    return _build_explanation_service(runtime, _build_adapter_registry(runtime))


def get_user_legal_answer_service(db: DbSession, user_id: str | None) -> LegalAnswerService:
    """Build the legal answer guard with the account's configured JSON-capable model."""
    runtime = get_runtime_llm_config(db, user_id=user_id) if user_id else get_runtime_llm_config()
    base_url = runtime.base_url
    model = runtime.model
    api_key = runtime.api_key
    if runtime.provider == "adapter":
        base_url = settings.adapter_base_url
        model = settings.legal_adapter_model
        api_key = settings.adapter_api_key
    elif runtime.provider in {"auto", "local"} and not base_url:
        base_url = settings.ollama_base_url.rstrip("/") + "/v1"
        model = model or settings.ollama_model
        api_key = ""
    generator = (
        OpenAIJSONGenerator(base_url, model, api_key, settings.llm_timeout_seconds)
        if base_url and model
        else None
    )
    return LegalAnswerService(generator=generator)


@lru_cache
def get_deepfake_service() -> DeepfakeImageService:
    return DeepfakeImageService(model_path=settings.deepfake_model_path)
