from backend import dependencies
from backend.services.legal_answer_service import OpenAIJSONGenerator
from backend.services.llm_provider_config_service import RuntimeLLMConfig


def test_legal_pipeline_uses_dedicated_adapter_model(monkeypatch) -> None:
    runtime = RuntimeLLMConfig(
        provider="adapter",
        base_url="",
        model="",
        api_key="",
        source="environment",
    )
    monkeypatch.setattr(dependencies, "get_runtime_llm_config", lambda *_args, **_kwargs: runtime)
    monkeypatch.setattr(dependencies.settings, "adapter_base_url", "https://gpu.example/v1")
    monkeypatch.setattr(dependencies.settings, "adapter_api_key", "adapter-secret")
    monkeypatch.setattr(dependencies.settings, "legal_adapter_model", "prewise-legal-rag")

    service = dependencies.get_user_legal_answer_service(object(), "user-1")  # type: ignore[arg-type]

    assert isinstance(service.generator, OpenAIJSONGenerator)
    assert service.generator.base_url == "https://gpu.example/v1"
    assert service.generator.model == "prewise-legal-rag"
    assert service.generator.api_key == "adapter-secret"


def test_legal_pipeline_fails_closed_without_adapter_endpoint(monkeypatch) -> None:
    runtime = RuntimeLLMConfig(
        provider="adapter",
        base_url="",
        model="",
        api_key="",
        source="environment",
    )
    monkeypatch.setattr(dependencies, "get_runtime_llm_config", lambda *_args, **_kwargs: runtime)
    monkeypatch.setattr(dependencies.settings, "adapter_base_url", "")

    service = dependencies.get_user_legal_answer_service(object(), "user-1")  # type: ignore[arg-type]

    assert service.generator is None
