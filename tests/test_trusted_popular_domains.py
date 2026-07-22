from __future__ import annotations

from mcp_server.tools import MCPTools, URLInput
from shared.schemas import Decision
from shared.trusted_popular_domains import (
    TRUSTED_POPULAR_DOMAINS,
    trusted_popular_assessment,
    trusted_popular_domain,
)


def test_popular_domain_database_has_exactly_100_entries() -> None:
    assert len(TRUSTED_POPULAR_DOMAINS) == 100
    assert len(set(TRUSTED_POPULAR_DOMAINS)) == 100


def test_exact_domain_and_subdomain_are_trusted() -> None:
    assert trusted_popular_domain("https://youtube.com/watch?v=1") == "youtube.com"
    assert trusted_popular_domain("https://mail.google.com/mail/u/0/") == "google.com"
    assert trusted_popular_domain("https://chatgpt.com/") == "chatgpt.com"


def test_lookalike_and_non_http_urls_are_not_trusted() -> None:
    assert trusted_popular_domain("https://youtube.com.attacker.example/") is None
    assert trusted_popular_domain("https://notyoutube.com/") is None
    assert trusted_popular_domain("javascript:https://youtube.com") is None


def test_trusted_assessment_is_an_immediate_safe_policy_result() -> None:
    result = trusted_popular_assessment("https://www.youtube.com/")
    assert result is not None
    assert result.risk_score == 0
    assert result.decision is Decision.ALLOW
    assert result.latency_ms == 0
    assert result.model_version == "trusted-popular-domains-v1"


def test_mcp_bypasses_inference_service_for_trusted_domain() -> None:
    class FailingService:
        def assess_url(self, *_args, **_kwargs):
            raise AssertionError("trusted domain must not reach inference")

    response = MCPTools(service=FailingService()).assess_url(
        URLInput(url="https://chatgpt.com/", context="")
    )
    assert response["risk_score"] == 0
    assert response["verdict"] == "ALLOW"
