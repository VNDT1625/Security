from __future__ import annotations

from mcp_server.tools import MCPTools, URLInput
from shared.schemas import AssessResponse, Decision, Modality, RiskLevel
from shared.trusted_popular_domains import (
    TRUSTED_POPULAR_DOMAINS,
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


def test_mcp_routes_popular_domains_through_the_unified_core() -> None:
    class RecordingService:
        called = False

        def assess_url(self, *_args, **_kwargs):
            self.called = True
            return AssessResponse(
                risk_score=0.0,
                risk_level=RiskLevel.SAFE,
                decision=Decision.ALLOW,
                confidence=0.8,
                modality=Modality.URL,
            )

    service = RecordingService()
    MCPTools(service=service).assess_url(
        URLInput(url="https://chatgpt.com/", context="")
    )
    assert service.called is True
