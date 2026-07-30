from types import SimpleNamespace

from security.domain_intelligence import DomainIntelligenceService
from security.risk_core import CriterionStatus, default_config
from security.risk_core.brand_content import assess_brand_content
from security.risk_core.contact_information import assess_contact_information
from security.risk_core.detectors import (
    ScanObservations,
    add_cross_source_intelligence,
    add_domain_intelligence,
    add_http_sandbox,
    build_criteria_evidence,
)
from security.risk_core.redirect_chain import assess_redirect_chain
from shared.schemas import SandboxURLResponse


def _domain(**overrides):
    values = {
        "available": True,
        "registration_available": True,
        "registration_source": "RDAP",
        "age_days": 900,
        "expiry_days": 900,
        "expires_at": None,
        "certificate_age_days": 300,
        "registrant": None,
        "registrar": "Example Registrar",
        "registrar_candidates": ("Example Registrar",),
        "listed": False,
        "reputation_source": "urlscan.io",
        "malicious_observations": 0,
        "reputation_ips": (),
        "malicious_ips": (),
        "shared_hosting_available": False,
        "shared_malicious_domains": (),
        "shared_malicious_observations": 0,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _by_id(observations):
    return {
        item.criterion_id: item
        for item in build_criteria_evidence(observations, default_config())
    }


def test_server_location_is_zero_weight_context_and_blacklist_gets_weight():
    config = default_config()
    assert config.criteria[10].max_weight == 4
    assert config.criteria[13].max_weight == 0
    assert sum(item.max_weight for item in config.criteria[:49]) == 80


def test_blacklist_and_repeated_domain_reputation_are_distinct():
    observations = ScanObservations("https://bad.example")
    add_domain_intelligence(
        observations,
        _domain(listed=True, malicious_observations=4),
    )
    by_id = _by_id(observations)
    assert by_id[11].status == CriterionStatus.MALICIOUS
    assert by_id[12].status == CriterionStatus.SUSPICIOUS


def test_ip_reputation_is_not_falsely_clean_without_current_ip_observation():
    observations = ScanObservations("https://example.test")
    add_cross_source_intelligence(
        observations,
        domain_intelligence=_domain(),
        dns_intelligence=SimpleNamespace(addresses=("203.0.113.10",), domain="example.test"),
        ip_intelligence=SimpleNamespace(
            ip="203.0.113.10", country_code="US", as_name="", isp=""
        ),
    )
    assert _by_id(observations)[13].status == CriterionStatus.UNAVAILABLE


def test_shared_hosting_requires_other_malicious_domains():
    observations = ScanObservations("https://example.test")
    add_cross_source_intelligence(
        observations,
        domain_intelligence=_domain(
            shared_hosting_available=True,
            shared_malicious_domains=("bad-one.test", "bad-two.test", "bad-three.test"),
            shared_malicious_observations=7,
        ),
        dns_intelligence=SimpleNamespace(addresses=("203.0.113.10",), domain="example.test"),
        ip_intelligence=SimpleNamespace(
            ip="203.0.113.10", country_code="US", as_name="Example Hosting", isp=""
        ),
    )
    assert _by_id(observations)[15].status == CriterionStatus.SUSPICIOUS


def test_reverse_ip_history_excludes_the_current_domain(monkeypatch):
    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {
                "results": [
                    {
                        "page": {"domain": "login.example.test"},
                        "verdicts": {"overall": {"malicious": True}},
                    },
                    {
                        "page": {"domain": "unrelated-bad.test"},
                        "verdicts": {"overall": {"malicious": True}},
                    },
                ]
            }

    monkeypatch.setattr("security.domain_intelligence.httpx.get", lambda *a, **k: Response())
    service = DomainIntelligenceService()
    enriched = service._add_shared_hosting_history(
        "example.test",
        {"results": [{"page": {"ip": "8.8.8.8"}}]},
    )

    assert enriched["shared_hosting_available"] is True
    assert enriched["shared_malicious_domains"] == ["unrelated-bad.test"]
    assert enriched["shared_malicious_observations"] == 1


def test_server_country_is_context_only():
    observations = ScanObservations("https://shop.example.test")
    browser = SimpleNamespace(
        page_identity={
            "is_commercial": True,
            "addresses": ["123 Example Road, Viet Nam"],
            "legal_names": [],
        },
        visual_analysis={},
        page_title="",
    )
    add_cross_source_intelligence(
        observations,
        domain_intelligence=_domain(),
        dns_intelligence=SimpleNamespace(addresses=("203.0.113.10",), domain="example.test"),
        ip_intelligence=SimpleNamespace(
            ip="203.0.113.10", country_code="US", as_name="Example Hosting", isp=""
        ),
        sandbox_reports=((browser, True),),
    )
    assert _by_id(observations)[14].status == CriterionStatus.NOT_APPLICABLE


def test_redirect_chain_detects_https_downgrade():
    result = assess_redirect_chain(
        "https://example.test",
        redirects=[
            {
                "from_url": "https://example.test",
                "to_url": "http://other.test/login",
            }
        ],
        final_url="http://other.test/login",
    )
    assert result.status == "suspicious"
    assert "https_downgrade" in result.metadata["issues"]


def test_shortlink_expansion_without_anomaly_is_not_redirect_anomaly():
    result = assess_redirect_chain(
        "https://bit.ly/demo",
        redirects=[
            {
                "from_url": "https://bit.ly/demo",
                "to_url": "https://example.test/",
            }
        ],
        final_url="https://example.test/",
    )
    assert result.status == "clean"
    assert result.shortlink_expanded is True


def test_brand_claim_on_unofficial_domain_is_detected_without_visual_registry():
    result = assess_brand_content(
        "https://secure-login.example/paypal",
        site_name="PayPal",
        password_fields=1,
    )
    assert result.status == "suspicious"
    assert result.claimed_brand == "paypal"


def test_official_brand_content_is_clean():
    result = assess_brand_content(
        "https://www.paypal.com/signin",
        site_name="PayPal",
        password_fields=1,
    )
    assert result.status == "clean"


def test_contact_requires_a_real_channel_not_just_the_word_contact():
    result = assess_contact_information(
        commercial=True,
        emails=(),
        phones=(),
        support_links=(),
    )
    assert result.status == "suspicious"


def test_http_report_integrates_redirect_and_contact_checks():
    report = SandboxURLResponse(
        ok=True,
        execution_status="completed",
        url="https://bit.ly/demo",
        final_url="https://shop.example.test/",
        redirects=[
            {
                "status_code": 302,
                "from_url": "https://bit.ly/demo",
                "to_url": "https://shop.example.test/",
            }
        ],
        page_signals={
            "is_commercial": True,
            "emails": ["support@shop.example.test"],
            "phones": [],
            "support_links": ["mailto:support@shop.example.test"],
        },
    )
    observations = ScanObservations(report.url)
    add_http_sandbox(observations, report)
    by_id = _by_id(observations)
    assert by_id[16].status == CriterionStatus.CLEAN
    assert by_id[17].status == CriterionStatus.SUSPICIOUS
    assert by_id[20].status == CriterionStatus.CLEAN
