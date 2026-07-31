from types import SimpleNamespace

from security.browser_sandbox_worker import _issues_from_signals
from security.dns_intelligence import DNSIntelligence
from security.domain_intelligence import DomainIntelligence
from security.risk_core import CriterionStatus, assess, default_config
from security.risk_core.detectors import (
    ScanObservations,
    add_browser_sandbox,
    add_cross_source_intelligence,
    add_dns_intelligence,
    add_domain_intelligence,
    add_http_sandbox,
    add_structured_observations,
    build_criteria_evidence,
)
from security.sandbox_worker import _inspect_html
from security.scan_history import LocalScanHistory
from shared.schemas import (
    BrowserSandboxURLResponse,
    SandboxIssue,
    SandboxURLResponse,
    Severity,
)


RISK_STATUSES = {CriterionStatus.SUSPICIOUS, CriterionStatus.MALICIOUS}


def _by_id(observations: ScanObservations):
    return {
        item.criterion_id: item
        for item in build_criteria_evidence(observations, default_config())
    }


def test_http_collectors_activate_criteria_31_32_36_46_47_48_49():
    url = "https://shop.example.test"
    ratings = " ".join(["5/5"] * 10)
    html = f"""
        <html>
          <head>
            <title>Alpha Shop</title>
            <meta property="og:site_name" content="Omega Market">
            <script src="http://8.8.8.8/payload.js"></script>
          </head>
          <body>
            Buy now. Urgent. Pay with crypto.
            Account: 123456789012.
            Scam complaint. {ratings}
          </body>
        </html>
    """
    inspected, raw_issues = _inspect_html(
        html.encode(),
        "text/html; charset=utf-8",
        url,
    )
    report = SandboxURLResponse(
        ok=True,
        execution_status="completed",
        url=url,
        page_title=inspected["page_title"],
        page_signals=inspected["page_signals"],
        issues=[SandboxIssue.model_validate(issue) for issue in raw_issues],
    )
    observations = ScanObservations(url)
    add_http_sandbox(observations, report)
    by_id = _by_id(observations)

    for criterion_id in (31, 32, 36, 46, 47, 48, 49):
        assert by_id[criterion_id].status in RISK_STATUSES


def test_browser_collectors_activate_criteria_33_34_35_36_37_38_40():
    url = "https://shop.example.test"
    browser_events = [
        {"type": "permission_request_blocked", "permission": "notifications"},
        {"type": "popup_open_blocked", "url": "https://ads.example/popup"},
    ]
    network_events = [
        {
            "url": "http://8.8.8.8/payload.js",
            "resource_type": "script",
            "same_origin": False,
            "blocked": False,
            "reason": "",
        },
        {
            "url": "http://127.0.0.1/admin",
            "resource_type": "fetch",
            "same_origin": False,
            "blocked": True,
            "reason": "private_network_blocked",
        },
        {
            "url": "https://doubleclick.net/ad.js",
            "resource_type": "script",
            "same_origin": False,
            "blocked": False,
            "reason": "",
        },
    ]
    raw_issues = _issues_from_signals(
        {},
        browser_events,
        network_events,
        {},
        [{"filename": "invoice.exe", "url": "https://shop.example.test/invoice.exe"}],
    )
    raw_issues.append(
        {
            "code": "forged_brand_image",
            "severity": "high",
            "category": "visual",
            "message": "Curated brand-image reference matched on an unofficial domain.",
            "detail": "",
        }
    )
    report = BrowserSandboxURLResponse(
        ok=True,
        execution_status="completed",
        url=url,
        issues=[SandboxIssue.model_validate(issue) for issue in raw_issues],
    )
    observations = ScanObservations(url)
    add_browser_sandbox(observations, report)
    by_id = _by_id(observations)

    for criterion_id in (33, 34, 35, 36, 37, 38, 40):
        assert by_id[criterion_id].status in RISK_STATUSES


def test_pro_ai_observations_activate_context_only_criteria_39_and_41():
    observations = ScanObservations("https://shop.example.test")
    add_structured_observations(
        observations,
        {
            "source": "web_context:test-adapter",
            "impersonating_copied_content": {
                "severity": 0.8,
                "quality": 0.9,
                "summary": "Content matches a referenced brand page on an unrelated domain.",
            },
            "social_identity_conflict": {
                "severity": 0.75,
                "quality": 0.8,
                "summary": "Linked social profile identifies a different business.",
            },
        },
    )
    by_id = _by_id(observations)

    assert by_id[39].status in RISK_STATUSES
    assert by_id[41].status in RISK_STATUSES


def test_history_dns_and_reputation_activate_criteria_42_to_45_and_total(tmp_path):
    url = "https://shop.example.test"
    domain = DomainIntelligence(
        domain="example.test",
        age_days=900,
        created_at="2024-01-01T00:00:00Z",
        registrar="Example Registrar",
        reputation_status="listed",
        reputation_source="public-test-feed",
        listed=True,
        score=1.0,
        reasons=("malicious history",),
        available=True,
        expiry_days=300,
        registrant="Example Company",
        registration_available=True,
        reputation_ips=("8.8.8.8",),
        malicious_ips=("8.8.8.8",),
        malicious_observations=3,
    )
    history = LocalScanHistory(tmp_path / "history.json")
    observations = None

    for index, ip in enumerate(("8.8.8.8", "1.1.1.1", "9.9.9.9"), start=1):
        dns = DNSIntelligence(
            "example.test",
            (ip,),
            (f"ns{index}.example.test",),
            ("mx.example.test",),
            True,
            False,
            False,
            True,
            (),
        )
        http = SandboxURLResponse(
            ok=True,
            execution_status="completed",
            url=url,
            page_title=f"Shop identity {index}",
            page_signals={
                "is_commercial": False,
                "content_fingerprint": f"fingerprint-{index}",
            },
        )
        observations = ScanObservations(url)
        add_domain_intelligence(observations, domain)
        add_dns_intelligence(observations, dns)
        add_cross_source_intelligence(
            observations,
            domain_intelligence=domain,
            dns_intelligence=dns,
            ip_intelligence=SimpleNamespace(
                ip=ip,
                country_code="",
                as_name="Example Network",
                isp="Example Network",
            ),
            sandbox_reports=((http, False),),
            history_store=history,
        )

    assert observations is not None
    config = default_config()
    evidence = build_criteria_evidence(observations, config)
    by_id = {item.criterion_id: item for item in evidence}

    for criterion_id in (42, 43, 44, 45):
        assert by_id[criterion_id].status in RISK_STATUSES
    assert by_id[50].status == CriterionStatus.CLEAN
    assert config.criteria[49].max_weight == 0
    assert assess(evidence, config=config).risk_score > 0
