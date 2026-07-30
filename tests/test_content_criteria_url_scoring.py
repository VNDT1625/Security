from security import sandbox_worker
from security.risk_core import CriterionStatus, assess, default_config
from security.risk_core.detectors import (
    ScanObservations,
    add_browser_sandbox,
    add_http_sandbox,
    build_criteria_evidence,
)
from shared.schemas import BrowserSandboxURLResponse, SandboxURLResponse

RISK_STATUSES = {CriterionStatus.SUSPICIOUS, CriterionStatus.MALICIOUS}


def _http_report(url: str, html: bytes) -> SandboxURLResponse:
    inspected, raw_issues = sandbox_worker._inspect_html(
        html,
        "text/html; charset=utf-8",
        url,
    )
    return SandboxURLResponse(
        ok=True,
        execution_status="completed",
        url=url,
        page_title=inspected["page_title"],
        page_signals=inspected["page_signals"],
        issues=raw_issues,
    )


def _criteria(observations: ScanObservations):
    result = assess(
        build_criteria_evidence(observations, default_config()),
        config=default_config(),
    )
    return {item.criterion_id: item for item in result.criteria}


def test_http_url_scores_every_criterion_from_20_through_30() -> None:
    url = "https://fake-prize.example/checkout"
    missing_contact = _http_report(
        url,
        b"<html><body><h1>Buy now</h1></body></html>",
    )
    contact_observations = ScanObservations(url)
    add_http_sandbox(contact_observations, missing_contact)
    assert _criteria(contact_observations)[20].status in RISK_STATUSES

    risky_report = _http_report(
        url,
        b"""
        <html><head><title>Urgent prize checkout</title></head><body>
          <h1>Buy now - 95% off</h1>
          <p>Act now. Contact billing@unrelated.example.</p>
          <p>Lorem ipsum. Insert text here. Placeholder placeholder placeholder.</p>
          <p>Placeholder placeholder placeholder placeholder placeholder placeholder.</p>
          <form action="https://collector.example/submit">
            <input type="password" name="recovery_seed_phrase">
          </form>
        </body></html>
        """,
    )
    observations = ScanObservations(url)
    add_http_sandbox(observations, risky_report)
    by_id = _criteria(observations)

    for criterion_id in range(21, 31):
        assert by_id[criterion_id].status in RISK_STATUSES, (
            criterion_id,
            by_id[criterion_id].status,
        )
        assert by_id[criterion_id].adjusted_score > 0, criterion_id


def test_javascript_rendered_url_scores_every_criterion_from_20_through_30() -> None:
    url = "https://dynamic-fake-shop.example/checkout"
    no_contact = BrowserSandboxURLResponse(
        ok=True,
        execution_status="completed",
        url=url,
        final_url=url,
        page_identity={"is_commercial": True},
    )
    contact_observations = ScanObservations(url)
    add_browser_sandbox(contact_observations, no_contact)
    assert _criteria(contact_observations)[20].status in RISK_STATUSES

    report = BrowserSandboxURLResponse(
        ok=True,
        execution_status="completed",
        url=url,
        final_url=url,
        page_title="Urgent prize checkout",
        visual_analysis={"status": "no_reference"},
        page_identity={
            "is_commercial": True,
            "support_links": [],
            "phones": [],
            "emails": ["billing@unrelated.example"],
            "addresses": [],
            "legal_names": [],
            "business_ids": [],
            "sensitive_fields": 2,
            "high_risk_sensitive_fields": ["recovery seed phrase"],
            "privacy_policy_links": [],
            "terms_links": [],
            "refund_links": [],
            "word_count": 100,
            "unique_word_ratio": 0.1,
            "placeholder_hits": ["lorem ipsum", "your company name"],
            "max_discount_percent": 95,
            "urgency_hits": ["act now"],
            "payment_recipient_hints": [],
        },
        issues=[
            {
                "code": "password_input_detected",
                "severity": "high",
                "category": "credential",
                "message": "Password field detected.",
            },
            {
                "code": "cross_origin_form_action",
                "severity": "critical",
                "category": "credential",
                "message": "Sensitive form posts to another origin.",
            },
        ],
    )
    observations = ScanObservations(url)
    add_browser_sandbox(observations, report)
    by_id = _criteria(observations)

    for criterion_id in range(21, 31):
        assert by_id[criterion_id].status in RISK_STATUSES, (
            criterion_id,
            by_id[criterion_id].status,
        )
        assert by_id[criterion_id].adjusted_score > 0, criterion_id


def test_price_and_payment_brand_in_advertising_do_not_make_url_commercial() -> None:
    report = _http_report(
        "https://utility.example.test",
        b"""
        <html><body>
          <form><input name="otp" autocomplete="one-time-code"></form>
          <aside>Advertising: VISA service, plans mentioned at $250.</aside>
        </body></html>
        """,
    )

    assert report.page_signals["is_commercial"] is False
