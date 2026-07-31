from security import urlvet_adapter
from security.risk_core.types import CriterionStatus, ProviderVerdict


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def _payload(*, risky: bool = False):
    return {
        "features": {
            "tld": {"is_risky_tld": risky},
            "url": {
                "uses_ip": False,
                "contains_punycode": risky,
                "has_homoglyph": risky,
                "url_shortener": False,
                "too_long": False,
                "too_deep": False,
                "subdomain_count": 0,
                "keywords": {"has_keywords": risky, "found": ["login"] if risky else []},
            },
        },
        "analysis": {"redirection_result": {"has_domain_jump": False}},
        "tls_info": {"Present": True, "HostnameMismatch": False},
        "ssl_info": {"HasTLS": True, "ChainValid": True, "IsSuspicious": False, "KnownBadChain": False},
        "domain_info": {"age_days": 5 if risky else 5000},
        "domain_randomness": {"IsSuspicious": risky},
        "typosquat_result": {"is_suspicious": risky},
        "content_data": {
            "has_login_form": risky,
            "has_payment_form": risky,
            "has_hidden_iframe": False,
            "forms": [{"has_password": risky, "is_external": risky}],
            "brand_check": {"is_mismatch": risky},
        },
        "phishing": {"valid": risky, "verified": risky},
        "result": {
            "verdict": "Risky" if risky else "Safe",
            "risk_score": 95 if risky else 5,
            "trust_score": 0 if risky else 95,
        },
        "incomplete": False,
    }


def test_urlvet_disabled_is_explicitly_not_checked(monkeypatch):
    monkeypatch.setattr(urlvet_adapter.httpx, "get", lambda *args, **kwargs: 1 / 0)
    evidence = urlvet_adapter.collect_urlvet("https://example.test", enabled=False)

    assert evidence[0].status == CriterionStatus.NOT_CHECKED
    assert evidence[0].metadata["adapter_status"] == "not_configured"


def test_urlvet_safe_scan_exposes_green_checklist(monkeypatch):
    monkeypatch.setattr(
        urlvet_adapter.httpx,
        "get",
        lambda *args, **kwargs: _Response(_payload()),
    )
    evidence = urlvet_adapter.collect_urlvet(
        "https://example.test", base_url="http://127.0.0.1:8080", enabled=True
    )

    assert len(evidence) == 1
    assert evidence[0].status == CriterionStatus.CLEAN
    assert evidence[0].provider_verdict == ProviderVerdict.CLEAN
    assert any(item["status"] == "safe" for item in evidence[0].metadata["checks"])
    context = evidence[0].metadata["feature_context"]
    assert context["tls_available"] == 1.0
    assert context["tls_hostname_match"] == 1.0
    assert context["dom_available"] == 1.0


def test_urlvet_risky_scan_maps_concrete_findings(monkeypatch):
    monkeypatch.setattr(
        urlvet_adapter.httpx,
        "get",
        lambda *args, **kwargs: _Response(_payload(risky=True)),
    )
    evidence = urlvet_adapter.collect_urlvet(
        "https://paypa1-login.test", base_url="http://localhost:8080", enabled=True
    )
    finding_types = {item.finding_type for item in evidence}

    assert evidence[0].status == CriterionStatus.MALICIOUS
    assert "urlvet_typosquat" in finding_types
    assert "urlvet_content_brand_mismatch" in finding_types
    assert "urlvet_external_form_action" in finding_types
    assert "urlvet_new_domain" in finding_types
    assert "urlvet_phishtank_confirmed" in finding_types
    assert any(
        check["status"] == "danger" for check in evidence[0].metadata["checks"]
    )


def test_urlvet_suspicious_aggregate_is_visible_but_not_scored_as_a_finding(monkeypatch):
    payload = _payload()
    payload["result"]["verdict"] = "Suspicious"
    monkeypatch.setattr(
        urlvet_adapter.httpx,
        "get",
        lambda *args, **kwargs: _Response(payload),
    )

    evidence = urlvet_adapter.collect_urlvet(
        "https://example.test/login",
        base_url="http://127.0.0.1:8080",
        enabled=True,
    )

    assert len(evidence) == 1
    assert evidence[0].status == CriterionStatus.SUSPICIOUS
    assert evidence[0].metadata["checks"][0]["status"] == "danger"


def test_login_or_payment_form_alone_is_context_not_risk(monkeypatch):
    payload = _payload()
    payload["content_data"]["has_login_form"] = True
    payload["content_data"]["has_payment_form"] = True
    payload["content_data"]["forms"] = [{"has_password": True, "is_external": False}]
    monkeypatch.setattr(
        urlvet_adapter.httpx,
        "get",
        lambda *args, **kwargs: _Response(payload),
    )

    evidence = urlvet_adapter.collect_urlvet(
        "https://accounts.example.test/login",
        base_url="http://127.0.0.1:8080",
        enabled=True,
    )

    findings = {item.finding_type for item in evidence[1:]}
    checks = {item["id"]: item for item in evidence[0].metadata["checks"]}
    assert "urlvet_login_form" not in findings
    assert "urlvet_payment_form" not in findings
    assert checks["urlvet_login_form"]["status"] == "review"
    assert checks["urlvet_payment_form"]["status"] == "review"


def test_urlvet_rejects_plain_http_remote_service():
    evidence = urlvet_adapter.collect_urlvet(
        "https://example.test", base_url="http://scanner.example", enabled=True
    )

    assert evidence[0].status == CriterionStatus.UNAVAILABLE
    assert evidence[0].provider_verdict == ProviderVerdict.UNAVAILABLE
