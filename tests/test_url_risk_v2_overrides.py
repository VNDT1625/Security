import pytest

from security.risk_core import PolicyEngineV2, default_config
from security.risk_core import assess as assess_risk_v2
from security.risk_core.detectors import (
    ScanObservations,
    add_offline_url_findings,
    build_criteria_evidence,
)
from security.risk_core.url_overrides import URL_OVERRIDE_RULES
from security.url_risk_core import assess_url


@pytest.mark.parametrize(
    "url,rule_id",
    [
        (
            "https://files.example.test/CV-Nguyen.pdf.exe",
            "url-disguised-executable-v1",
        ),
        (
            "https://microsoft-login.pages.dev/account/verify",
            "url-brand-shared-hosting-lure-v1",
        ),
        (
            "http://paypa1-verify.tk/login",
            "url-homoglyph-risky-tld-lure-v1",
        ),
    ],
)
def test_high_confidence_offline_url_patterns_hard_block_in_v2(url, rule_id):
    obs = ScanObservations(url)
    add_offline_url_findings(obs, assess_url(url).evidence)
    evidence = build_criteria_evidence(obs, default_config())
    risk = assess_risk_v2(evidence, override_rules=URL_OVERRIDE_RULES)
    policy = PolicyEngineV2().decide(risk)

    assert risk.risk_score >= 85
    assert risk.effective_override is not None
    assert risk.effective_override.rule_id == rule_id
    assert policy.decision.value == "hard_block"


def test_benign_url_has_no_v2_override():
    url = "https://github.com/openai"
    obs = ScanObservations(url)
    add_offline_url_findings(obs, assess_url(url).evidence)
    evidence = build_criteria_evidence(obs, default_config())
    risk = assess_risk_v2(evidence, override_rules=URL_OVERRIDE_RULES)

    assert risk.effective_override is None
    assert risk.risk_score < 20
    policy = PolicyEngineV2().decide(risk)
    assert policy.decision.value == "require_review"


def test_login_keyword_alone_is_not_a_warning_decision():
    url = "https://github.com/login"
    obs = ScanObservations(url)
    add_offline_url_findings(obs, assess_url(url).evidence)
    evidence = build_criteria_evidence(obs, default_config())
    risk = assess_risk_v2(evidence, override_rules=URL_OVERRIDE_RULES)
    policy = PolicyEngineV2().decide(risk)

    assert risk.risk_score < 20
    assert policy.decision.value == "allow"
    assert policy.next_action.value == "deep_scan"


def test_high_confidence_url_model_warns_but_never_blocks() -> None:
    """The URL classifier reaches the verdict, capped at WARN.

    Before this, model_score only produced an INFO evidence item with zero
    contribution, so Risk Core v2 — which builds criteria from evidence — never
    saw it. Retraining the model on a domain-grouped split lifted its holdout F1
    from 0.3502 to 0.6683 without moving the product verdict at all.
    """
    from security.risk_core import PolicyEngineV2, assess as assess_risk_v2, default_config
    from security.risk_core.detectors import (
        ScanObservations,
        add_offline_url_findings,
        build_criteria_evidence,
    )
    from security.risk_core.url_overrides import URL_OVERRIDE_RULES
    from security.url_risk_core import MODEL_HIGH_CONFIDENCE, assess_url

    url = "https://plain-looking-host.example/page"

    def verdict(model_score):
        core = assess_url(url, model_score=model_score)
        observations = ScanObservations(url)
        add_offline_url_findings(observations, core.evidence)
        config = default_config()
        risk = assess_risk_v2(
            build_criteria_evidence(observations, config),
            config=config,
            override_rules=URL_OVERRIDE_RULES,
        )
        return PolicyEngineV2().decide(risk).decision.value, risk.risk_score

    quiet_decision, quiet_score = verdict(0.90)
    loud_decision, loud_score = verdict(MODEL_HIGH_CONFIDENCE)

    # Thiếu bằng chứng độc lập không được tự động coi là an toàn.
    assert quiet_decision == "require_review"
    # At the bar it warns, and the floor keeps it out of every blocking band.
    assert loud_decision == "warn"
    assert loud_score >= 20.0
    assert loud_score < 60.0
    assert loud_score > quiet_score


def test_url_model_wiring_does_not_touch_message_modes() -> None:
    """Scope check: the URL classifier must not leak into email/SMS scoring."""
    from security.text_risk_core import assess_text_risk

    for modality in ("email", "sms"):
        benign = assess_text_risk(
            "Chào anh, lịch họp nội bộ chuyển sang 14h chiều mai.",
            modality,
            model_score=0.0,
        )
        assert benign.score < 0.50
        assert "model_high_confidence_phishing" not in {
            item.feature for item in benign.evidence
        }
