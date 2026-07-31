from dataclasses import replace

from security.risk_core import LightGBMRiskAdapter, PolicyEngineV2, RiskEngineV2, assess
from security.risk_core.types import CriterionStatus, EvidenceV2, ProviderVerdict


def _evidence(
    evidence_id: str,
    *,
    criterion: int,
    finding: str,
    incident: str = "scan",
    severity: float = 1.0,
    quality: float = 1.0,
) -> EvidenceV2:
    return EvidenceV2(
        evidence_id=evidence_id,
        exact_subject_key="url",
        campaign_subject_key="domain",
        finding_key=evidence_id,
        incident_key=incident,
        criterion_id=criterion,
        source_id="url_detector",
        organization_id="url_detector",
        source_family="url",
        status=CriterionStatus.MALICIOUS,
        provider_verdict=ProviderVerdict.MALICIOUS,
        severity=severity,
        evidence_quality=quality,
        match_strength=1.0,
        authority_tier=3,
        finding_type=finding,
        metadata={"summary": finding},
    )


def test_url_criteria_use_the_shared_pipeline_not_legacy_weight_sum() -> None:
    result = assess([_evidence("brand", criterion=5, finding="brand_domain_mismatch")])

    assert result.base_risk_score == result.composite_score
    assert result.internal_score > 0  # Compatibility trace only.
    assert result.risk_score == result.composite_score
    assert result.unified_evidence_groups["intent_mismatch"] > 0


def test_password_word_or_sensitive_request_never_sets_direct_floor() -> None:
    result = assess(
        [_evidence("keyword", criterion=29, finding="credential_theft_intent", severity=0.85, quality=0.8)]
    )

    assert result.direct_floor == 0
    assert result.risk_score < 95


def test_confirmed_credential_exfiltration_sets_floor_95() -> None:
    result = assess(
        [_evidence("exfil", criterion=29, finding="credential_exfiltration", severity=0.95, quality=1.0)]
    )

    assert result.direct_floor == 95
    assert result.risk_score == 95


def test_same_event_detectors_are_deduplicated() -> None:
    first = _evidence("first", criterion=29, finding="credential_theft_intent", incident="event-1")
    second = replace(first, evidence_id="second", finding_key="second", evidence_quality=0.7)

    result = assess([first, second])

    assert result.deduplicated_evidence_count == 1


def test_independent_url_risks_are_kept_for_composite_score() -> None:
    credential = _evidence("credential", criterion=29, finding="credential_theft_intent")
    transfer = _evidence("transfer", criterion=30, finding="external_form_action")
    destination = _evidence("destination", criterion=11, finding="public_malicious_listing")

    result = assess([credential, transfer, destination])

    assert len(result.unified_evidence_groups) == 3
    assert result.risk_score > max(result.unified_evidence_groups.values()) * 0.7


def test_lightgbm_can_raise_composite_but_not_lower_direct_floor() -> None:
    engine = RiskEngineV2(
        lightgbm=LightGBMRiskAdapter(lambda _features: 0.99, model_version="url-test")
    )
    result = engine.evaluate(
        [_evidence("exfil", criterion=29, finding="credential_exfiltration", severity=0.95)]
    )

    assert result.ml_contribution > 0
    assert result.direct_floor == 95
    assert result.risk_score == 95


def test_no_observation_is_not_treated_as_safe() -> None:
    result = assess([])
    policy = PolicyEngineV2().decide(result)

    assert result.missing_fields
    assert result.confidence_score < 40
    assert policy.decision.value == "require_review"
