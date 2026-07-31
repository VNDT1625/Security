from dataclasses import replace

import pytest

from security.risk_core import OverrideRule, assess, default_config, normalize_url
from security.risk_core.types import CriterionStatus, EvidenceV2, ProviderVerdict


def ev(eid="e1", source="source_51", criterion=1, finding="f1", incident="i1"):
    return EvidenceV2(eid, "x", "c", finding, incident, criterion, source, source,
        "reputation", status=CriterionStatus.MALICIOUS,
        provider_verdict=ProviderVerdict.MALICIOUS, severity=1, evidence_quality=1,
        match_strength=1, authority_tier=1, finding_type="malware")


def test_default_config_invariants():
    cfg = default_config()
    assert sum(c.max_weight for c in cfg.criteria[:49]) == 80
    assert cfg.criteria[49].max_weight == 0
    assert sum(s.raw_weight for s in cfg.sources) == 25
    assert sum(cfg.family_caps.values()) == 20
    replace(cfg, criteria=cfg.criteria[:-1]).validate if False else None
    with pytest.raises(ValueError):
        replace(cfg, criteria=cfg.criteria[:-1]).validate()


def test_url_normalization():
    a = normalize_url("HTTPS://Exämple.com:443/a/../b?z=2&a=1#frag")
    assert a.normalized_url == "https://xn--exmple-cua.com/b?z=2&a=1"
    assert a.registrable_domain_key == "xn--exmple-cua.com"


def test_order_and_retry_dedup_invariance():
    a = ev("a", finding="same")
    b = replace(a, evidence_id="b", evidence_quality=.5)
    r1, r2 = assess([a, b]), assess([b, a])
    assert r1.risk_score == r2.risk_score
    assert [e.evidence_id for e in r1.evidence] == ["a"]


def test_no_hit_and_clean_do_not_add_risk():
    nohit = replace(ev(), status=CriterionStatus.CLEAN, provider_verdict=ProviderVerdict.NO_HIT)
    clean = replace(ev("e2", finding="f2"), status=CriterionStatus.CLEAN, provider_verdict=ProviderVerdict.CLEAN)
    assert assess([nohit, clean]).risk_score == 0


def test_external_family_cap_and_internal_exclusion():
    external = [replace(ev(str(i), f"source_{51+i}", None, f"f{i}", f"i{i}"), organization_id=f"o{i}") for i in range(4)]
    result = assess(external)
    assert result.external_corroboration_score <= 6
    assert result.internal_score == 0


def test_override_is_floor_not_addition():
    rule = OverrideRule("r1", frozenset({"malware"}), 70, "soft_block", "confirmed")
    result = assess([ev()], override_rules=(rule,))
    assert result.risk_score == 70
    assert result.base_risk_score < result.risk_score


def test_high_confidence_access_hazard_gets_immediate_danger_floor():
    dangerous = replace(
        ev(criterion=29),
        finding_type="credential_exfiltration",
        evidence_quality=0.9,
    )
    result = assess([dangerous])

    assert result.base_risk_score < 60
    assert result.risk_score == 95
    assert result.direct_floor == 95
    assert result.risk_level == "critical"
    assert result.effective_override is None


def test_clean_evidence_cannot_activate_override():
    clean = replace(
        ev(criterion=None),
        finding_type="external_google_web_risk_known_malicious",
        status=CriterionStatus.CLEAN,
        provider_verdict=ProviderVerdict.CLEAN,
        severity=0,
    )
    rule = OverrideRule(
        "clean-must-not-match",
        frozenset({"external_google_web_risk_known_malicious"}),
        90,
        "hard_block",
        "confirmed",
    )

    result = assess([clean], override_rules=(rule,))

    assert result.risk_score == 0
    assert result.effective_override is None


@pytest.mark.parametrize("criterion", [6, 10, 13, 16, 36, 37, 40, 48])
def test_circumstantial_single_finding_does_not_force_sixty(criterion):
    contextual = replace(
        ev(criterion=criterion),
        finding_type=f"circumstantial_{criterion}",
        severity=0.75,
        evidence_quality=0.8,
    )

    result = assess([contextual])

    assert result.risk_score < 20
    assert result.effective_override is None


def test_confidence_does_not_jump_above_high_from_one_weak_signal():
    from security.risk_core.detectors import ScanObservations, build_criteria_evidence

    observations = ScanObservations("https://example.test")
    observations.clean(*range(1, 50))
    observations.risk(29, "weak_login_lure", 0.6, 0.8, "weak login signal")

    result = assess(build_criteria_evidence(observations, default_config()))

    assert result.risk_score < 20
    assert result.confidence_score < 70
