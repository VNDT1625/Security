"""Policy engine unit tests (test-plan.md §2.4)."""

from security.policy_engine import PolicyEngine, score_to_level
from shared.schemas import Decision, RiskLevel


def test_policy_allow_low_risk():
    assert PolicyEngine().evaluate_human(0.1) == Decision.ALLOW


def test_policy_warn_medium_risk():
    assert PolicyEngine().evaluate_human(0.6) == Decision.WARN


def test_policy_block_high_risk():
    assert PolicyEngine().evaluate_human(0.9) == Decision.BLOCK


def test_score_to_level():
    assert score_to_level(0.05) == RiskLevel.SAFE
    assert score_to_level(0.95) == RiskLevel.CRITICAL


def test_combine_evidence_score():
    from shared.schemas import Evidence, Severity

    eng = PolicyEngine()
    ev = [Evidence(source="x", message="m", severity=Severity.HIGH, contribution=0.8)]
    assert eng.combine_evidence_score(0.2, ev) > 0.2
