from datetime import UTC, date, datetime, timedelta

import pytest

from security.risk_core.domain_lifecycle import (
    DomainLifecycleState,
    evaluate_domain_lifecycle,
)
from security.risk_core.types import CriterionStatus

NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


def test_expired_registration_is_malicious_evidence():
    result = evaluate_domain_lifecycle(
        expires_at=NOW - timedelta(days=3),
        expiry_days=400,
        now=NOW,
        source="RDAP",
    )

    assert result.state == DomainLifecycleState.EXPIRED
    assert result.status == CriterionStatus.MALICIOUS
    assert result.finding_type == "expired_domain_registration"
    assert result.days_remaining == -3
    assert result.severity == 1.0
    assert result.evidence_quality == 0.9
    assert result.metadata["value_origin"] == "expires_at"


@pytest.mark.parametrize("days_remaining", [0, 1, 30])
def test_registration_inside_warning_window_is_suspicious(days_remaining):
    result = evaluate_domain_lifecycle(
        expires_at=NOW + timedelta(days=days_remaining),
        now=NOW,
    )

    assert result.state == DomainLifecycleState.EXPIRING_SOON
    assert result.status == CriterionStatus.SUSPICIOUS
    assert result.finding_type == "domain_registration_expiring_soon"
    assert result.days_remaining == days_remaining
    assert result.is_risk is True


def test_registration_beyond_warning_window_is_clean():
    result = evaluate_domain_lifecycle(
        expires_at=NOW + timedelta(days=31),
        now=NOW,
    )

    assert result.state == DomainLifecycleState.HEALTHY
    assert result.status == CriterionStatus.CLEAN
    assert result.finding_type is None
    assert result.days_remaining == 31
    assert result.checked is True
    assert result.is_risk is False


def test_missing_expiry_is_unavailable_not_clean_or_risk():
    result = evaluate_domain_lifecycle(
        now=NOW,
        unavailable_reason="RDAP omitted the expiration event.",
    )

    assert result.state == DomainLifecycleState.UNAVAILABLE
    assert result.status == CriterionStatus.UNAVAILABLE
    assert result.finding_type is None
    assert result.days_remaining is None
    assert result.checked is False
    assert result.is_risk is False
    assert result.summary == "RDAP omitted the expiration event."


def test_invalid_expiry_values_are_unavailable():
    result = evaluate_domain_lifecycle(
        expires_at="not-a-date",
        expiry_days="unknown",
        now=NOW,
    )

    assert result.state == DomainLifecycleState.UNAVAILABLE
    assert result.status == CriterionStatus.UNAVAILABLE


def test_absolute_expiry_wins_over_stale_relative_value():
    result = evaluate_domain_lifecycle(
        expires_at=(NOW + timedelta(days=365)).isoformat(),
        expiry_days=-10,
        now=NOW,
    )

    assert result.state == DomainLifecycleState.HEALTHY
    assert result.days_remaining == 365
    assert result.metadata["value_origin"] == "expires_at"


def test_relative_expiry_is_supported_as_lower_quality_fallback():
    result = evaluate_domain_lifecycle(
        expiry_days="12",
        now=NOW,
        source="legacy_whois",
    )

    assert result.state == DomainLifecycleState.EXPIRING_SOON
    assert result.days_remaining == 12
    assert result.expires_at is None
    assert result.evidence_quality == 0.75
    assert result.metadata["value_origin"] == "expiry_days"


def test_date_and_rfc_2822_values_are_normalised():
    date_result = evaluate_domain_lifecycle(
        expires_at=date(2026, 9, 1),
        now=datetime(2026, 7, 31, tzinfo=UTC),
    )
    rfc_result = evaluate_domain_lifecycle(
        expires_at="Tue, 01 Sep 2026 00:00:00 GMT",
        now=datetime(2026, 7, 31, tzinfo=UTC),
    )

    assert date_result.state == DomainLifecycleState.HEALTHY
    assert rfc_result.state == DomainLifecycleState.HEALTHY
    assert date_result.expires_at == "2026-09-01T00:00:00Z"
    assert rfc_result.expires_at == "2026-09-01T00:00:00Z"


def test_invalid_warning_window_is_rejected():
    with pytest.raises(ValueError, match="at least 1"):
        evaluate_domain_lifecycle(now=NOW, expiring_soon_days=0)
