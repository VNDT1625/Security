"""Deterministic evidence for criterion 2: domain registration lifetime.

The evaluator is deliberately independent from the network provider.  WHOIS/RDAP
collection supplies an absolute expiry timestamp when possible; this module turns
that observation into one of four explicit states without treating missing data as
either a clean result or a risk finding.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time
from email.utils import parsedate_to_datetime
from enum import StrEnum
from typing import Any

from .types import CriterionStatus

CRITERION_ID = 2
DEFAULT_EXPIRING_SOON_DAYS = 30

__all__ = [
    "CRITERION_ID",
    "DEFAULT_EXPIRING_SOON_DAYS",
    "DomainLifecycleEvidence",
    "DomainLifecycleState",
    "evaluate_domain_lifecycle",
]


class DomainLifecycleState(StrEnum):
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    HEALTHY = "healthy"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class DomainLifecycleEvidence:
    """Provider-neutral evidence ready for the Risk Core observation adapter."""

    state: DomainLifecycleState
    status: CriterionStatus
    summary: str
    finding_type: str | None = None
    severity: float = 0.0
    evidence_quality: float = 0.0
    days_remaining: int | None = None
    expires_at: str | None = None
    source: str = "domain_registration"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_risk(self) -> bool:
        return self.state in {
            DomainLifecycleState.EXPIRED,
            DomainLifecycleState.EXPIRING_SOON,
        }

    @property
    def checked(self) -> bool:
        return self.state is not DomainLifecycleState.UNAVAILABLE


def evaluate_domain_lifecycle(
    *,
    expires_at: str | date | datetime | None = None,
    expiry_days: int | float | str | None = None,
    now: datetime | None = None,
    source: str = "domain_registration",
    unavailable_reason: str | None = None,
    expiring_soon_days: int = DEFAULT_EXPIRING_SOON_DAYS,
) -> DomainLifecycleEvidence:
    """Classify a public registration expiry observation.

    ``expires_at`` is authoritative because it can be recalculated against the
    current scan time. ``expiry_days`` is a compatibility fallback for providers
    which return only a relative lifetime.
    """

    if expiring_soon_days < 1:
        raise ValueError("expiring_soon_days must be at least 1")

    observed_now = _normalise_now(now)
    parsed_expiry = _parse_expiry(expires_at)
    quality = 0.9
    value_origin = "expires_at"

    if parsed_expiry is not None:
        days_remaining = _whole_days_remaining(parsed_expiry, observed_now)
        normalised_expiry = parsed_expiry.isoformat().replace("+00:00", "Z")
    else:
        days_remaining = _parse_expiry_days(expiry_days)
        normalised_expiry = None
        quality = 0.75
        value_origin = "expiry_days"

    base_metadata: dict[str, Any] = {
        "criterion_id": CRITERION_ID,
        "source": source,
        "expiring_soon_days": expiring_soon_days,
    }
    if expires_at is not None:
        base_metadata["reported_expires_at"] = str(expires_at)
    if expiry_days is not None:
        base_metadata["reported_expiry_days"] = expiry_days

    if days_remaining is None:
        reason = unavailable_reason or (
            "The registration provider did not publish a usable domain expiry date."
        )
        return DomainLifecycleEvidence(
            state=DomainLifecycleState.UNAVAILABLE,
            status=CriterionStatus.UNAVAILABLE,
            summary=reason,
            source=source,
            metadata={
                **base_metadata,
                "value_origin": None,
                "observation_available": False,
            },
        )

    metadata = {
        **base_metadata,
        "value_origin": value_origin,
        "observation_available": True,
        "days_remaining": days_remaining,
        "expires_at": normalised_expiry,
    }
    absolute_expired = parsed_expiry is not None and parsed_expiry <= observed_now
    if days_remaining < 0 or absolute_expired:
        days_expired = max(0, -days_remaining)
        summary = (
            f"Domain registration expired {days_expired} day(s) ago."
            if days_expired
            else "Domain registration has expired."
        )
        return DomainLifecycleEvidence(
            state=DomainLifecycleState.EXPIRED,
            status=CriterionStatus.MALICIOUS,
            summary=summary,
            finding_type="expired_domain_registration",
            severity=1.0,
            evidence_quality=quality,
            days_remaining=days_remaining,
            expires_at=normalised_expiry,
            source=source,
            metadata=metadata,
        )
    if days_remaining <= expiring_soon_days:
        return DomainLifecycleEvidence(
            state=DomainLifecycleState.EXPIRING_SOON,
            status=CriterionStatus.SUSPICIOUS,
            summary=f"Domain registration expires in {days_remaining} day(s).",
            finding_type="domain_registration_expiring_soon",
            severity=0.45,
            evidence_quality=quality,
            days_remaining=days_remaining,
            expires_at=normalised_expiry,
            source=source,
            metadata=metadata,
        )
    return DomainLifecycleEvidence(
        state=DomainLifecycleState.HEALTHY,
        status=CriterionStatus.CLEAN,
        summary=(
            f"Domain registration remains valid for {days_remaining} day(s), "
            f"beyond the {expiring_soon_days}-day warning window."
        ),
        evidence_quality=quality,
        days_remaining=days_remaining,
        expires_at=normalised_expiry,
        source=source,
        metadata=metadata,
    )


def _normalise_now(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _parse_expiry(value: str | date | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, time.min, tzinfo=UTC)
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            iso_value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            parsed = (
                datetime.combine(iso_value.date(), time.max, tzinfo=UTC)
                if len(raw) == 10
                else iso_value
            )
        except ValueError:
            try:
                parsed = parsedate_to_datetime(raw)
            except (TypeError, ValueError, OverflowError):
                return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _parse_expiry_days(value: int | float | str | None) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed):
        return None
    return math.floor(parsed)


def _whole_days_remaining(expires_at: datetime, now: datetime) -> int:
    seconds = (expires_at - now).total_seconds()
    if seconds >= 0:
        return math.ceil(seconds / 86_400)
    return -math.ceil(abs(seconds) / 86_400)
