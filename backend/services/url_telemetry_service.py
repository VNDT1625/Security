"""Privacy-preserving multi-sensor URL IOC ingestion and consensus evidence."""
from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.config import settings
from backend.models import URLTelemetryObservation
from backend.security_utils import utcnow
from security.risk_core.normalization import (
    make_finding_key,
    make_incident_key,
    normalize_url,
)
from security.risk_core.types import (
    CriterionStatus,
    EvidenceV2,
    MatchedSubject,
    ProviderVerdict,
)
from shared.schemas import URLTelemetryEvent


def _sensor_hash(sensor_id: str) -> str:
    return hmac.new(
        settings.telemetry_sensor_pepper.encode("utf-8"),
        sensor_id.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _naive_utc(value: datetime) -> datetime:
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value


def ingest_url_events(
    db: Session,
    events: list[URLTelemetryEvent],
    *,
    api_key_id: str,
) -> tuple[int, int]:
    """Store deduplicated IOC observations without raw URLs or machine identifiers."""

    now = utcnow()
    earliest = now - timedelta(days=settings.telemetry_retention_days)
    latest = now + timedelta(minutes=5)
    accepted = duplicates = 0
    for event in events:
        observed = _naive_utc(event.observed_at)
        if observed < earliest or observed > latest:
            raise ValueError("observed_at is outside the accepted telemetry window")
        keys = normalize_url(event.url)
        if not keys.normalized_url.startswith(("http://", "https://")):
            raise ValueError("telemetry URL must use HTTP or HTTPS")
        sensor_hash = _sensor_hash(event.sensor_id)
        exists = db.execute(
            select(URLTelemetryObservation.id).where(
                URLTelemetryObservation.sensor_hash == sensor_hash,
                URLTelemetryObservation.event_id == event.event_id,
            )
        ).scalar_one_or_none()
        if exists is not None:
            duplicates += 1
            continue
        db.add(
            URLTelemetryObservation(
                event_id=event.event_id,
                sensor_hash=sensor_hash,
                api_key_id=api_key_id,
                exact_url_key=keys.exact_subject_key,
                campaign_key=keys.campaign_subject_key,
                registrable_domain=keys.registrable_domain_key,
                verdict=event.verdict,
                event_type=event.event_type,
                confidence=event.confidence,
                malware_family=(event.malware_family or "").strip()[:120] or None,
                tags=[str(tag).strip()[:40] for tag in event.tags if str(tag).strip()],
                observed_at=observed,
                expires_at=observed + timedelta(days=settings.telemetry_retention_days),
            )
        )
        accepted += 1
    db.commit()
    return accepted, duplicates


def _status_evidence(
    url: str,
    *,
    status: CriterionStatus,
    verdict: ProviderVerdict,
    summary: str,
    sensor_count: int,
    check_status: str,
) -> EvidenceV2:
    keys = normalize_url(url)
    return EvidenceV2(
        evidence_id=f"distributed-status-{keys.exact_subject_key[:20]}",
        exact_subject_key=keys.exact_subject_key,
        campaign_subject_key=keys.campaign_subject_key,
        finding_key=make_finding_key(
            keys.exact_subject_key, "distributed_telemetry_status", "distributed_telemetry"
        ),
        incident_key=make_incident_key(
            keys.campaign_subject_key, "distributed_telemetry", "scan"
        ),
        criterion_id=None,
        source_id="distributed_telemetry",
        organization_id="distributed_telemetry",
        source_family="endpoint_telemetry",
        matched_subject=MatchedSubject.EXACT_URL,
        finding_type="distributed_telemetry_status",
        status=status,
        provider_verdict=verdict,
        severity=0.0,
        evidence_quality=0.0,
        match_strength=1.0,
        authority_tier=1,
        observed_at=datetime.now(UTC).isoformat(),
        metadata={
            "summary": summary,
            "adapter_status": "completed",
            "sensor_count": sensor_count,
            "consensus_threshold": settings.telemetry_min_independent_sensors,
            "checks": [
                {
                    "id": "distributed_sensor_consensus",
                    "label": "Đồng thuận IOC từ nhiều máy",
                    "status": check_status,
                    "detail": (
                        f"{sensor_count} sensor độc lập; cần ít nhất "
                        f"{settings.telemetry_min_independent_sensors}."
                    ),
                }
            ],
        },
    )


def _consensus_evidence(
    url: str,
    *,
    criterion_id: int,
    finding_type: str,
    sensor_count: int,
    confidence: float,
    matched_subject: MatchedSubject,
    summary: str,
) -> EvidenceV2:
    keys = normalize_url(url)
    severity = 0.98 if matched_subject == MatchedSubject.EXACT_URL else 0.72
    quality = min(0.95, max(0.65, confidence) * min(1.0, sensor_count / 3))
    subject_key = (
        keys.exact_subject_key
        if matched_subject == MatchedSubject.EXACT_URL
        else keys.registrable_domain_key
    )
    return EvidenceV2(
        evidence_id=f"distributed-{finding_type}-{keys.exact_subject_key[:16]}",
        exact_subject_key=keys.exact_subject_key,
        campaign_subject_key=keys.campaign_subject_key,
        finding_key=make_finding_key(subject_key, finding_type, "distributed_telemetry"),
        incident_key=make_incident_key(
            keys.campaign_subject_key, "distributed_endpoint_incident", "rolling-window"
        ),
        criterion_id=criterion_id,
        source_id="distributed_telemetry",
        organization_id="distributed_telemetry",
        source_family="endpoint_telemetry",
        matched_subject=matched_subject,
        finding_type=finding_type,
        status=(
            CriterionStatus.MALICIOUS
            if matched_subject == MatchedSubject.EXACT_URL
            else CriterionStatus.SUSPICIOUS
        ),
        provider_verdict=(
            ProviderVerdict.MALICIOUS
            if matched_subject == MatchedSubject.EXACT_URL
            else ProviderVerdict.SUSPICIOUS
        ),
        severity=severity,
        evidence_quality=quality,
        match_strength=1.0 if matched_subject == MatchedSubject.EXACT_URL else 0.7,
        authority_tier=2,
        observed_at=datetime.now(UTC).isoformat(),
        metadata={
            "summary": summary,
            "adapter_status": "completed",
            "sensor_count": sensor_count,
            "consensus_threshold": settings.telemetry_min_independent_sensors,
            "privacy": "sensor identifiers HMAC-pseudonymized; raw logs not stored",
        },
    )


def build_distributed_url_evidence(db: Session, url: str) -> list[EvidenceV2]:
    keys = normalize_url(url)
    now = utcnow()
    cutoff = now - timedelta(days=settings.telemetry_consensus_window_days)
    rows = list(
        db.execute(
            select(URLTelemetryObservation).where(
                URLTelemetryObservation.observed_at >= cutoff,
                URLTelemetryObservation.expires_at > now,
                or_(
                    URLTelemetryObservation.exact_url_key == keys.exact_subject_key,
                    URLTelemetryObservation.campaign_key == keys.campaign_subject_key,
                    URLTelemetryObservation.registrable_domain == keys.registrable_domain_key,
                ),
            )
        ).scalars()
    )
    # A sensor API key is provisioned per managed machine.  Counting API keys rather
    # than caller-supplied sensor_id values prevents one compromised key from
    # inventing many machine names and manufacturing consensus.
    exact = {
        row.api_key_id: row
        for row in rows
        if row.api_key_id
        and row.exact_url_key == keys.exact_subject_key
        and row.verdict == "malicious"
    }
    related = {
        row.api_key_id: row
        for row in rows
        if row.api_key_id and row.verdict in {"suspicious", "malicious"}
    }
    threshold = settings.telemetry_min_independent_sensors

    if len(exact) >= threshold:
        confidence = sum(row.confidence for row in exact.values()) / len(exact)
        summary = f"Exact URL was observed as malicious by {len(exact)} independent sensors."
        return [
            _status_evidence(
                url,
                status=CriterionStatus.MALICIOUS,
                verdict=ProviderVerdict.MALICIOUS,
                summary=summary,
                sensor_count=len(exact),
                check_status="danger",
            ),
            _consensus_evidence(
                url,
                criterion_id=11,
                finding_type="distributed_exact_malicious_consensus",
                sensor_count=len(exact),
                confidence=confidence,
                matched_subject=MatchedSubject.EXACT_URL,
                summary=summary,
            ),
        ]

    domain_threshold = threshold + 1
    if len(related) >= domain_threshold:
        confidence = sum(row.confidence for row in related.values()) / len(related)
        summary = (
            f"The domain/campaign was observed as suspicious by {len(related)} independent sensors."
        )
        return [
            _status_evidence(
                url,
                status=CriterionStatus.SUSPICIOUS,
                verdict=ProviderVerdict.SUSPICIOUS,
                summary=summary,
                sensor_count=len(related),
                check_status="danger",
            ),
            _consensus_evidence(
                url,
                criterion_id=12,
                finding_type="distributed_domain_suspicious_consensus",
                sensor_count=len(related),
                confidence=confidence,
                matched_subject=MatchedSubject.EXACT_DOMAIN,
                summary=summary,
            ),
        ]

    observed = len(related)
    return [
        _status_evidence(
            url,
            status=CriterionStatus.CLEAN if observed == 0 else CriterionStatus.NOT_CHECKED,
            verdict=ProviderVerdict.NO_HIT if observed == 0 else ProviderVerdict.NOT_OBSERVED,
            summary=(
                "No active endpoint IOC observation matched this URL."
                if observed == 0
                else "Endpoint observations exist but do not meet the independent-sensor threshold."
            ),
            sensor_count=observed,
            check_status="safe" if observed == 0 else "review",
        )
    ]


def collect_distributed_url_evidence(url: str) -> list[EvidenceV2]:
    """Runtime wrapper that never lets telemetry storage failure break a scan."""

    from backend.db import SessionLocal

    try:
        with SessionLocal() as db:
            return build_distributed_url_evidence(db, url)
    except (SQLAlchemyError, ValueError, TypeError):
        keys = normalize_url(url)
        return [
            EvidenceV2(
                evidence_id=f"distributed-unavailable-{keys.exact_subject_key[:20]}",
                exact_subject_key=keys.exact_subject_key,
                campaign_subject_key=keys.campaign_subject_key,
                finding_key=make_finding_key(
                    keys.exact_subject_key,
                    "distributed_telemetry_unavailable",
                    "distributed_telemetry",
                ),
                incident_key=make_incident_key(
                    keys.campaign_subject_key, "distributed_telemetry", "scan"
                ),
                criterion_id=None,
                source_id="distributed_telemetry",
                organization_id="distributed_telemetry",
                source_family="endpoint_telemetry",
                finding_type="distributed_telemetry_status",
                status=CriterionStatus.UNAVAILABLE,
                provider_verdict=ProviderVerdict.UNAVAILABLE,
                observed_at=datetime.now(UTC).isoformat(),
                metadata={
                    "summary": "Distributed telemetry storage is unavailable.",
                    "adapter_status": "provider_error",
                    "checks": [
                        {
                            "id": "distributed_sensor_consensus",
                            "label": "Đồng thuận IOC từ nhiều máy",
                            "status": "unavailable",
                            "detail": "Không truy cập được kho telemetry.",
                        }
                    ],
                },
            )
        ]
