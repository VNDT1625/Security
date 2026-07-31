"""Bridge the 50 URL criteria into the shared evidence risk pipeline.

The URL detectors remain responsible for observing facts.  They must not make a
second scoring decision: this module turns those facts into ``SecurityEvidence``
so URL and action assessments share normalization, event deduplication, direct
evidence floors, bounded composition, optional LightGBM and confidence rules.
"""

from __future__ import annotations

from dataclasses import dataclass

from .action_config import ActionRiskConfig
from .action_evidence import deduplicate_evidence, normalize_evidence
from .action_features import ActionFeatureVector, FEATURE_NAMES
from .action_lightgbm import LightGBMRiskAdapter
from .action_scoring import (
    compute_action_confidence,
    evaluate_direct_evidence,
    score_composite,
)
from .action_types import (
    DirectEvidenceResult,
    EvidenceCategory,
    EvidenceRelationship,
    EvidenceSource,
    EvidenceGroup,
    LightGBMRiskResult,
    SecurityEvidence,
    SessionRiskResult,
)
from .types import CriterionStatus, EvidenceV2


_DESTINATION_CRITERIA = frozenset({1, 2, 4, 8, 9, 10, 11, 12, 13, 14, 15, 17, 42, 44, 45})
_INTENT_CRITERIA = frozenset({5, 19, 26, 27, 28, 31, 32, 39, 40, 41, 46, 47, 48, 49})
_BEHAVIOURAL_CRITERIA = frozenset({6, 7, 16, 18, 33, 36, 37, 38, 43})
_MALWARE_FINDINGS = frozenset(
    {
        "confirmed_malware_execution",
        "malicious_javascript_behavior",
        "canary_exfiltration_blocked",
        "private_network_request_blocked",
        "websocket_request_blocked",
    }
)
_DIRECT_KINDS = {
    "credential_exfiltration": "confirmed_credential_exfiltration",
    "credential_form_with_external_destination": "confirmed_credential_exfiltration",
    "sensitive_form_with_external_destination": "confirmed_credential_exfiltration",
    "credential_field_with_deception_or_exfiltration": "confirmed_credential_exfiltration",
    "confirmed_otp_exfiltration": "confirmed_otp_exfiltration",
    "confirmed_malware_execution": "confirmed_malware_execution",
}


@dataclass(frozen=True)
class UnifiedUrlEvidenceResult:
    before_dedup: list[SecurityEvidence]
    after_dedup: list[SecurityEvidence]
    groups: list[EvidenceGroup]
    direct: DirectEvidenceResult
    composite_score: float
    rule_score: float
    confidence: float
    ml: LightGBMRiskResult
    missing_fields: list[str]


def _category(item: EvidenceV2) -> EvidenceCategory:
    finding = item.finding_type
    if finding in _MALWARE_FINDINGS or item.criterion_id in {34, 35}:
        return EvidenceCategory.MALWARE_EXECUTION
    if finding in _DIRECT_KINDS or finding in {"high_risk_secret_request", "sensitive_data_request"}:
        return EvidenceCategory.CREDENTIAL_ACCESS
    if item.criterion_id == 30:
        return EvidenceCategory.EXTERNAL_TRANSFER
    if item.criterion_id == 29:
        return EvidenceCategory.SENSITIVE_DATA_ACCESS
    if item.criterion_id in _DESTINATION_CRITERIA:
        return EvidenceCategory.DESTINATION_REPUTATION
    if item.criterion_id in _INTENT_CRITERIA:
        return EvidenceCategory.INTENT_MISMATCH
    if item.criterion_id in _BEHAVIOURAL_CRITERIA:
        return EvidenceCategory.BEHAVIORAL_ANOMALY
    return EvidenceCategory.POLICY_VIOLATION


def _event_id(item: EvidenceV2, category: EvidenceCategory) -> str:
    # Most legacy detectors use the scan-wide default incident.  Treating that as
    # one event would incorrectly collapse independent URL risks.  Only explicit
    # detector incidents are shared; otherwise group exact duplicates by category
    # and finding type.
    incident = item.incident_key.strip()
    if incident and incident not in {"scan", "structured_scan"}:
        return incident
    return f"url:{category.value}:{item.finding_type}"


def _relationship(item: EvidenceV2, category: EvidenceCategory) -> EvidenceRelationship:
    if item.incident_key.strip() and item.incident_key.strip() not in {"scan", "structured_scan"}:
        return EvidenceRelationship.SAME_EVENT
    if category in {EvidenceCategory.CREDENTIAL_ACCESS, EvidenceCategory.EXTERNAL_TRANSFER}:
        return EvidenceRelationship.SAME_EVENT
    if item.source_family in {"phishing_malware", "infrastructure_ip", "reputation"}:
        return EvidenceRelationship.SUPPORTING_EVIDENCE
    return EvidenceRelationship.INDEPENDENT_RISK


def _direct_metadata(item: EvidenceV2) -> tuple[bool, dict[str, object]]:
    kind = _DIRECT_KINDS.get(item.finding_type)
    # A direct floor needs a concrete observed behaviour and reliable evidence.
    # A word such as "password" or a generic sensitive form never meets this bar.
    confirmed = (
        kind is not None
        and item.status == CriterionStatus.MALICIOUS
        and item.evidence_quality >= 0.90
        and item.severity >= 0.90
    )
    return confirmed, {"confirmed": confirmed, "direct_kind": kind or ""}


def criteria_to_security_evidence(
    items: list[EvidenceV2],
    *,
    criterion_max_weights: dict[int, float] | None = None,
) -> list[SecurityEvidence]:
    output: list[SecurityEvidence] = []
    for item in items:
        if item.status not in {CriterionStatus.MALICIOUS, CriterionStatus.SUSPICIOUS}:
            continue
        if item.evidence_quality <= 0 or item.severity <= 0:
            continue
        category = _category(item)
        direct, metadata = _direct_metadata(item)
        # The previous maximum criterion weight becomes a bounded prior for one
        # detector, not a score to be added.  This keeps a lone contextual clue
        # weak while independent categories can still strengthen each other.
        prior = (criterion_max_weights or {}).get(item.criterion_id or 0, 1.5)
        signal_strength = min(45.0, max(0.0, prior) * 10.0 * item.severity)
        metadata.update(
            {
                "criterion_id": item.criterion_id,
                "finding_type": item.finding_type,
                "source_id": item.source_id,
            }
        )
        output.append(
            SecurityEvidence(
                id=item.evidence_id,
                category=category,
                event_id=_event_id(item, category),
                source=EvidenceSource.URL_RISK_CORE,
                severity=round(signal_strength, 4),
                reliability=round(item.evidence_quality, 4),
                relationship=_relationship(item, category),
                direct=direct,
                reason_code=f"URL_CRITERION_{item.criterion_id}_{item.finding_type}".upper(),
                summary=str(item.metadata.get("summary", item.finding_type)),
                metadata=metadata,
            )
        )
    return normalize_evidence(output)


def _features(
    groups: list[EvidenceGroup],
    direct: DirectEvidenceResult,
    missing_fields: list[str],
    config: ActionRiskConfig,
) -> ActionFeatureVector:
    scores = {group.category: group.score for group in groups}
    sensitive = max(
        scores.get(EvidenceCategory.CREDENTIAL_ACCESS, 0.0),
        scores.get(EvidenceCategory.SENSITIVE_DATA_ACCESS, 0.0),
    )
    destination = scores.get(EvidenceCategory.DESTINATION_REPUTATION)
    values: dict[str, float | None] = {
        "action_type_code": 0.0,
        "has_target": 1.0,
        "accesses_secret": 1.0 if sensitive > 0 else 0.0,
        "sensitive_data_level": sensitive / 100.0 if sensitive > 0 else 0.0,
        "external_destination": 1.0 if EvidenceCategory.EXTERNAL_TRANSFER in scores else 0.0,
        "destination_trust_score": None if destination is None else 1.0 - destination / 100.0,
        "requested_by_user": None,
        "intent_match_score": None,
        "requires_admin": 0.0,
        "privilege_level_code": 0.0,
        "workflow_known": 0.0,
        "payload_classified": None if "payload_classification" in missing_fields else 1.0,
        "data_flow_outbound": 1.0 if EvidenceCategory.EXTERNAL_TRANSFER in scores else 0.0,
        "session_cumulative_risk": 0.0,
        "rule_trigger_count": min(1.0, len(groups) / 10.0),
        "critical_rule_triggered": 1.0 if direct.floor > 0 else 0.0,
        "missing_feature_ratio": 0.0,
        "destination_confidence": None if destination is None else 0.8,
    }
    missing = tuple(sorted(name for name in FEATURE_NAMES if values[name] is None))
    values["missing_feature_ratio"] = len(missing) / len(FEATURE_NAMES)
    return ActionFeatureVector(config.feature_schema_version, values, missing)


def evaluate_url_evidence(
    items: list[EvidenceV2],
    *,
    action_config: ActionRiskConfig,
    lightgbm: LightGBMRiskAdapter | None = None,
    criterion_max_weights: dict[int, float] | None = None,
) -> UnifiedUrlEvidenceResult:
    before = criteria_to_security_evidence(
        items,
        criterion_max_weights=criterion_max_weights,
    )
    after, groups = deduplicate_evidence(before, action_config)
    direct = evaluate_direct_evidence(after, action_config)
    missing_set = {
        "payload_classification"
        for item in items
        if item.criterion_id in {29, 30, 34, 35}
        and item.status in {CriterionStatus.NOT_CHECKED, CriterionStatus.UNAVAILABLE}
    }
    if not items or not any(
        item.status
        in {CriterionStatus.CLEAN, CriterionStatus.SUSPICIOUS, CriterionStatus.MALICIOUS}
        for item in items
    ):
        missing_set.update({"destination", "payload_classification"})
    missing = sorted(missing_set)
    features = _features(groups, direct, missing, action_config)
    ml = (lightgbm or LightGBMRiskAdapter()).assess(features, action_config)
    composite, _ = score_composite(
        groups,
        action_config,
        ml=ml,
        session=SessionRiskResult(None, 0.0, 0.0, 0, False, False, 1),
    )
    rule_score, _ = score_composite(groups, action_config)
    confidence = compute_action_confidence(
        after,
        groups,
        missing_fields=missing,
        total_expected_fields=4,
        ml=ml,
        direct=direct,
    )
    if direct.floor == 0 and len(groups) < 2:
        # One URL detector is not enough to claim a high-confidence conclusion,
        # even when that detector itself is reliable.
        confidence = min(confidence, 60.0)
    return UnifiedUrlEvidenceResult(
        before_dedup=before,
        after_dedup=after,
        groups=groups,
        direct=direct,
        composite_score=composite,
        rule_score=rule_score,
        confidence=confidence,
        ml=ml,
        missing_fields=missing,
    )
