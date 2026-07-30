"""Typed contracts for the evidence-based action risk engine.

These contracts deliberately contain classifications and hashes only. Raw
credentials, commands, payloads and one-time codes must never enter a trace.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class EvidenceCategory(StrEnum):
    CREDENTIAL_ACCESS = "credential_access"
    CREDENTIAL_EXFILTRATION = "credential_exfiltration"
    OTP_EXPOSURE = "otp_exposure"
    SENSITIVE_DATA_ACCESS = "sensitive_data_access"
    EXTERNAL_TRANSFER = "external_transfer"
    MALWARE_EXECUTION = "malware_execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DESTRUCTIVE_ACTION = "destructive_action"
    INTENT_MISMATCH = "intent_mismatch"
    DESTINATION_REPUTATION = "destination_reputation"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    POLICY_VIOLATION = "policy_violation"
    UNKNOWN_PAYLOAD = "unknown_payload"
    MISSING_CONTEXT = "missing_context"


class EvidenceSource(StrEnum):
    ACTION_RULE = "action_rule"
    URL_RISK_CORE = "url_risk_core"
    POLICY_CONTEXT = "policy_context"
    LIGHTGBM = "lightgbm"
    SESSION_TRACKER = "session_tracker"


class EvidenceRelationship(StrEnum):
    SAME_EVENT = "same_event"
    SUPPORTING_EVIDENCE = "supporting_evidence"
    INDEPENDENT_RISK = "independent_risk"


class ActionRiskLevel(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"
    INSUFFICIENT_INFORMATION = "insufficient_information"


class ActionPolicyDecision(StrEnum):
    ALLOW = "allow"
    ALLOW_WITH_LOG = "allow_with_log"
    WARN = "warn"
    ASK_CONFIRM = "ask_confirm"
    SANDBOX = "sandbox"
    TEMPORARY_BLOCK = "temporary_block"
    BLOCK = "block"


@dataclass(frozen=True)
class SecurityEvidence:
    id: str
    category: EvidenceCategory
    event_id: str
    source: EvidenceSource
    severity: float
    reliability: float
    relationship: EvidenceRelationship
    direct: bool = False
    reason_code: str = ""
    summary: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id or not self.event_id:
            raise ValueError("evidence id and event id are required")
        if not 0.0 <= self.severity <= 100.0:
            raise ValueError("evidence severity must be within 0..100")
        if not 0.0 <= self.reliability <= 1.0:
            raise ValueError("evidence reliability must be within 0..1")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["category"] = self.category.value
        value["source"] = self.source.value
        value["relationship"] = self.relationship.value
        return value


@dataclass(frozen=True)
class EvidenceGroup:
    category: EvidenceCategory
    event_id: str
    score: float
    evidence_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    strongest_evidence_id: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["category"] = self.category.value
        return value


@dataclass(frozen=True)
class DirectEvidenceResult:
    floor: float
    kinds: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class LightGBMRiskResult:
    available: bool
    risk_probability: float | None = None
    risk_contribution: float = 0.0
    model_confidence: float = 0.0
    out_of_distribution: bool = False
    top_features: tuple[dict[str, float | str], ...] = ()
    model_version: str = "unavailable"
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SessionRiskResult:
    session_id_hash: str | None
    cumulative_risk: float
    contribution: float
    repeated_access_count: int
    slow_exfiltration: bool
    multi_step_attack: bool
    action_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ActionRiskInput:
    action_id: str
    action_type: str
    target_url: str | None
    data_types: tuple[str, ...]
    user_intent: str | None
    planned_action: str | None
    permission_level: str | None
    available_assets: tuple[str, ...]
    session_id: str | None
    workflow_id: str | None = None
    destination_risk_score: float | None = None
    destination_confidence: float | None = None


@dataclass
class ActionRiskResult:
    action_id: str
    danger_score: float | None
    confidence: float
    risk_level: ActionRiskLevel
    decision: ActionPolicyDecision
    direct_floor: float
    composite_score: float
    rule_score: float
    evidence_before_dedup: list[SecurityEvidence]
    evidence_after_dedup: list[SecurityEvidence]
    evidence_groups: list[EvidenceGroup]
    direct_evidence: DirectEvidenceResult
    ml: LightGBMRiskResult
    session: SessionRiskResult
    missing_fields: list[str]
    reason_codes: list[str]
    explanation: str
    rules_triggered: list[str]
    scoring_version: str
    feature_schema_version: str
    policy_version: str
    mode: str = "new_engine"
    legacy_comparison: dict[str, Any] = field(default_factory=dict)

    def to_trace(self) -> dict[str, Any]:
        return {
            "schema_version": "3.0",
            "scoring_version": self.scoring_version,
            "feature_schema_version": self.feature_schema_version,
            "policy_version": self.policy_version,
            "mode": self.mode,
            "danger_score": self.danger_score,
            "confidence": self.confidence,
            "risk_level": self.risk_level.value,
            "decision": self.decision.value,
            "direct_floor": self.direct_floor,
            "composite_score": self.composite_score,
            "rule_score": self.rule_score,
            "direct_evidence": list(self.direct_evidence.kinds),
            "evidence_groups": {
                group.category.value: max(
                    group.score,
                    max(
                        (
                            other.score
                            for other in self.evidence_groups
                            if other.category == group.category
                        ),
                        default=group.score,
                    ),
                )
                for group in self.evidence_groups
            },
            "evidence_before_dedup_count": len(self.evidence_before_dedup),
            "deduplicated_evidence_count": len(self.evidence_after_dedup),
            "ml": self.ml.to_dict(),
            "session": self.session.to_dict(),
            "missing_fields": list(self.missing_fields),
            "reason_codes": list(self.reason_codes),
            "rules_triggered": list(self.rules_triggered),
            "explanation": self.explanation,
            "legacy_comparison": dict(self.legacy_comparison),
        }
