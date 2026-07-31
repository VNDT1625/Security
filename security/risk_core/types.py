"""CoreGuide v2 contracts. Scores use the documented 0..100 scale."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class CriterionStatus(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    NOT_CHECKED = "not_checked"
    UNAVAILABLE = "unavailable"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class ProviderVerdict(StrEnum):
    MALICIOUS = "malicious_verdict"
    SUSPICIOUS = "suspicious_verdict"
    CLEAN = "clean_verdict"
    NO_HIT = "no_hit"
    UNKNOWN = "unknown"
    NOT_OBSERVED = "not_observed"
    UNAVAILABLE = "unavailable"


class AdapterStatus(StrEnum):
    COMPLETED = "completed"
    NOT_CONFIGURED = "not_configured"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    PROVIDER_ERROR = "provider_error"
    INVALID_RESPONSE = "invalid_response"
    DISABLED = "disabled"
    CANCELLED = "cancelled"


class MatchedSubject(StrEnum):
    EXACT_URL = "exact_url"
    FINAL_REDIRECT_URL = "final_redirect_url"
    EXACT_DOMAIN = "exact_domain"
    IP = "ip"
    RELATED_SUBJECT = "related_subject"


@dataclass(frozen=True)
class SubjectKeys:
    exact_subject_key: str
    campaign_subject_key: str
    registrable_domain_key: str
    normalized_url: str


@dataclass
class EvidenceV2:
    evidence_id: str
    exact_subject_key: str
    campaign_subject_key: str
    finding_key: str
    incident_key: str
    criterion_id: int | None
    source_id: str
    organization_id: str
    source_family: str
    feed_lineage: tuple[str, ...] = ()
    matched_subject: MatchedSubject = MatchedSubject.RELATED_SUBJECT
    finding_type: str = "unknown"
    status: CriterionStatus = CriterionStatus.NOT_CHECKED
    provider_verdict: ProviderVerdict = ProviderVerdict.UNKNOWN
    severity: float = 0.0
    evidence_quality: float = 0.0
    match_strength: float = 0.0
    independence_coefficient: float = 1.0
    freshness_factor: float = 1.0
    authority_tier: int = 0
    observed_at: str = ""
    provider_sequence: str = ""
    max_weight: float = 0.0
    raw_score: float = 0.0
    adjusted_score: float = 0.0
    eligible_for_external_score: bool = True
    applicability_evidence_ids: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CriterionResult:
    criterion_id: int
    status: CriterionStatus
    max_weight: float
    coverage_weight: float
    severity: float = 0.0
    evidence_quality: float = 0.0
    raw_score: float = 0.0
    adjusted_score: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    incident_key: str = ""
    name: str = ""
    reason: str = ""
    applicable: bool = True
    checked: bool = False


@dataclass(frozen=True)
class ExternalAward:
    evidence_id: str
    source_id: str
    family: str
    candidate_score: float
    awarded_score: float


@dataclass(frozen=True)
class OverrideResult:
    rule_id: str
    floor: float
    minimum_decision: str
    matched_evidence_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class ConfidenceComponents:
    coverage: float
    agreement: float
    freshness: float
    score: float


@dataclass
class RiskResultV2:
    base_risk_score: float
    risk_score: float
    risk_level: str
    confidence_score: float
    confidence_band: str
    internal_score: float
    external_corroboration_score: float
    coverage: float
    agreement: float
    freshness: float
    criteria: list[CriterionResult]
    evidence: list[EvidenceV2]
    external_sources: list[ExternalAward]
    overrides: list[OverrideResult]
    effective_override: OverrideResult | None
    conflicts: list[dict[str, Any]]
    rules_version: str
    weights_version: str
    scan_version: str = "risk-core-url-v2.2.0"
    calibrated_probability: float | None = None
    mitigations: list[dict[str, Any]] = field(default_factory=list)
    unavailable_checks: list[int] = field(default_factory=list)
    not_checked_checks: list[int] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    policy_version: str = "default-policy-v2"
    model_version: str = ""
    source_adapter_versions: dict[str, str] = field(default_factory=dict)
    scan_started_at: str = ""
    scan_cutoff_at: str = ""
    scan_completed_at: str = ""
    # The 50 URL criteria remain available for existing clients, but final risk
    # is decided by the shared evidence pipeline exposed by these fields.
    direct_floor: float = 0.0
    composite_score: float = 0.0
    rule_score: float = 0.0
    ml_contribution: float = 0.0
    ml_model_version: str = "unavailable"
    missing_fields: list[str] = field(default_factory=list)
    unified_evidence_groups: dict[str, float] = field(default_factory=dict)
    deduplicated_evidence_count: int = 0
    reason_codes: list[str] = field(default_factory=list)


class PolicyDecision(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    REQUIRE_REVIEW = "require_review"
    SOFT_BLOCK = "soft_block"
    HARD_BLOCK = "hard_block"


class NextAction(StrEnum):
    NONE = "none"
    DEEP_SCAN = "deep_scan"
    SANDBOX = "sandbox"
    USER_CONFIRMATION = "user_confirmation"
    REPORT = "report"
    MANUAL_INVESTIGATION = "manual_investigation"


@dataclass(frozen=True)
class PolicyProfile:
    version: str = "default-policy-v2"
    dangerous_decision: PolicyDecision = PolicyDecision.SOFT_BLOCK


@dataclass(frozen=True)
class PolicyResult:
    decision: PolicyDecision
    next_action: NextAction
    policy_version: str
    reason: str
