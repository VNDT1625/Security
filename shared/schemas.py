"""Pydantic v2 data contracts — single source of truth (design.md §7).

Imported by the backend gateway, MCP server, and AI modules. Kept dependency-free
(only pydantic) so importing schemas never pulls in heavy ML libraries.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from shared.adapter_schemas import AdapterTrace


# --------------------------------------------------------------------------- enums
class Modality(StrEnum):
    URL = "url"
    EMAIL = "email"
    TEXT = "text"
    SMS = "sms"
    PROMPT = "prompt"
    FILE = "file"
    ACTION = "action"
    CHAT = "chat"
    CALL_TRANSCRIPT = "call_transcript"
    WEBPAGE = "webpage"


class LegalEvidenceStatus(StrEnum):
    """Outcome of the legal evidence layer, never a permission decision."""

    NOT_APPLICABLE = "not_applicable"
    REFERENCE_FOUND = "reference_found"
    REVIEW_REQUIRED = "review_required"
    INSUFFICIENT_BASIS = "insufficient_basis"
    CONFLICT_DETECTED = "conflict_detected"


class RiskLevel(StrEnum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"
    ASK_USER_CONFIRMATION = "ASK_USER_CONFIRMATION"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------- evidence
class Evidence(BaseModel):
    source: str = Field(..., description="Module that produced this evidence")
    message: str = Field(..., description="Human-readable (Vietnamese) description")
    severity: Severity = Severity.INFO
    feature: str | None = Field(default=None, description="Technical feature name")
    contribution: float | None = Field(default=None, description="SHAP-like contribution")

    evidence_id: str | None = None
    category: str | None = None
    detector_family: str | None = None
    adapter: str | None = None
    cluster_id: str | None = None
    normalized_key: str | None = None
    raw_contribution: float | None = None
    weighted_contribution: float | None = None


class RiskCoreTrace(BaseModel):
    """Additive Risk Core v2 result; all numeric scores use the explicit 0..100 scale."""

    schema_version: str = "2"
    scoring_version: str
    score_scale: Literal["0..100"] = "0..100"
    raw_score: float = Field(..., ge=0.0, le=100.0)
    final_score: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=100.0)
    verdict: str
    # UI/CoreGuide aliases are optional so early v2 producers remain valid.
    base_risk_score: float | None = Field(default=None, ge=0.0, le=100.0)
    risk_score: float | None = Field(default=None, ge=0.0, le=100.0)
    risk_level: str | None = None
    confidence_score: float | None = Field(default=None, ge=0.0, le=100.0)
    confidence_band: str | None = None
    decision: str | None = None
    next_action: str | None = None
    internal_score: float | None = Field(default=None, ge=0.0, le=100.0)
    external_corroboration_score: float | None = Field(default=None, ge=0.0, le=100.0)
    coverage: float | None = Field(default=None, ge=0.0, le=100.0)
    agreement: float | None = Field(default=None, ge=0.0, le=100.0)
    freshness: float | None = Field(default=None, ge=0.0, le=100.0)
    criteria: list[dict[str, Any]] = Field(default_factory=list)
    penalties: dict[str, Any] = Field(default_factory=dict)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    external_sources: list[dict[str, Any]] = Field(default_factory=list)
    mitigations: list[dict[str, Any]] = Field(default_factory=list)
    overrides: list[dict[str, Any]] = Field(default_factory=list)
    effective_override: dict[str, Any] | None = None
    caps: list[dict[str, Any]] = Field(default_factory=list)
    conflicts: list[dict[str, Any]] = Field(default_factory=list)
    unavailable_checks: list[str | int] = Field(default_factory=list)
    not_checked_checks: list[str | int] = Field(default_factory=list)
    confidence_factors: dict[str, Any] = Field(default_factory=dict)
    versions: dict[str, str] = Field(default_factory=dict)
    timestamps: dict[str, str] = Field(default_factory=dict)
    source_adapter_versions: dict[str, str] = Field(default_factory=dict)
    reasoning: list[str] = Field(default_factory=list)
    ai_context_weight_percent: int = Field(default=0, ge=0, le=100)
    ai_context_effective_weight_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    ai_context_score: float | None = Field(default=None, ge=0.0, le=100.0)
    blended_final_score: float | None = Field(default=None, ge=0.0, le=100.0)


# ---------------------------------------------------------------------- requests
class AssessURLRequest(BaseModel):
    url: str = Field(..., max_length=2048)
    context: str | None = Field(default="", description="Surrounding text where URL was found")
    ai_context: Literal["off", "auto", "on"] = "auto"
    force_rescan: bool = Field(
        default=False,
        description="Bypass a saved URL result and run a fresh assessment",
    )


class SandboxURLRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


class BrowserSandboxRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    canary_mode: Literal["dry_run"] = "dry_run"


class AssessTextRequest(BaseModel):
    text: str = Field(..., max_length=50_000)
    modality: Literal["email", "text", "sms", "chat", "call_transcript"] = "email"
    metadata: dict[str, Any] | None = None
    ai_context: Literal["off", "auto", "on"] = "auto"


class URLTelemetryEvent(BaseModel):
    event_id: str = Field(
        ..., min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    )
    sensor_id: str = Field(..., min_length=8, max_length=200)
    url: str = Field(..., min_length=1, max_length=2048)
    verdict: Literal["suspicious", "malicious"]
    event_type: Literal["dns", "http", "browser", "endpoint", "sandbox"] = "endpoint"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    observed_at: datetime
    malware_family: str | None = Field(default=None, max_length=120)
    tags: list[str] = Field(default_factory=list, max_length=16)


class URLTelemetryBatchRequest(BaseModel):
    events: list[URLTelemetryEvent] = Field(..., min_length=1, max_length=100)


class URLTelemetryBatchResponse(BaseModel):
    accepted: int
    duplicates: int
    rejected: int = 0


class AgentContext(BaseModel):
    agent_type: Literal["chat", "browser_agent", "desktop_agent", "coding_agent", "generic"] = (
        "generic"
    )
    agent_id: str | None = None
    session_id: str | None = None
    user_intent: str | None = None
    current_url: str | None = None
    planned_action: str | None = None
    available_assets: list[str] = Field(default_factory=list)
    data_types_involved: list[str] = Field(default_factory=list)
    permission_level: str | None = None


class AssessActionRequest(BaseModel):
    action_type: Literal[
        "open_url",
        "click_link",
        "submit_form",
        "send_email",
        "download_file",
        "open_file",
        "execute_file",
        "copy_data",
        "call_api",
        "upload_file",
        "payment_or_transfer",
    ]
    target_url: str | None = None
    target: str | None = None
    data_types: list[str] = Field(default_factory=list)
    agent_context: AgentContext = Field(default_factory=AgentContext)


class ScanPromptRequest(BaseModel):
    content: str = Field(..., max_length=50_000)
    content_type: Literal["email", "webpage", "file", "chat_message", "prompt"] = "webpage"


# --------------------------------------------------------------------- responses
class IntelligenceSourceStatus(BaseModel):
    source: str
    status: Literal["completed", "not_configured", "unavailable", "redacted"]
    detail: str = ""


class URLBasicIntelligence(BaseModel):
    """Provenance-aware registration, DNS and public-IP facts for a URL."""

    domain: str
    ip_addresses: list[str] = Field(default_factory=list)
    primary_ip: str | None = None
    ip_location: str | None = None
    city: str | None = None
    region: str | None = None
    country: str | None = None
    country_code: str | None = None
    asn: str | None = None
    provider: str | None = None
    registrar: str | None = None
    registrant: str | None = None
    registrant_phone: str | None = None
    registered_at: str | None = None
    expires_at: str | None = None
    nameservers: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    collected_at: str
    sources: list[IntelligenceSourceStatus] = Field(default_factory=list)


class AssessResponse(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Normalized 0..1")
    risk_level: RiskLevel
    decision: Decision
    confidence: float = Field(..., ge=0.0, le=1.0)
    modality: Modality
    reasons: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    explanation: str = Field(default="", description="Vietnamese NL explanation (Layer 2)")
    recommended_agent_behavior: str = ""
    model_version: str = "heuristic-1"
    latency_ms: float = 0.0
    request_id: str = ""
    # Additive v2 fields: existing response consumers can safely ignore them.
    schema_version: str = "1"
    scoring_version: str | None = None
    raw_score: float | None = Field(default=None, ge=0.0, le=1.0)
    final_score: float | None = Field(default=None, ge=0.0, le=1.0)
    risk_core: RiskCoreTrace | None = None
    url_intelligence: URLBasicIntelligence | None = None
    contextual_analysis: AdapterTrace | None = None
    phone_intelligence: AdapterTrace | None = None
    # Message-specific audit fields. These make missing checks explicit instead of
    # silently treating unavailable Gmail/MIME/provider data as safe.
    analysis_coverage: dict[str, str] = Field(default_factory=dict)
    # Cache metadata is intentionally product-level only: it does not expose
    # cache keys, database identifiers, or another user's scan information.
    cache_hit: bool = False
    cache_status: Literal["hit", "miss", "bypassed", "refresh"] = "bypassed"
    message_metadata: dict[str, Any] = Field(default_factory=dict)
    embedded_url_assessments: list[dict[str, Any]] = Field(default_factory=list)


class SandboxIssue(BaseModel):
    code: str
    severity: Severity
    category: str
    message: str
    detail: str = ""


class SandboxScanStep(BaseModel):
    key: str
    label: str
    status: Literal["passed", "failed", "skipped"] = "passed"
    detail: str = ""


class SandboxRedirect(BaseModel):
    status_code: int
    from_url: str
    to_url: str


class SandboxNetworkEvent(BaseModel):
    url: str
    method: str = "GET"
    resource_type: str = ""
    status: int | None = None
    blocked: bool = False
    reason: str = ""
    same_origin: bool | None = None


class SandboxCanaryReport(BaseModel):
    enabled: bool = True
    mode: Literal["dry_run"] = "dry_run"
    clone_email: str = ""
    fields_filled: int = 0
    field_types: dict[str, int] = Field(default_factory=dict)
    form_submissions_blocked: int = 0
    exfiltration_blocked: bool = False
    notes: list[str] = Field(default_factory=list)


class SandboxURLResponse(BaseModel):
    risk_core: RiskCoreTrace | None = None
    ok: bool
    execution_status: Literal["completed", "failed"]
    url: str
    final_url: str = ""
    status_code: int | None = None
    http_reason: str = ""
    content_type: str = ""
    bytes_read: int = 0
    resolved_ip: str = ""
    redirects: list[SandboxRedirect] = Field(default_factory=list)
    tls: dict[str, Any] = Field(default_factory=dict)
    page_title: str = ""
    page_signals: dict[str, Any] = Field(default_factory=dict)
    issues: list[SandboxIssue] = Field(default_factory=list)
    scan_steps: list[SandboxScanStep] = Field(default_factory=list)
    elapsed_ms: float = 0.0

    @classmethod
    def failed(cls, url: str, code: str, message: str, detail: str = ""):
        return cls(
            ok=False,
            execution_status="failed",
            url=url,
            issues=[
                SandboxIssue(
                    code=code,
                    severity=Severity.HIGH,
                    category="execution",
                    message=message,
                    detail=detail,
                )
            ],
            scan_steps=[
                SandboxScanStep(
                    key=code,
                    label="Sandbox execution",
                    status="failed",
                    detail=message,
                )
            ],
        )


class BrowserSandboxURLResponse(BaseModel):
    risk_core: RiskCoreTrace | None = None
    ok: bool
    execution_status: Literal["completed", "failed"]
    url: str
    final_url: str = ""
    status_code: int | None = None
    page_title: str = ""
    isolation: dict[str, Any] = Field(default_factory=dict)
    canary: SandboxCanaryReport = Field(default_factory=SandboxCanaryReport)
    network_events: list[SandboxNetworkEvent] = Field(default_factory=list)
    browser_events: list[dict[str, Any]] = Field(default_factory=list)
    console_errors: list[str] = Field(default_factory=list)
    visual_analysis: dict[str, Any] = Field(default_factory=dict)
    page_identity: dict[str, Any] = Field(default_factory=dict)
    screenshot_data_url: str | None = None
    issues: list[SandboxIssue] = Field(default_factory=list)
    scan_steps: list[SandboxScanStep] = Field(default_factory=list)
    elapsed_ms: float = 0.0

    @classmethod
    def failed(cls, url: str, code: str, message: str, detail: str = ""):
        return cls(
            ok=False,
            execution_status="failed",
            url=url,
            issues=[
                SandboxIssue(
                    code=code,
                    severity=Severity.HIGH,
                    category="execution",
                    message=message,
                    detail=detail,
                )
            ],
            scan_steps=[
                SandboxScanStep(
                    key=code,
                    label="Browser sandbox execution",
                    status="failed",
                    detail=message,
                )
            ],
        )


class AgentRiskResponse(BaseModel):
    decision: Decision
    risk_level: RiskLevel
    risk_score: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    verdict: Decision
    safe_summary: str = ""
    reasoning: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    recommended_agent_behavior: str = ""
    requires_user_confirmation: bool = False
    legal_rag_status: Literal["completed", "unavailable", "not_applicable"] = "not_applicable"
    legal_evidence_status: LegalEvidenceStatus = LegalEvidenceStatus.NOT_APPLICABLE
    legal_review_required: bool = False
    legal_references: list[dict[str, Any]] = Field(default_factory=list)
    # Additive evidence-engine trace. Existing clients can ignore this field.
    security_core: dict[str, Any] | None = None
    request_id: str = ""


class ChatRequestWS(BaseModel):
    question: str
    context: dict[str, Any] | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    error: str
    detail: str = ""
    request_id: str = ""


class HealthResponse(BaseModel):
    status: str = "ok"
    models_loaded: bool = False
    llm_available: bool = False
    model_status: dict[str, Any] = Field(default_factory=dict)
    version: str = "0.1.0"
