"""Central, validated configuration for evidence-based action risk."""

from __future__ import annotations

from dataclasses import dataclass, field

from .action_types import EvidenceCategory


def _category_weights() -> dict[EvidenceCategory, float]:
    return {
        EvidenceCategory.CREDENTIAL_ACCESS: 0.82,
        EvidenceCategory.CREDENTIAL_EXFILTRATION: 1.00,
        EvidenceCategory.OTP_EXPOSURE: 1.00,
        EvidenceCategory.SENSITIVE_DATA_ACCESS: 0.70,
        EvidenceCategory.EXTERNAL_TRANSFER: 0.86,
        EvidenceCategory.MALWARE_EXECUTION: 1.00,
        EvidenceCategory.PRIVILEGE_ESCALATION: 0.96,
        EvidenceCategory.DESTRUCTIVE_ACTION: 1.00,
        EvidenceCategory.INTENT_MISMATCH: 0.58,
        EvidenceCategory.DESTINATION_REPUTATION: 0.82,
        EvidenceCategory.BEHAVIORAL_ANOMALY: 0.64,
        EvidenceCategory.POLICY_VIOLATION: 0.78,
        EvidenceCategory.UNKNOWN_PAYLOAD: 0.42,
        # Missing context lowers confidence and drives policy. It is intentionally
        # weak in danger scoring so absence is never treated as proof of harm.
        EvidenceCategory.MISSING_CONTEXT: 0.20,
    }


def _direct_floors() -> dict[str, float]:
    return {
        "confirmed_credential_exfiltration": 95.0,
        "confirmed_otp_exfiltration": 95.0,
        "confirmed_malware_execution": 95.0,
        "confirmed_destructive_system_command": 92.0,
        "confirmed_privilege_escalation": 94.0,
        "confirmed_mass_encryption_or_deletion": 95.0,
    }


@dataclass(frozen=True)
class ActionRiskConfig:
    scoring_version: str = "evidence-action-risk-v3.0.0"
    feature_schema_version: str = "action-features-v1"
    policy_version: str = "action-policy-v3"

    direct_floors: dict[str, float] = field(default_factory=_direct_floors)
    category_weights: dict[EvidenceCategory, float] = field(default_factory=_category_weights)
    supporting_bonus_ratio: float = 0.15
    supporting_bonus_cap: float = 10.0
    ml_max_contribution: float = 18.0
    ml_review_probability: float = 0.72
    ml_ood_missing_ratio: float = 0.40

    suspicious_threshold: float = 35.0
    dangerous_threshold: float = 60.0
    critical_threshold: float = 85.0
    high_confidence_threshold: float = 70.0
    low_confidence_threshold: float = 40.0

    session_half_life_seconds: float = 900.0
    session_max_risk: float = 100.0
    session_max_contribution: float = 30.0
    session_history_limit: int = 64
    slow_exfiltration_count: int = 3
    workflow_approval_discount: float = 0.35

    credential_types: frozenset[str] = frozenset(
        {
            "password",
            "credentials",
            "credential",
            "api_key",
            "private_key",
            "session_token",
            "access_token",
            "email_credentials",
        }
    )
    otp_types: frozenset[str] = frozenset({"otp", "one_time_password", "verification_code"})
    sensitive_types: frozenset[str] = frozenset(
        {
            "password",
            "credentials",
            "credential",
            "api_key",
            "private_key",
            "session_token",
            "access_token",
            "email_credentials",
            "otp",
            "one_time_password",
            "verification_code",
            "credit_card",
            "payment_info",
            "personal_data",
            "personal_info",
            "health_data",
        }
    )
    transfer_actions: frozenset[str] = frozenset(
        {"submit_form", "send_email", "upload_file", "call_api", "payment_or_transfer"}
    )
    privileged_actions: frozenset[str] = frozenset(
        {"execute_file", "call_api", "payment_or_transfer"}
    )
    irreversible_actions: frozenset[str] = frozenset(
        {"execute_file", "payment_or_transfer"}
    )
    confirmed_destructive_types: frozenset[str] = frozenset(
        {
            "confirmed_destructive_command",
            "confirmed_mass_deletion",
            "confirmed_mass_encryption",
        }
    )

    def validate(self) -> None:
        if set(self.category_weights) != set(EvidenceCategory):
            raise ValueError("every evidence category requires exactly one weight")
        if any(not 0.0 <= value <= 1.0 for value in self.category_weights.values()):
            raise ValueError("category weights must be within 0..1")
        if any(not 0.0 <= value <= 100.0 for value in self.direct_floors.values()):
            raise ValueError("direct floors must be within 0..100")
        if not (
            0
            <= self.suspicious_threshold
            < self.dangerous_threshold
            < self.critical_threshold
            <= 100
        ):
            raise ValueError("policy thresholds must be strictly increasing")
        if not 0 <= self.ml_max_contribution <= 30:
            raise ValueError("LightGBM contribution limit must be within 0..30")
        if self.session_half_life_seconds <= 0 or self.session_history_limit < 1:
            raise ValueError("session settings must be positive")


def default_action_risk_config() -> ActionRiskConfig:
    config = ActionRiskConfig()
    config.validate()
    return config
