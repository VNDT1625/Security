"""Versioned structured feature extraction for an optional action LightGBM model."""

from __future__ import annotations

import math
from dataclasses import dataclass

from .action_config import ActionRiskConfig
from .action_evidence import ActionClassification
from .action_types import ActionRiskInput, EvidenceGroup, SessionRiskResult


ACTION_TYPES = (
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
)

FEATURE_NAMES = (
    "action_type_code",
    "has_target",
    "accesses_secret",
    "sensitive_data_level",
    "external_destination",
    "destination_trust_score",
    "requested_by_user",
    "intent_match_score",
    "requires_admin",
    "privilege_level_code",
    "workflow_known",
    "payload_classified",
    "data_flow_outbound",
    "session_cumulative_risk",
    "rule_trigger_count",
    "critical_rule_triggered",
    "missing_feature_ratio",
    "destination_confidence",
)


@dataclass(frozen=True)
class ActionFeatureVector:
    schema_version: str
    values: dict[str, float | None]
    missing_fields: tuple[str, ...]

    @property
    def missing_ratio(self) -> float:
        return len(self.missing_fields) / max(1, len(self.values))

    def numeric_vector(self) -> list[float]:
        # LightGBM handles NaN as missing. Zero remains a real, potentially safe
        # value and is never substituted for unavailable context.
        return [
            math.nan if self.values[name] is None else float(self.values[name])
            for name in FEATURE_NAMES
        ]


def extract_action_features(
    value: ActionRiskInput,
    classification: ActionClassification,
    groups: list[EvidenceGroup],
    session: SessionRiskResult,
    missing_fields: list[str],
    config: ActionRiskConfig,
) -> ActionFeatureVector:
    data_types = {item.lower() for item in value.data_types}
    permission = (value.permission_level or "").lower()
    destination_score = value.destination_risk_score
    values: dict[str, float | None] = {
        "action_type_code": (
            float(ACTION_TYPES.index(value.action_type))
            if value.action_type in ACTION_TYPES
            else None
        ),
        "has_target": 1.0 if value.target_url else 0.0,
        "accesses_secret": 1.0 if classification.credential or classification.otp else 0.0,
        "sensitive_data_level": (
            1.0
            if classification.credential or classification.otp
            else 0.65
            if classification.sensitive
            else 0.0
            if value.data_types
            else None
        ),
        "external_destination": (
            None
            if classification.external_destination is None
            else float(classification.external_destination)
        ),
        "destination_trust_score": (
            None
            if destination_score is None
            else 1.0 - max(0.0, min(100.0, destination_score)) / 100.0
        ),
        "requested_by_user": None if not value.user_intent else 1.0,
        "intent_match_score": classification.intent_match_score,
        "requires_admin": 1.0 if classification.privileged else 0.0,
        "privilege_level_code": (
            {"none": 0.0, "denied": 0.0, "user": 0.35, "restricted": 0.25,
             "admin": 0.8, "root": 1.0, "system": 1.0}.get(permission)
            if permission
            else None
        ),
        "workflow_known": 1.0 if classification.workflow_approved else 0.0,
        "payload_classified": 1.0 if data_types else None,
        "data_flow_outbound": 1.0 if classification.transfer else 0.0,
        "session_cumulative_risk": session.cumulative_risk / 100.0,
        "rule_trigger_count": min(1.0, len(groups) / 10.0),
        "critical_rule_triggered": 1.0 if any(
            group.score >= 90 for group in groups
        ) else 0.0,
        "missing_feature_ratio": 0.0,  # Filled after the other values are known.
        "destination_confidence": value.destination_confidence,
    }
    missing = tuple(sorted(name for name, item in values.items() if item is None))
    ratio = len(missing) / max(1, len(values))
    values["missing_feature_ratio"] = ratio
    return ActionFeatureVector(config.feature_schema_version, values, missing)
