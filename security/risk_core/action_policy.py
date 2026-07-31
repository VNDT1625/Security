"""Final action policy. Models and scorers cannot override this module."""

from __future__ import annotations

from dataclasses import dataclass

from .action_config import ActionRiskConfig
from .action_evidence import ActionClassification
from .action_types import (
    ActionPolicyDecision,
    ActionRiskLevel,
    DirectEvidenceResult,
    LightGBMRiskResult,
)


@dataclass(frozen=True)
class ActionPolicyResult:
    risk_level: ActionRiskLevel
    decision: ActionPolicyDecision
    reason_code: str


class EvidenceActionPolicy:
    def __init__(self, config: ActionRiskConfig) -> None:
        self.config = config

    def decide(
        self,
        danger_score: float,
        confidence: float,
        direct: DirectEvidenceResult,
        missing_fields: list[str],
        classification: ActionClassification,
        ml: LightGBMRiskResult,
    ) -> ActionPolicyResult:
        if direct.floor >= 90:
            return ActionPolicyResult(
                ActionRiskLevel.CRITICAL,
                ActionPolicyDecision.BLOCK,
                "DIRECT_CRITICAL_EVIDENCE",
            )

        if "legal_context" in missing_fields:
            return ActionPolicyResult(
                ActionRiskLevel.INSUFFICIENT_INFORMATION,
                ActionPolicyDecision.ASK_CONFIRM,
                "LEGAL_REVIEW_REQUIRED",
            )

        critical_missing = bool(
            set(missing_fields)
            & {
                "destination",
                "payload_classification",
                "permission_context",
                "data_sensitivity",
            }
        )
        if critical_missing and (
            classification.sensitive
            or classification.privileged
            or classification.transfer
            or classification.irreversible
        ):
            decision = (
                ActionPolicyDecision.TEMPORARY_BLOCK
                if classification.irreversible
                else ActionPolicyDecision.SANDBOX
                if classification.privileged
                else ActionPolicyDecision.ASK_CONFIRM
            )
            return ActionPolicyResult(
                ActionRiskLevel.INSUFFICIENT_INFORMATION,
                decision,
                "MISSING_CRITICAL_CONTEXT",
            )

        if danger_score >= self.config.critical_threshold:
            if confidence >= self.config.high_confidence_threshold:
                decision = ActionPolicyDecision.BLOCK
            elif classification.irreversible or classification.privileged:
                decision = ActionPolicyDecision.BLOCK
            else:
                decision = ActionPolicyDecision.SANDBOX
            return ActionPolicyResult(
                ActionRiskLevel.CRITICAL,
                decision,
                "CRITICAL_COMPOSITE_RISK",
            )
        if danger_score >= self.config.dangerous_threshold:
            decision = (
                ActionPolicyDecision.BLOCK
                if classification.irreversible
                and confidence >= self.config.high_confidence_threshold
                else ActionPolicyDecision.SANDBOX
                if confidence < self.config.high_confidence_threshold
                else ActionPolicyDecision.ASK_CONFIRM
            )
            return ActionPolicyResult(
                ActionRiskLevel.DANGEROUS,
                decision,
                "DANGEROUS_COMPOSITE_RISK",
            )
        if danger_score >= self.config.suspicious_threshold:
            return ActionPolicyResult(
                ActionRiskLevel.SUSPICIOUS,
                (
                    ActionPolicyDecision.ASK_CONFIRM
                    if classification.sensitive or classification.privileged
                    else ActionPolicyDecision.WARN
                ),
                "SUSPICIOUS_COMPOSITE_RISK",
            )
        if (
            ml.available
            and not ml.out_of_distribution
            and (ml.risk_probability or 0.0) >= self.config.ml_review_probability
        ):
            return ActionPolicyResult(
                ActionRiskLevel.SUSPICIOUS,
                ActionPolicyDecision.ASK_CONFIRM,
                "MODEL_WEAK_SIGNAL_COMBINATION",
            )
        if confidence < self.config.low_confidence_threshold:
            return ActionPolicyResult(
                ActionRiskLevel.INSUFFICIENT_INFORMATION,
                ActionPolicyDecision.ASK_CONFIRM,
                "LOW_CONFIDENCE",
            )
        if classification.workflow_approved:
            return ActionPolicyResult(
                ActionRiskLevel.SAFE,
                ActionPolicyDecision.ALLOW_WITH_LOG,
                "APPROVED_WORKFLOW",
            )
        return ActionPolicyResult(
            ActionRiskLevel.SAFE,
            ActionPolicyDecision.ALLOW,
            "LOW_RISK",
        )
