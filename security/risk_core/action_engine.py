"""Evidence-based action risk orchestration."""

from __future__ import annotations

from .action_config import ActionRiskConfig, default_action_risk_config
from .action_evidence import (
    collect_action_evidence,
    deduplicate_evidence,
    normalize_evidence,
)
from .action_explanation import explain_action_result
from .action_features import extract_action_features
from .action_lightgbm import LightGBMRiskAdapter
from .action_policy import EvidenceActionPolicy
from .action_scoring import (
    compute_action_confidence,
    evaluate_direct_evidence,
    score_composite,
)
from .action_session import SessionRiskTracker
from .action_types import (
    ActionRiskInput,
    ActionRiskLevel,
    ActionRiskResult,
    SecurityEvidence,
)


class EvidenceBasedActionRiskEngine:
    def __init__(
        self,
        config: ActionRiskConfig | None = None,
        *,
        lightgbm: LightGBMRiskAdapter | None = None,
        session_tracker: SessionRiskTracker | None = None,
    ) -> None:
        self.config = config or default_action_risk_config()
        self.config.validate()
        self.lightgbm = lightgbm or LightGBMRiskAdapter()
        self.session_tracker = session_tracker or SessionRiskTracker(self.config)
        self.policy = EvidenceActionPolicy(self.config)

    def evaluate(
        self,
        value: ActionRiskInput,
        *,
        extra_evidence: tuple[SecurityEvidence, ...] = (),
    ) -> ActionRiskResult:
        collected, missing, rules, classification = collect_action_evidence(
            value, self.config
        )
        before = normalize_evidence([*collected, *extra_evidence])
        after, groups = deduplicate_evidence(before, self.config)
        rule_score, _ = score_composite(groups, self.config)

        categories = {item.category for item in after}
        session = self.session_tracker.assess_and_record(
            value.session_id,
            categories,
            rule_score,
            external_sensitive_transfer=(
                classification.transfer
                and classification.sensitive
                and classification.external_destination is True
            ),
            workflow_approved=classification.workflow_approved,
        )
        features = extract_action_features(
            value,
            classification,
            groups,
            session,
            missing,
            self.config,
        )
        ml = self.lightgbm.assess(features, self.config)
        composite, category_scores = score_composite(
            groups,
            self.config,
            ml=ml,
            session=session,
        )
        direct = evaluate_direct_evidence(after, self.config)
        final_score = max(direct.floor, composite)
        confidence = compute_action_confidence(
            after,
            groups,
            missing_fields=missing,
            total_expected_fields=5,
            ml=ml,
            direct=direct,
        )
        policy = self.policy.decide(
            final_score,
            confidence,
            direct,
            missing,
            classification,
            ml,
        )
        reason_codes = sorted(
            {
                *(item.reason_code for item in after if item.reason_code),
                policy.reason_code,
                *(
                    ["SESSION_SLOW_EXFILTRATION"]
                    if session.slow_exfiltration
                    else []
                ),
                *(
                    ["SESSION_MULTI_STEP_ATTACK"]
                    if session.multi_step_attack
                    else []
                ),
            }
        )
        explanation = explain_action_result(
            direct_kinds=direct.kinds,
            category_scores=category_scores,
            missing_fields=missing,
            decision=policy.decision.value,
        )
        public_danger_score = (
            None
            if policy.risk_level == ActionRiskLevel.INSUFFICIENT_INFORMATION
            and direct.floor == 0
            else round(final_score, 4)
        )
        return ActionRiskResult(
            action_id=value.action_id,
            danger_score=public_danger_score,
            confidence=confidence,
            risk_level=policy.risk_level,
            decision=policy.decision,
            direct_floor=direct.floor,
            composite_score=round(composite, 4),
            rule_score=round(rule_score, 4),
            evidence_before_dedup=before,
            evidence_after_dedup=after,
            evidence_groups=groups,
            direct_evidence=direct,
            ml=ml,
            session=session,
            missing_fields=missing,
            reason_codes=reason_codes,
            explanation=explanation,
            rules_triggered=rules,
            scoring_version=self.config.scoring_version,
            feature_schema_version=self.config.feature_schema_version,
            policy_version=self.config.policy_version,
        )
