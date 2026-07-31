"""Pure CoreGuide v2 policy decisions; never changes the risk score."""

from __future__ import annotations

from .types import (
    CriterionStatus,
    NextAction,
    PolicyDecision,
    PolicyProfile,
    PolicyResult,
    RiskResultV2,
)

_DECISION_RANK = {
    PolicyDecision.ALLOW: 0,
    PolicyDecision.WARN: 1,
    PolicyDecision.REQUIRE_REVIEW: 2,
    PolicyDecision.SOFT_BLOCK: 3,
    PolicyDecision.HARD_BLOCK: 4,
}


class PolicyEngineV2:
    def decide(
        self,
        risk_result: RiskResultV2,
        profile: PolicyProfile | None = None,
    ) -> PolicyResult:
        selected = profile or PolicyProfile()
        score = risk_result.risk_score
        confidence = risk_result.confidence_score
        # Direct evidence was already validated by the shared pipeline.  A model
        # or low confidence cannot weaken this security floor.
        if risk_result.direct_floor >= 90:
            decision, action = PolicyDecision.HARD_BLOCK, NextAction.REPORT
        elif score >= 85:
            decision, action = PolicyDecision.HARD_BLOCK, NextAction.REPORT
        elif score >= 60:
            decision, action = selected.dangerous_decision, NextAction.SANDBOX
        elif score >= 40:
            if confidence >= 70:
                decision, action = PolicyDecision.SOFT_BLOCK, NextAction.USER_CONFIRMATION
            else:
                decision, action = PolicyDecision.REQUIRE_REVIEW, NextAction.SANDBOX
        elif score >= 20:
            decision, action = PolicyDecision.WARN, NextAction.DEEP_SCAN
        else:
            has_malicious_finding = any(
                item.adjusted_score > 0
                and item.status == CriterionStatus.MALICIOUS
                for item in risk_result.criteria
            )
            has_suspicious_finding = any(
                item.adjusted_score > 0
                and item.status == CriterionStatus.SUSPICIOUS
                for item in risk_result.criteria
            )
            if confidence < 40:
                decision, action = PolicyDecision.REQUIRE_REVIEW, NextAction.SANDBOX
            elif has_malicious_finding:
                decision, action = PolicyDecision.WARN, NextAction.DEEP_SCAN
            else:
                # Incomplete coverage is a reason to recommend a deeper scan,
                # not evidence that an otherwise clean or weakly suspicious URL
                # is dangerous.
                decision = PolicyDecision.ALLOW
                action = (
                    NextAction.DEEP_SCAN
                    if confidence < 40 or has_suspicious_finding
                    else NextAction.NONE
                )

        override = risk_result.effective_override
        if override:
            try:
                minimum = PolicyDecision(override.minimum_decision)
            except ValueError:
                minimum = PolicyDecision.REQUIRE_REVIEW
            if _DECISION_RANK[minimum] > _DECISION_RANK[decision]:
                decision = minimum
            action = NextAction.REPORT

        return PolicyResult(
            decision=decision,
            next_action=action,
            policy_version=selected.version,
            reason=(
                f"risk={score:.2f}, confidence={confidence:.2f}, level={risk_result.risk_level}"
            ),
        )
