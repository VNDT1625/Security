"""Policy & Action Risk Engine (module-specification.md M4; design.md §5).

Deterministic, auditable rule engine that converts a raw risk score + optional
AgentContext into a Decision. No ML, no network, no runtime learning.
"""

from __future__ import annotations

from shared.constants import RISK_THRESHOLD_ALLOW, RISK_THRESHOLD_BLOCK, RISK_THRESHOLD_WARN
from shared.schemas import AgentContext, Decision, Evidence, RiskLevel


def score_to_level(score: float) -> RiskLevel:
    if score < 0.15:
        return RiskLevel.SAFE
    if score < 0.40:
        return RiskLevel.LOW
    if score < 0.70:
        return RiskLevel.MEDIUM
    if score < 0.85:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


class PolicyEngine:
    def __init__(
        self,
        block: float = RISK_THRESHOLD_BLOCK,
        warn: float = RISK_THRESHOLD_WARN,
        allow: float = RISK_THRESHOLD_ALLOW,
    ) -> None:
        self.block = block
        self.warn = warn
        self.allow = allow

    # ------------------------------------------------------------------ human
    def evaluate_human(self, risk_score: float) -> Decision:
        """Simple threshold decision for human users (Extension / Web)."""
        if risk_score >= self.block:
            return Decision.BLOCK
        if risk_score >= self.warn:
            return Decision.WARN
        return Decision.ALLOW

    # -------------------------------------------------------------- guidance
    def recommend_behavior(self, decision: Decision, ctx: AgentContext | None = None) -> str:
        mapping = {
            Decision.ALLOW: "Tiếp tục hành động bình thường.",
            Decision.WARN: "Tiếp tục nhưng thận trọng và ghi nhận cảnh báo cho người dùng.",
            Decision.BLOCK: "DỪNG hành động. Không thực hiện. Báo lý do cho người dùng.",
            Decision.ASK_USER_CONFIRMATION: (
                "DỪNG và hỏi xác nhận người dùng trước khi tiếp tục — không tự quyết."
            ),
        }
        return mapping[decision]

    def combine_evidence_score(self, base_score: float, evidence: list[Evidence]) -> float:
        """Blend base score with the strongest evidence contribution (not just max).

        Uses a soft-OR: combine base with the top contribution so multiple strong
        signals push the score up without exceeding 1.0.
        """
        contribs = [e.contribution for e in evidence if e.contribution]
        if not contribs:
            return base_score
        top = max(contribs)
        return min(1.0 - (1.0 - base_score) * (1.0 - min(top, 0.99)), 1.0)
