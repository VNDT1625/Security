"""Evidence-grounded explanations and privacy-safe audit traces."""

from __future__ import annotations

import hashlib
from typing import Any

from .action_types import ActionRiskResult

_SENSITIVE_KEYS = {
    "password",
    "otp",
    "token",
    "access_token",
    "api_key",
    "private_key",
    "payload",
    "command",
    "content",
}


def explain_action_result(
    *,
    direct_kinds: tuple[str, ...],
    category_scores: dict[str, float],
    missing_fields: list[str],
    decision: str,
) -> str:
    if direct_kinds:
        labels = ", ".join(kind.replace("_", " ") for kind in direct_kinds)
        return f"Đã xác nhận bằng chứng trực tiếp: {labels}; quyết định {decision}."
    risky = sorted(category_scores.items(), key=lambda item: (-item[1], item[0]))[:3]
    if risky:
        labels = ", ".join(f"{name} ({score:.0f})" for name, score in risky)
        if missing_fields:
            return (
                f"Các nhóm rủi ro chính: {labels}. "
                f"Thiếu ngữ cảnh: {', '.join(missing_fields)}; quyết định {decision}."
            )
        return f"Các nhóm rủi ro chính: {labels}; quyết định {decision}."
    if missing_fields:
        return (
            f"Chưa đủ dữ liệu để kết luận an toàn: {', '.join(missing_fields)}; "
            f"quyết định {decision}."
        )
    return f"Không ghi nhận nhóm bằng chứng nguy hiểm đáng kể; quyết định {decision}."


def _hash(value: object) -> str:
    return hashlib.sha256(str(value).encode("utf-8", errors="ignore")).hexdigest()


def _redact(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if lowered in _SENSITIVE_KEYS or any(part in lowered for part in _SENSITIVE_KEYS):
        return {"redacted": True, "sha256": _hash(value)}
    if isinstance(value, dict):
        return {str(name): _redact(item, str(name)) for name, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, str) and len(value) > 200:
        return {"redacted": True, "sha256": _hash(value)}
    return value


def build_action_audit_record(
    result: ActionRiskResult,
    *,
    workflow_id: str | None,
) -> dict[str, Any]:
    return _redact(
        {
            "schema_version": "3.0",
            "input_action_id": result.action_id,
            "workflow_id_hash": _hash(workflow_id) if workflow_id else None,
            "session_id_hash": result.session.session_id_hash,
            "rules_triggered": result.rules_triggered,
            "evidence_before_dedup": [
                item.to_dict() for item in result.evidence_before_dedup
            ],
            "evidence_after_dedup": [
                item.to_dict() for item in result.evidence_after_dedup
            ],
            "direct_floor": result.direct_floor,
            "composite_score": result.composite_score,
            "lightgbm_contribution": result.ml.risk_contribution,
            "confidence": result.confidence,
            "missing_fields": result.missing_fields,
            "policy_decision": result.decision.value,
            "reason_codes": result.reason_codes,
            "model_version": result.ml.model_version,
            "feature_schema_version": result.feature_schema_version,
            "scoring_version": result.scoring_version,
        }
    )
