"""Persist privacy-safe evidence-engine action decisions."""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from backend.models import AuditLog
from backend.routers.auth import ActorContext
from backend.security_utils import hash_metadata, input_sha256
from shared.schemas import AgentRiskResponse


def log_action_assessment(
    db: Session,
    *,
    result: AgentRiskResponse,
    actor: ActorContext,
    request: Request,
    action_type: str,
    target: str | None,
) -> None:
    core = result.security_core or {}
    audit = core.get("audit") if isinstance(core.get("audit"), dict) else {}
    db.add(
        AuditLog(
            actor_user_id=actor.user.id if actor.user is not None else None,
            actor_api_key_id=actor.api_key.id if actor.api_key is not None else None,
            actor_channel=actor.channel,
            action="security.action.assessed",
            resource_type="agent_action",
            resource_id=result.request_id,
            source_ip_hash=hash_metadata(request.client.host if request.client else None),
            user_agent_hash=hash_metadata(request.headers.get("user-agent")),
            extra_metadata={
                "action_type": action_type,
                "target_sha256": input_sha256(target),
                "decision": result.decision.value,
                "risk_score": result.risk_score,
                "confidence": result.confidence,
                "security_core": audit,
            },
        )
    )
    db.commit()
