"""WebSocket Q&A endpoint with optional owned-history context.

Chat never runs a new risk assessment. Fresh URL/email/SMS analysis belongs to
Analyze; an ``analysis_id`` only reuses the signed-in user's stored result.
"""

from __future__ import annotations

import inspect
import json
import uuid
from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import selectinload

from backend.db import get_db
from backend.dependencies import (
    get_explanation_service,
    get_user_explanation_service,
    get_user_legal_answer_service,
)
from backend.middleware import sanitize_text
from backend.models import ScanEvent
from backend.routers.auth import build_actor_plan_info, resolve_actor
from backend.services.legal_answer_service import LegalQuestionContext
from backend.services.quota_service import (
    refund_ai_credits,
    reserve_ai_credits,
)
from shared.schemas import Evidence, Severity

router = APIRouter(tags=["chat"])


def _accepts_keyword(callable_obj: object, keyword: str) -> bool:
    """Feature-detect evolving legal service/context APIs without version checks."""

    try:
        parameters = inspect.signature(callable_obj).parameters
    except (TypeError, ValueError):
        return False
    return keyword in parameters or any(
        item.kind is inspect.Parameter.VAR_KEYWORD for item in parameters.values()
    )


def _legal_context(raw: object, *, intent_mode: str) -> LegalQuestionContext:
    values = raw if isinstance(raw, Mapping) else {}
    candidates = {
        "jurisdiction": sanitize_text(str(values.get("jurisdiction", ""))),
        "as_of_date": sanitize_text(str(values.get("as_of_date", ""))),
        "actor": sanitize_text(str(values.get("actor", ""))),
        "action": sanitize_text(str(values.get("action", ""))),
        "data_or_asset": sanitize_text(str(values.get("data_or_asset", ""))),
        "purpose": sanitize_text(str(values.get("purpose", ""))),
        "recipient": sanitize_text(str(values.get("recipient", ""))),
        "consent_state": sanitize_text(str(values.get("consent_state", ""))),
        "mode": intent_mode,
    }
    supported = {
        key: value
        for key, value in candidates.items()
        if _accepts_keyword(LegalQuestionContext, key)
    }
    return LegalQuestionContext(**supported)


def _model_dump(value: object) -> dict[str, Any]:
    dump = getattr(value, "model_dump", None)
    if not callable(dump):
        return {}
    payload = dump(mode="json") if _accepts_keyword(dump, "mode") else dump()
    return dict(payload) if isinstance(payload, Mapping) else {}


def _generation_attempt_failed(payload: Mapping[str, Any]) -> bool:
    explicit_failure = (
        payload.get("generation_attempted") is True and payload.get("generation_succeeded") is False
    )
    return explicit_failure or str(payload.get("reason_code", "")).strip().casefold() in {
        "generation_failed",
        "generator_failed",
        "model_generation_failed",
    }


def _public_legal_payload(
    payload: Mapping[str, Any],
) -> tuple[dict[str, Any], str, str, dict[str, Any]]:
    """Strip admin-only retrieval internals while retaining release traceability."""

    public = dict(payload)
    raw_trace = public.pop("retrieval_trace", {})
    public.pop("generation_attempted", None)
    public.pop("generation_succeeded", None)
    trace = raw_trace if isinstance(raw_trace, Mapping) else {}
    trace_id = str(public.get("trace_id") or trace.get("trace_id") or "")
    retrieval_mode = str(public.get("retrieval_mode") or trace.get("mode") or "")

    raw_corpus = public.get("corpus")
    corpus_values = raw_corpus if isinstance(raw_corpus, Mapping) else {}
    corpus = {
        "release_id": str(
            corpus_values.get("release_id")
            or corpus_values.get("corpus_release_id")
            or public.get("corpus_release_id")
            or ""
        ),
        "verified_through": str(
            corpus_values.get("verified_through") or public.get("verified_through") or ""
        ),
    }
    if trace_id:
        public["trace_id"] = trace_id
    if retrieval_mode:
        public["retrieval_mode"] = retrieval_mode
    public["corpus"] = corpus
    return public, trace_id, retrieval_mode, corpus


def _load_owned_history_context(
    db: DbSession,
    *,
    user_id: str | None,
    request_id: str,
) -> tuple[ScanEvent, list[Evidence], dict[str, Any]]:
    """Load one privacy-minimised analysis context owned by the current user."""

    clean_id = sanitize_text(request_id).strip()
    if not clean_id:
        raise HTTPException(status_code=422, detail="Mã lịch sử không hợp lệ.")
    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="Bạn cần đăng nhập để dùng kết quả lịch sử làm ngữ cảnh.",
        )

    row = db.execute(
        select(ScanEvent)
        .options(selectinload(ScanEvent.evidence))
        .where(ScanEvent.request_id == clean_id, ScanEvent.user_id == user_id)
    ).scalar_one_or_none()
    if row is None:
        # Do not reveal whether the id belongs to another account.
        raise HTTPException(status_code=404, detail="Không tìm thấy kết quả lịch sử này.")

    evidence: list[Evidence] = []
    for item in row.evidence[:50]:
        try:
            severity = Severity(item.severity)
        except ValueError:
            severity = Severity.INFO
        evidence.append(
            Evidence(
                evidence_id=item.id,
                source=sanitize_text(item.source),
                message=sanitize_text(item.message),
                severity=severity,
                feature=sanitize_text(item.feature) if item.feature else None,
                contribution=item.contribution,
            )
        )

    assessment_context = {
        "risk_score": round(float(row.risk_score) * 100),
        "risk_level": row.risk_level,
        "decision": row.decision,
        "confidence": round(float(row.confidence) * 100),
        "reasons": [item.message for item in evidence[:10]],
    }
    return row, evidence, assessment_context


@router.websocket("/v1/chat")
async def chat_ws(ws: WebSocket, db: DbSession = Depends(get_db)):
    await ws.accept()
    expl = get_explanation_service()
    turn_count = 0
    try:
        while True:
            raw = await ws.receive_text()
            payload = json.loads(raw)
            access_token = sanitize_text(payload.get("access_token", ""))
            credentials = (
                HTTPAuthorizationCredentials(scheme="Bearer", credentials=access_token)
                if access_token
                else None
            )
            actor = resolve_actor(credentials, db, ws)  # WebSocket exposes client like Request.
            user_id = actor.user.id if actor.user else None
            expl = get_user_explanation_service(db, user_id)
            plan = build_actor_plan_info(db, actor)
            if turn_count > plan.chatFollowupLimit:
                await ws.send_text(
                    json.dumps(
                        {
                            "type": "error",
                            "error": "Bạn đã dùng hết số câu hỏi tiếp nối của cuộc trò chuyện này.",
                        }
                    )
                )
                continue

            question = sanitize_text(payload.get("question", ""))
            context = payload.get("context") or {}
            analysis_id = sanitize_text(context.get("analysis_id", "")) if context else ""
            history_row: ScanEvent | None = None
            history_evidence: list[Evidence] = []
            history_assessment: dict[str, Any] | None = None
            if analysis_id:
                history_row, history_evidence, history_assessment = _load_owned_history_context(
                    db,
                    user_id=user_id,
                    request_id=analysis_id,
                )

            legal_service = get_user_legal_answer_service(db, user_id)
            raw_legal_context = payload.get("legal_context") or {}
            requested_intent_mode = sanitize_text(
                str(payload.get("intent_mode", "auto"))
            ).casefold()
            selected_intent_mode = (
                requested_intent_mode if requested_intent_mode in {"auto", "legal"} else "auto"
            )
            intent_mode = (
                "legal"
                if isinstance(raw_legal_context, Mapping) and bool(raw_legal_context)
                else selected_intent_mode
            )
            context_model = _legal_context(
                raw_legal_context,
                intent_mode=intent_mode,
            )
            legal_credit_reserved = False

            def before_generate(
                _actor: object = actor,
                _ws: WebSocket = ws,
            ) -> None:
                nonlocal legal_credit_reserved
                if legal_credit_reserved:
                    return
                reserve_ai_credits(db, _actor, _ws, kind="explanation")
                legal_credit_reserved = True

            answer_kwargs: dict[str, Any] = {}
            if _accepts_keyword(legal_service.answer, "intent_mode"):
                answer_kwargs["intent_mode"] = intent_mode
            elif _accepts_keyword(legal_service.answer, "mode"):
                answer_kwargs["mode"] = intent_mode
            if _accepts_keyword(legal_service.answer, "before_generate"):
                answer_kwargs["before_generate"] = before_generate
            legal_result = None
            if history_row is None:
                try:
                    legal_result = await legal_service.answer(
                        question,
                        context_model,
                        **answer_kwargs,
                    )
                except Exception:
                    if legal_credit_reserved:
                        refund_ai_credits(db, actor, ws, kind="explanation")
                    raise
            if legal_result is not None:
                internal_legal_payload = _model_dump(legal_result)
                if legal_credit_reserved and _generation_attempt_failed(internal_legal_payload):
                    refund_ai_credits(db, actor, ws, kind="explanation")
                legal_payload, trace_id, retrieval_mode, corpus = _public_legal_payload(
                    internal_legal_payload
                )
                await ws.send_text(
                    json.dumps({"type": "delta", "delta": legal_payload.get("answer", "")})
                )
                await ws.send_text(
                    json.dumps(
                        {
                            "type": "final",
                            "message_id": str(uuid.uuid4()),
                            "modality": "legal",
                            "legal_answer": legal_payload,
                            "trace_id": trace_id,
                            "retrieval_mode": retrieval_mode,
                            "corpus": corpus,
                        }
                    )
                )
                turn_count += 1
                continue

            modality = "text"
            operator_context = sanitize_text(context.get("operator_context", ""))
            if history_row is not None:
                modality = history_row.modality
                operator_context = (
                    f"Kết quả lịch sử @{history_row.request_id}: "
                    f"{history_row.risk_level}, quyết định {history_row.decision}."
                )
            history = payload.get("history") or []
            if isinstance(history, list):
                history_context = "\n".join(
                    f"{str(item.get('role', 'user'))}: {sanitize_text(str(item.get('text', '')))}"
                    for item in history[-4:]
                    if isinstance(item, dict)
                )
                operator_context = sanitize_text(
                    f"{operator_context}\nLịch sử hội thoại:\n{history_context}"
                )

            evidence = history_evidence
            excerpt = (
                f"Kết quả lịch sử {history_row.request_id}"
                if history_row is not None
                else question
            )
            assessment_context = history_assessment
            reserved_explanation = expl.llm_ready
            if reserved_explanation:
                reserve_ai_credits(db, actor, ws, kind="explanation")
            try:
                async for token in expl.generate(
                    evidence,
                    excerpt,
                    question,
                    operator_context=operator_context,
                    assessment_context=assessment_context,
                ):
                    await ws.send_text(json.dumps({"type": "delta", "delta": token}))
            except Exception:
                if reserved_explanation:
                    refund_ai_credits(db, actor, ws, kind="explanation")
                raise
            if reserved_explanation and not expl.available:
                refund_ai_credits(db, actor, ws, kind="explanation")

            final = {
                "type": "final",
                "message_id": (
                    history_row.request_id
                    if history_row is not None
                    else str(uuid.uuid4())
                ),
                "modality": modality,
            }
            if history_row is not None:
                final["analysis_id"] = history_row.request_id
            await ws.send_text(json.dumps(final))
            turn_count += 1
    except WebSocketDisconnect:
        return
    except HTTPException as exc:
        await ws.send_text(json.dumps({"type": "error", "error": str(exc.detail)}))
    except Exception as exc:  # pragma: no cover
        await ws.send_text(json.dumps({"type": "error", "error": str(exc)}))
