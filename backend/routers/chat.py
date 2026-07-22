"""WebSocket chat endpoint (design.md GAP-2.6 RAG-like pattern).

Flow: user question (+context) -> Layer 1 assessment -> Layer 2 LLM explanation
streamed token-by-token -> final message with assessment attached.
"""

from __future__ import annotations

import inspect
import json
import uuid
from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session as DbSession

from backend.db import get_db
from backend.dependencies import (
    get_explanation_service,
    get_inference_service,
    get_user_explanation_service,
    get_user_inference_service,
    get_user_legal_answer_service,
)
from backend.middleware import sanitize_text
from backend.routers.auth import build_actor_plan_info, resolve_actor
from backend.services.legal_answer_service import LegalAnswerService, LegalQuestionContext
from backend.services.quota_service import (
    refund_ai_credits,
    reserve_ai_credits,
    reserve_scan_quota,
)
from shared.adapter_schemas import AdapterRunStatus, AdapterTask

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


@router.websocket("/v1/chat")
async def chat_ws(ws: WebSocket, db: DbSession = Depends(get_db)):
    await ws.accept()
    svc = get_inference_service()
    expl = get_explanation_service()
    turn_count = 0
    cached_context_key = ""
    cached_assessment = None
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
            svc = get_user_inference_service(db, user_id)
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
            legal_turn = intent_mode == "legal"
            if not legal_turn:
                detector = getattr(
                    legal_service,
                    "is_legal_question",
                    LegalAnswerService.is_legal_question,
                )
                try:
                    legal_turn = bool(detector(question))
                except Exception:
                    legal_turn = LegalAnswerService.is_legal_question(question)
            scan_reserved = False
            if legal_turn:
                reserve_scan_quota(db, actor, ws)
                scan_reserved = True
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
            context = payload.get("context") or {}
            content = sanitize_text(context.get("content", "")) if context else ""
            modality = context.get("modality", "text") if context else "text"
            operator_context = sanitize_text(context.get("operator_context", ""))
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

            assessment = None
            if content:
                context_key = f"{modality}\n{content}\n{operator_context}"
                if context_key == cached_context_key and cached_assessment is not None:
                    assessment = cached_assessment
                else:
                    if not scan_reserved:
                        reserve_scan_quota(db, actor, ws)
                        scan_reserved = True
                    auto_context = (
                        plan.autoWebContext if modality == "url" else plan.autoMessageContext
                    )
                    context_task = (
                        AdapterTask.WEB_CONTEXT
                        if modality == "url"
                        else AdapterTask.MESSAGE_CONTEXT
                    )
                    context_mode = "shadow" if auto_context else "off"
                    reserved_evaluation = context_mode == "shadow" and svc.context_ai_ready(
                        context_task
                    )
                    if reserved_evaluation:
                        reserve_ai_credits(db, actor, ws, kind="evaluation")
                    try:
                        if modality == "url":
                            assessment = svc.assess_url(
                                content,
                                operator_context,
                                context_ai_mode=context_mode,
                            )
                        else:
                            assessment = svc.assess_text(
                                content,
                                modality,
                                {"operator_context": operator_context},
                                context_ai_mode=context_mode,
                            )
                    except Exception:
                        if reserved_evaluation:
                            refund_ai_credits(db, actor, ws, kind="evaluation")
                        raise
                    if reserved_evaluation and (
                        assessment.contextual_analysis is None
                        or assessment.contextual_analysis.status != AdapterRunStatus.COMPLETED
                    ):
                        refund_ai_credits(db, actor, ws, kind="evaluation")
                    cached_context_key = context_key
                    cached_assessment = assessment

            evidence = assessment.evidence if assessment else []
            excerpt = content or question
            assessment_context = assessment.model_dump(mode="json") if assessment else None
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
                "message_id": assessment.request_id if assessment else "",
                "modality": modality,
            }
            if assessment:
                final["assessment"] = assessment.model_dump(mode="json")
            await ws.send_text(json.dumps(final))
            turn_count += 1
    except WebSocketDisconnect:
        return
    except HTTPException as exc:
        await ws.send_text(json.dumps({"type": "error", "error": str(exc.detail)}))
    except Exception as exc:  # pragma: no cover
        await ws.send_text(json.dumps({"type": "error", "error": str(exc)}))
