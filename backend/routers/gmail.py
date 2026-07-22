"""Authenticated Gmail OAuth, message picker, and raw-message assessment."""
from __future__ import annotations

import asyncio
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from backend.config import settings
from backend.db import SessionLocal, get_db
from backend.dependencies import get_inference_service, get_user_inference_service
from backend.routers.auth import (
    ActorContext,
    CurrentSession,
    build_plan_info,
)
from backend.services.gmail_service import GmailIntegrationError, gmail_service
from backend.services.inference_service import InferenceService
from backend.services.quota_service import (
    refund_ai_credits,
    reserve_ai_credits,
    reserve_deep_scan_quota,
    reserve_scan_quota,
)
from backend.services.scan_log_service import log_assessment
from security.email_message_parser import parse_email_bytes, safe_email_preview
from shared.adapter_schemas import AdapterRunStatus, AdapterTask
from shared.schemas import AssessResponse

router = APIRouter(prefix="/v1/integrations/gmail", tags=["gmail"])


class GmailAssessRequest(BaseModel):
    analysis_depth: Literal["quick", "balanced", "deep", "pro"] = "balanced"
    operator_context: str = Field(default="", max_length=2_000)


def _raise_integration(exc: GmailIntegrationError) -> None:
    status_code = {
        "not_configured": status.HTTP_503_SERVICE_UNAVAILABLE,
        "not_connected": status.HTTP_409_CONFLICT,
        "expired": status.HTTP_401_UNAUTHORIZED,
        "message_too_large": status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        "invalid_message_id": status.HTTP_400_BAD_REQUEST,
        "invalid_raw": status.HTTP_502_BAD_GATEWAY,
    }.get(exc.code, status.HTTP_502_BAD_GATEWAY)
    raise HTTPException(status_code=status_code, detail=exc.detail) from exc


def _return_url(**updates: str) -> str:
    target = urlsplit(settings.gmail_web_return_url)
    query = dict(parse_qsl(target.query, keep_blank_values=True))
    query.update(updates)
    return urlunsplit((target.scheme, target.netloc, target.path, urlencode(query), ""))


def _oauth_redirect(**updates: str) -> RedirectResponse:
    response = RedirectResponse(_return_url(**updates), status_code=303)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _get_raw_message(user_id: str, message_id: str):
    with SessionLocal() as worker_db:
        return gmail_service.get_raw_message(worker_db, user_id, message_id)


def _get_safe_preview(user_id: str, message_id: str) -> dict:
    raw = _get_raw_message(user_id, message_id)
    parsed = parse_email_bytes(raw.data, f"gmail-{raw.message_id}.eml")
    raw_html = str(parsed.metadata.get("raw_html") or "")
    body = safe_email_preview(
        parsed.body,
        is_html=bool(raw_html and parsed.body.strip() == raw_html.strip()),
    )
    return {
        "id": raw.message_id,
        "threadId": raw.thread_id,
        "from": str(parsed.metadata.get("from") or "")[:1_000],
        "replyTo": str(parsed.metadata.get("reply_to") or "")[:1_000],
        "subject": str(parsed.metadata.get("subject") or "(Không có chủ đề)")[:1_000],
        "date": str(parsed.metadata.get("date") or "")[:500],
        "body": body,
        "labelIds": raw.label_ids,
        "attachments": [
            {
                "filename": item.filename[:500],
                "contentType": item.content_type[:200],
                "size": len(item.data),
            }
            for item in parsed.attachments[:30]
        ],
        "linksRemoved": body.count("[LIÊN KẾT ĐÃ KHỬ]"),
    }


@router.get("/status")
def gmail_status(auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict:
    return gmail_service.status(db, auth.user.id)


@router.post("/connect")
def gmail_connect(auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict[str, str]:
    try:
        return {"authUrl": gmail_service.begin_oauth(db, auth.user.id, auth.user.email)}
    except GmailIntegrationError as exc:
        _raise_integration(exc)


@router.get("/callback")
def gmail_callback(
    state: str = Query(default="", max_length=200),
    code: str = Query(default="", max_length=2_000),
    error: str = Query(default="", max_length=200),
    db: DbSession = Depends(get_db),
):
    if error or not state or not code:
        return _oauth_redirect(gmail="error", reason="access_denied")
    try:
        gmail_service.complete_oauth(db, state, code)
        return _oauth_redirect(gmail="connected")
    except GmailIntegrationError as exc:
        return _oauth_redirect(gmail="error", reason=exc.code)


@router.get("/messages")
def gmail_messages(
    auth: CurrentSession,
    q: str = Query(default="", max_length=200),
    label: str = Query(default="", max_length=20),
    limit: int = Query(default=20, ge=1, le=30),
    db: DbSession = Depends(get_db),
) -> dict:
    try:
        return {"messages": gmail_service.list_messages(
            db, auth.user.id, query=q.strip(), label=label.upper(), max_results=limit
        )}
    except GmailIntegrationError as exc:
        _raise_integration(exc)


@router.get("/messages/{message_id}/preview")
async def gmail_message_preview(message_id: str, auth: CurrentSession) -> dict:
    try:
        return await asyncio.to_thread(_get_safe_preview, auth.user.id, message_id)
    except GmailIntegrationError as exc:
        _raise_integration(exc)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Không thể tạo bản xem trước an toàn cho email này.",
        ) from exc


@router.post("/messages/{message_id}/assess", response_model=AssessResponse)
async def assess_gmail_message(
    message_id: str,
    payload: GmailAssessRequest,
    request: Request,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
    svc: InferenceService = Depends(get_inference_service),
):
    svc = get_user_inference_service(db, auth.user.id)
    plan = build_plan_info(db, auth.user.id)
    if payload.analysis_depth == "pro" and plan.tier == "free":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Chế độ Pro AI yêu cầu gói Pro hoặc cao hơn.",
        )
    try:
        raw = await asyncio.to_thread(_get_raw_message, auth.user.id, message_id)
    except GmailIntegrationError as exc:
        _raise_integration(exc)
    actor = ActorContext(user=auth.user, channel="web")
    reserve_scan_quota(db, actor, request)
    if payload.analysis_depth in {"deep", "pro"}:
        reserve_deep_scan_quota(db, actor, request)

    context_mode = (
        "active"
        if payload.analysis_depth == "pro" and plan.autoMessageContext
        else "shadow"
        if plan.autoMessageContext
        else "off"
    )
    reserved_ai = context_mode != "off" and svc.context_ai_ready(AdapterTask.MESSAGE_CONTEXT)
    if reserved_ai:
        reserve_ai_credits(db, actor, request, kind="evaluation")
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(
                svc.assess_email_bytes,
                raw.data,
                f"gmail-{raw.message_id}.eml",
                analysis_depth=payload.analysis_depth,
                context_ai_mode=context_mode,
                operator_context=payload.operator_context,
                gmail_context={
                    "message_id": raw.message_id,
                    "thread_id": raw.thread_id,
                    "label_ids": raw.label_ids,
                },
            ),
            timeout=max(10.0, min(float(settings.email_analysis_timeout_seconds), 180.0)),
        )
    except TimeoutError as exc:
        if reserved_ai:
            refund_ai_credits(db, actor, request, kind="evaluation")
        raise HTTPException(status_code=504, detail="Phân tích Gmail vượt thời gian.") from exc
    except Exception:
        if reserved_ai:
            refund_ai_credits(db, actor, request, kind="evaluation")
        raise
    if reserved_ai and (
        result.contextual_analysis is None
        or result.contextual_analysis.status != AdapterRunStatus.COMPLETED
    ):
        refund_ai_credits(db, actor, request, kind="evaluation")
    log_assessment(
        db,
        result=result,
        actor=actor,
        request=request,
        raw_input=raw.data,
        metadata={"source": "gmail", "gmail_message_id": raw.message_id},
        retain_input_preview=False,
    )
    return result


@router.delete("/connection")
def gmail_disconnect(auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict[str, bool]:
    gmail_service.disconnect(db, auth.user.id)
    return {"disconnected": True}
