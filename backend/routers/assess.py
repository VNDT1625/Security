"""Assessment endpoints (design.md §7 API Contract)."""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session as DbSession

from backend.config import settings
from backend.db import get_db
from backend.dependencies import get_inference_service, get_user_inference_service
from backend.middleware import sanitize_text
from backend.models import AssessmentCache
from backend.routers.auth import (
    BearerCredentials,
    build_actor_plan_info,
    require_api_key_scope,
    resolve_actor,
)
from backend.security_utils import input_sha256, utcnow
from backend.services.ai_context_weight_service import get_url_assessment_cache_enabled
from backend.services.action_audit_service import log_action_assessment
from backend.services.exe_quick_scan_service import exe_quick_scan_service
from backend.services.inference_service import InferenceService
from backend.services.quota_service import (
    refund_ai_credits,
    reserve_ai_credits,
    reserve_deep_scan_quota,
    reserve_scan_quota,
)
from backend.services.scan_log_service import log_assessment
from security.browser_sandbox import BrowserSandboxRunner
from security.exe_sandbox import ExeSandboxRunner
from security.risk_core import default_config
from security.url_sandbox import URLSandboxRunner
from shared.adapter_schemas import (
    AdapterRunStatus,
    AdapterTask,
    AssessPhoneRequest,
    AssessPhoneResponse,
)
from shared.schemas import (
    AgentRiskResponse,
    AssessActionRequest,
    AssessResponse,
    AssessTextRequest,
    AssessURLRequest,
    BrowserSandboxRequest,
    BrowserSandboxURLResponse,
    SandboxURLRequest,
    SandboxURLResponse,
    ScanPromptRequest,
)
from shared.trusted_popular_domains import trusted_popular_assessment

router = APIRouter(prefix="/v1/assess", tags=["assess"])
sandbox_runner = URLSandboxRunner()
browser_sandbox_runner = BrowserSandboxRunner()
exe_sandbox_runner = ExeSandboxRunner()
_URL_CACHE_VERSION = default_config().rules_version


def _context_ai_mode(
    requested: str,
    *,
    auto_enabled: bool,
    useful_context: bool,
    active_enabled: bool = False,
) -> str:
    if requested == "off":
        return "off"
    if requested == "on":
        return "active" if active_enabled else "shadow"
    if not (auto_enabled and useful_context):
        return "off"
    return "active" if active_enabled else "shadow"


def _message_analysis_depth(metadata: dict | None) -> str:
    depth = str((metadata or {}).get("analysis_depth", "balanced")).lower()
    if depth not in {"quick", "balanced", "deep", "pro"}:
        raise HTTPException(status_code=400, detail="Mức phân tích nội dung không hợp lệ")
    return depth


def _enforce_pro_depth(depth: str, plan) -> None:
    if depth == "pro" and plan.tier == "free":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Chế độ Pro AI yêu cầu gói Pro hoặc cao hơn.",
        )


def _refund_failed_evaluation(
    db: DbSession,
    actor,
    request: Request,
    result: AssessResponse | None,
    credits: int = 1,
) -> None:
    trace = result.contextual_analysis if result is not None else None
    if trace is None or trace.status != AdapterRunStatus.COMPLETED:
        refund_ai_credits(
            db, actor, request, credits, kind="evaluation"
        )


def _url_cache_key(url: str, context: str = "", cache_namespace: str = "") -> str:
    cache_material = url if not context else url + chr(10) + context
    if cache_namespace:
        cache_material += chr(10) + cache_namespace
    versioned_material = _URL_CACHE_VERSION + chr(10) + cache_material
    return f"url:{input_sha256(versioned_material)}"


def _cached_url_result(
    db: DbSession,
    url: str,
    context: str = "",
    cache_namespace: str = "",
    enabled: bool = True,
) -> AssessResponse | None:
    if not enabled:
        return None
    key = _url_cache_key(url, context, cache_namespace)
    cached = db.get(AssessmentCache, key)
    if cached is None or cached.expires_at <= utcnow():
        return None
    return AssessResponse.model_validate(cached.response).model_copy(
        update={
            "request_id": str(uuid.uuid4()),
            "latency_ms": 0.0,
            "cache_hit": True,
            "cache_status": "hit",
        }
    )


def _store_url_result(
    db: DbSession,
    url: str,
    result: AssessResponse,
    context: str = "",
    cache_namespace: str = "",
    enabled: bool = True,
) -> None:
    if not enabled:
        return
    key = _url_cache_key(url, context, cache_namespace)
    cached = db.get(AssessmentCache, key)
    if cached is None:
        cached = AssessmentCache(cache_key=key, modality="url", response={"risk_score": 0}, expires_at=utcnow())
        db.add(cached)
    cached.response = result.model_dump(mode="json")
    cached.expires_at = utcnow() + timedelta(seconds=max(1, settings.shared_assessment_cache_ttl_seconds))


@router.post("/url", response_model=AssessResponse)
def assess_url(
    req: AssessURLRequest,
    request: Request,
    credentials: BearerCredentials,
    db: DbSession = Depends(get_db),
    svc: InferenceService = Depends(get_inference_service),
):
    actor = resolve_actor(credentials, db, request)
    svc = get_user_inference_service(db, actor.user.id if actor.user else None)
    require_api_key_scope(actor, "assess:url")
    url = sanitize_text(req.url)
    context = sanitize_text(req.context or "")
    trusted_result = trusted_popular_assessment(url)
    if trusted_result is not None:
        log_assessment(
            db,
            result=trusted_result,
            actor=actor,
            request=request,
            raw_input=url,
            normalized_url=url,
        )
        return trusted_result
    plan = build_actor_plan_info(db, actor)
    cache_enabled = get_url_assessment_cache_enabled(
        db,
        default=settings.shared_assessment_cache_enabled,
    )
    context_mode = _context_ai_mode(
        req.ai_context,
        auto_enabled=plan.autoWebContext,
        useful_context=bool(context),
    )
    cache_namespace = f"{svc.adapter_cache_token}:{context_mode}:unified-risk-core"
    if actor.user is not None and context_mode != "off":
        # Contextual responses may depend on a personal provider/key. Never let
        # one account receive another account's cached AI-derived evidence.
        cache_namespace += f":account={actor.user.id}"
    result = _cached_url_result(
        db,
        url,
        context,
        cache_namespace,
        enabled=cache_enabled and not req.force_rescan,
    )
    if result is None:
        # Cache lookup is deliberately before quota reservation. Reusing an
        # equivalent saved quick result must not consume the caller's scan
        # allowance; an explicit force_rescan always consumes one instead.
        reserve_scan_quota(db, actor, request)
        reserved_ai = (
            context_mode != "off"
            and svc.context_ai_ready(AdapterTask.WEB_CONTEXT)
        )
        if reserved_ai:
            reserve_ai_credits(db, actor, request, kind="evaluation")
        try:
            result = svc.assess_url(
                url, context, context_ai_mode=context_mode
            )
        except Exception:
            if reserved_ai:
                refund_ai_credits(db, actor, request, kind="evaluation")
            raise
        if reserved_ai:
            _refund_failed_evaluation(db, actor, request, result)
        result = result.model_copy(
            update={
                "cache_hit": False,
                "cache_status": (
                    "refresh" if req.force_rescan else "miss" if cache_enabled else "bypassed"
                ),
            }
        )
        _store_url_result(
            db,
            url,
            result,
            context,
            cache_namespace,
            enabled=cache_enabled,
        )
    log_assessment(db, result=result, actor=actor, request=request, raw_input=url, normalized_url=url)
    return result


@router.post("/phone", response_model=AssessPhoneResponse)
def assess_phone(
    req: AssessPhoneRequest,
    request: Request,
    credentials: BearerCredentials,
    db: DbSession = Depends(get_db),
    svc: InferenceService = Depends(get_inference_service),
):
    actor = resolve_actor(credentials, db, request)
    svc = get_user_inference_service(db, actor.user.id if actor.user else None)
    require_api_key_scope(actor, "assess:content")
    plan = build_actor_plan_info(db, actor)
    depth = _message_analysis_depth(req.metadata)
    _enforce_pro_depth(depth, plan)
    reserve_scan_quota(db, actor, request)
    if depth in {"deep", "pro"}:
        reserve_deep_scan_quota(db, actor, request)
    context_mode = _context_ai_mode(
        req.ai_context,
        auto_enabled=plan.autoMessageContext,
        useful_context=bool(req.sms or req.transcript),
        active_enabled=depth == "pro" and plan.tier != "free",
    )
    evaluation_count = int(bool(req.sms)) + int(bool(req.transcript))
    reserved_message_credits = (
        evaluation_count
        if context_mode != "off"
        and svc.context_ai_ready(AdapterTask.MESSAGE_CONTEXT)
        else 0
    )
    reserved_phone_credits = (
        1 if svc.context_ai_ready(AdapterTask.PHONE_INTELLIGENCE) else 0
    )
    reserved_credits = reserved_message_credits + reserved_phone_credits
    if reserved_credits:
        reserve_ai_credits(
            db,
            actor,
            request,
            reserved_credits,
            kind="evaluation",
        )
    try:
        result = svc.assess_phone(
            sanitize_text(req.phone_number),
            country_hint=sanitize_text(req.country_hint),
            sms=sanitize_text(req.sms),
            transcript=sanitize_text(req.transcript),
            metadata=req.metadata,
            context_ai_mode=context_mode,
        )
    except Exception:
        if reserved_credits:
            refund_ai_credits(
                db,
                actor,
                request,
                reserved_credits,
                kind="evaluation",
            )
        raise
    if reserved_message_credits:
        _refund_failed_evaluation(
            db, actor, request, result.assessment, reserved_message_credits
        )
    if (
        reserved_phone_credits
        and result.phone_intelligence.status != AdapterRunStatus.COMPLETED
    ):
        refund_ai_credits(
            db, actor, request, reserved_phone_credits, kind="evaluation"
        )
    return result


@router.post("/url/sandbox", response_model=SandboxURLResponse)
async def sandbox_url(
    req: SandboxURLRequest,
    request: Request,
    credentials: BearerCredentials,
    db: DbSession = Depends(get_db),
    svc: InferenceService = Depends(get_inference_service),
):
    actor = resolve_actor(credentials, db, request)
    svc = get_user_inference_service(db, actor.user.id if actor.user else None)
    require_api_key_scope(actor, "assess:url")
    reserve_scan_quota(db, actor, request)
    reserve_deep_scan_quota(db, actor, request)
    url = sanitize_text(req.url)
    report = await asyncio.to_thread(sandbox_runner.inspect, url)
    report.risk_core = svc.assess_sandbox_report(url, report)
    return report


@router.post("/url/browser-sandbox", response_model=BrowserSandboxURLResponse)
async def browser_sandbox_url(
    req: BrowserSandboxRequest,
    request: Request,
    credentials: BearerCredentials,
    db: DbSession = Depends(get_db),
    svc: InferenceService = Depends(get_inference_service),
):
    actor = resolve_actor(credentials, db, request)
    svc = get_user_inference_service(db, actor.user.id if actor.user else None)
    require_api_key_scope(actor, "assess:url")
    reserve_scan_quota(db, actor, request)
    reserve_deep_scan_quota(db, actor, request)
    url = sanitize_text(req.url)
    report = await asyncio.to_thread(browser_sandbox_runner.inspect, url, req.canary_mode)
    report.risk_core = svc.assess_sandbox_report(url, report, browser=True)
    return report


@router.post("/text", response_model=AssessResponse)
def assess_text(
    req: AssessTextRequest,
    request: Request,
    credentials: BearerCredentials,
    db: DbSession = Depends(get_db),
    svc: InferenceService = Depends(get_inference_service),
):
    actor = resolve_actor(credentials, db, request)
    svc = get_user_inference_service(db, actor.user.id if actor.user else None)
    require_api_key_scope(actor, "assess:content")
    plan = build_actor_plan_info(db, actor)
    depth = _message_analysis_depth(req.metadata)
    _enforce_pro_depth(depth, plan)
    reserve_scan_quota(db, actor, request)
    if depth in {"deep", "pro"}:
        reserve_deep_scan_quota(db, actor, request)
    text = sanitize_text(req.text)
    context_mode = _context_ai_mode(
        req.ai_context,
        auto_enabled=plan.autoMessageContext,
        useful_context=req.modality in {"email", "sms", "chat", "call_transcript"},
        active_enabled=depth == "pro" and plan.tier != "free",
    )
    reserved_ai = (
        context_mode != "off"
        and svc.context_ai_ready(AdapterTask.MESSAGE_CONTEXT)
    )
    if reserved_ai:
        reserve_ai_credits(db, actor, request, kind="evaluation")
    try:
        result = svc.assess_text(
            text,
            req.modality,
            req.metadata,
            context_ai_mode=context_mode,
        )
    except Exception:
        if reserved_ai:
            refund_ai_credits(db, actor, request, kind="evaluation")
        raise
    if reserved_ai:
        _refund_failed_evaluation(db, actor, request, result)
    log_assessment(db, result=result, actor=actor, request=request, raw_input=text, metadata=req.metadata)
    return result


@router.post("/email-file", response_model=AssessResponse)
async def assess_email_file(
    file: UploadFile,
    request: Request,
    credentials: BearerCredentials,
    analysis_depth: str = Form(default="balanced"),
    operator_context: str = Form(default=""),
    ai_context: str = Form(default="auto"),
    db: DbSession = Depends(get_db),
    svc: InferenceService = Depends(get_inference_service),
):
    """Parse and assess an RFC822/MIME `.eml` upload with bounded inspection."""

    actor = resolve_actor(credentials, db, request)
    svc = get_user_inference_service(db, actor.user.id if actor.user else None)
    require_api_key_scope(actor, "assess:content")
    filename = file.filename or "message.eml"
    if not filename.lower().endswith((".eml", ".rfc822")):
        raise HTTPException(status_code=400, detail="Chỉ chấp nhận tệp Email .eml hoặc .rfc822")
    if analysis_depth not in {"quick", "balanced", "deep", "pro"}:
        raise HTTPException(status_code=400, detail="Mức phân tích Email không hợp lệ")
    if ai_context not in {"off", "auto", "on"}:
        raise HTTPException(status_code=400, detail="Chế độ AI Email không hợp lệ")
    operator_context = sanitize_text(operator_context.strip())
    if len(operator_context) > 2_000:
        raise HTTPException(status_code=400, detail="Ngữ cảnh Email vượt quá 2.000 ký tự")
    plan = build_actor_plan_info(db, actor)
    _enforce_pro_depth(analysis_depth, plan)
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Email file too large")
    reserve_scan_quota(db, actor, request)
    if analysis_depth in {"deep", "pro"}:
        reserve_deep_scan_quota(db, actor, request)
    context_mode = _context_ai_mode(
        ai_context,
        auto_enabled=plan.autoMessageContext,
        useful_context=True,
        active_enabled=analysis_depth == "pro" and plan.tier != "free",
    )
    reserved_ai = (
        context_mode != "off"
        and svc.context_ai_ready(AdapterTask.MESSAGE_CONTEXT)
    )
    if reserved_ai:
        reserve_ai_credits(db, actor, request, kind="evaluation")
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(
                svc.assess_email_bytes,
                data,
                filename,
                analysis_depth=analysis_depth,
                context_ai_mode=context_mode,
                operator_context=operator_context,
            ),
            timeout=max(10.0, min(float(settings.email_analysis_timeout_seconds), 180.0)),
        )
    except ValueError as exc:
        if reserved_ai:
            refund_ai_credits(db, actor, request, kind="evaluation")
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except TimeoutError as exc:
        if reserved_ai:
            refund_ai_credits(db, actor, request, kind="evaluation")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Phân tích Email vượt quá thời gian cho phép.",
        ) from exc
    except Exception:
        if reserved_ai:
            refund_ai_credits(db, actor, request, kind="evaluation")
        raise
    if reserved_ai:
        _refund_failed_evaluation(db, actor, request, result)
    log_assessment(
        db,
        result=result,
        actor=actor,
        request=request,
        raw_input=data,
        metadata={
            "filename": filename,
            "source": "eml_upload",
            "analysis_depth": analysis_depth,
            "operator_context_supplied": bool(operator_context),
        },
        retain_input_preview=False,
    )
    return result


@router.post("/prompt", response_model=AssessResponse)
def assess_prompt(
    req: ScanPromptRequest,
    request: Request,
    credentials: BearerCredentials,
    db: DbSession = Depends(get_db),
    svc: InferenceService = Depends(get_inference_service),
):
    actor = resolve_actor(credentials, db, request)
    svc = get_user_inference_service(db, actor.user.id if actor.user else None)
    require_api_key_scope(actor, "assess:prompt")
    reserve_scan_quota(db, actor, request)
    content = sanitize_text(req.content)
    result = svc.assess_prompt(content)
    log_assessment(db, result=result, actor=actor, request=request, raw_input=content)
    return result


@router.post("/action", response_model=AgentRiskResponse)
def assess_action(
    req: AssessActionRequest,
    request: Request,
    credentials: BearerCredentials,
    db: DbSession = Depends(get_db),
    svc: InferenceService = Depends(get_inference_service),
):
    actor = resolve_actor(credentials, db, request)
    svc = get_user_inference_service(db, actor.user.id if actor.user else None)
    require_api_key_scope(actor, "assess:action")
    reserve_scan_quota(db, actor, request)
    target = sanitize_text(req.target_url or req.target or "") or None
    result = svc.assess_action(req.action_type, target, req.data_types, req.agent_context)
    log_action_assessment(
        db,
        result=result,
        actor=actor,
        request=request,
        action_type=req.action_type,
        target=target,
    )
    return result


@router.post("/file/exe-quick-scan", response_model=dict)
async def quick_scan_executable(
    file: UploadFile,
    request: Request,
    credentials: BearerCredentials,
    share_with_provider: bool = Form(False),
    db: DbSession = Depends(get_db),
):
    actor = resolve_actor(credentials, db, request)
    require_api_key_scope(actor, "assess:file")
    reserve_scan_quota(db, actor, request)
    filename = file.filename or "sample.exe"
    if not filename.lower().endswith(".exe"):
        raise HTTPException(status_code=400, detail="Chỉ chấp nhận tệp .exe")
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="File too large")
    return await asyncio.to_thread(
        exe_quick_scan_service.inspect,
        data,
        filename,
        share_with_provider=share_with_provider,
    )


@router.get("/file/exe-quick-scan/provider/{data_id}", response_model=dict)
async def quick_scan_provider_report(
    data_id: str,
    request: Request,
    credentials: BearerCredentials,
    db: DbSession = Depends(get_db),
):
    actor = resolve_actor(credentials, db, request)
    require_api_key_scope(actor, "assess:file")
    return await asyncio.to_thread(exe_quick_scan_service.provider_report, data_id)

@router.post("/file/exe-sandbox", response_model=dict)
async def sandbox_executable(file: UploadFile, request: Request, credentials: BearerCredentials, db: DbSession = Depends(get_db)):
    actor = resolve_actor(credentials, db, request)
    require_api_key_scope(actor, "assess:file")
    reserve_scan_quota(db, actor, request)
    filename = file.filename or "sample.exe"
    if not filename.lower().endswith(".exe"):
        raise HTTPException(status_code=400, detail="Chỉ chấp nhận tệp .exe")
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="File too large")
    return await asyncio.to_thread(exe_sandbox_runner.inspect, data, filename)


@router.post("/file", response_model=AssessResponse)
async def assess_file(
    file: UploadFile,
    request: Request,
    credentials: BearerCredentials,
    db: DbSession = Depends(get_db),
    svc: InferenceService = Depends(get_inference_service),
):
    actor = resolve_actor(credentials, db, request)
    svc = get_user_inference_service(db, actor.user.id if actor.user else None)
    require_api_key_scope(actor, "assess:file")
    reserve_scan_quota(db, actor, request)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.max_upload_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="File too large",
                )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from None
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large")
    result = svc.assess_file(data, file.filename or "")
    log_assessment(
        db,
        result=result,
        actor=actor,
        request=request,
        raw_input=data,
        metadata={"filename": file.filename or ""},
    )
    return result
