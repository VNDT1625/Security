"""Fail-closed HTTP transport for the Legal RAG v2 answer service."""

from __future__ import annotations

import inspect
import json
import uuid
from collections.abc import Callable, Mapping
from datetime import date, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session as DbSession

from backend.db import get_db
from backend.dependencies import get_user_legal_answer_service
from backend.middleware import sanitize_text
from backend.models import AssessmentCache
from backend.routers.auth import BearerCredentials, require_api_key_scope, resolve_actor
from backend.security_utils import input_sha256, utcnow
from backend.services.legal_answer_service import LegalQuestionContext
from backend.services.quota_service import (
    refund_ai_credits,
    reserve_ai_credits,
    reserve_scan_quota,
)

router = APIRouter(prefix="/v1/legal", tags=["legal"])

_STATUS = {
    "answered",
    "need_more_facts",
    "insufficient_legal_basis",
    "conflicting_sources",
    "human_legal_review",
}
_IDEMPOTENCY_TTL = timedelta(hours=24)
_IDEMPOTENCY_PENDING = "pending"
_IDEMPOTENCY_COMPLETED = "completed"
_DISCLAIMER = (
    "Đây là phân tích hỗ trợ bằng AI, không phải ý kiến của cơ quan có thẩm quyền. "
    "Hãy đối chiếu văn bản gốc và tham vấn chuyên gia pháp lý cho quyết định quan trọng."
)


class LegalContextInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    jurisdiction: str = Field(default="", max_length=64)
    as_of_date: str = Field(default="", max_length=10)
    actor: str = Field(default="", max_length=1_000)
    action: str = Field(default="", max_length=4_000)
    data_or_asset: str = Field(default="", max_length=4_000)
    recipient: str = Field(default="", max_length=2_000)
    purpose: str = Field(default="", max_length=2_000)
    consent_state: str = Field(default="", max_length=100)

    @field_validator("as_of_date")
    @classmethod
    def valid_iso_date(cls, value: str) -> str:
        if not value:
            return value
        try:
            return date.fromisoformat(value).isoformat()
        except ValueError as exc:
            raise ValueError("as_of_date must be a valid ISO date") from exc


class LegalAnswerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    schema_version: Literal["legal-answer.v2"]
    request_id: str = Field(min_length=36, max_length=36)
    idempotency_key: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    intent_mode: Literal["auto", "legal"]
    question: str = Field(min_length=1, max_length=20_000)
    legal_context: LegalContextInput | None = None

    @field_validator("request_id")
    @classmethod
    def valid_request_uuid(cls, value: str) -> str:
        try:
            parsed = uuid.UUID(value)
        except ValueError as exc:
            raise ValueError("request_id must be a UUID") from exc
        if str(parsed) != value.lower():
            raise ValueError("request_id must use canonical UUID format")
        return str(parsed)


class CorpusMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    release_id: str = ""
    verified_through: str = ""
    coverage_domains: list[str] = Field(default_factory=list)


class LegalAnswerResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["legal-answer.v2"] = "legal-answer.v2"
    request_id: str
    status: Literal[
        "answered",
        "need_more_facts",
        "insufficient_legal_basis",
        "conflicting_sources",
        "human_legal_review",
    ]
    reason_code: str
    jurisdiction: str = ""
    as_of_date: str = ""
    answer: str = ""
    corpus: CorpusMetadata = Field(default_factory=CorpusMetadata)
    trace_id: str
    claims: list[dict[str, Any]] = Field(default_factory=list)
    citations: list[dict[str, Any]] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    requires_human_review: bool = False
    disclaimer: str = _DISCLAIMER


def _safe_answer(answer_status: str, missing_facts: list[str]) -> str:
    if answer_status == "need_more_facts":
        detail = ", ".join(missing_facts) if missing_facts else "bối cảnh pháp lý cần thiết"
        return f"Chưa thể kết luận. Vui lòng bổ sung: {detail}."
    if answer_status == "conflicting_sources":
        return (
            "Các nguồn có dấu hiệu xung đột; cần chuyên gia pháp lý đối chiếu trước khi kết luận."
        )
    if answer_status == "human_legal_review":
        return "Bằng chứng hiện có cần được chuyên gia pháp lý hoặc người kiểm duyệt xác minh."
    return "Chưa có đủ căn cứ pháp lý đã kiểm chứng để đưa ra kết luận."


def _context_model(raw: LegalContextInput | None) -> LegalQuestionContext:
    values = raw.model_dump() if raw is not None else LegalContextInput().model_dump()
    clean = {key: sanitize_text(str(value)) for key, value in values.items()}
    # v1 currently has five fields; v2 adds recipient/purpose/consent_state.  Filter
    # only for backwards compatibility while the service contract is being rolled out.
    accepted = inspect.signature(LegalQuestionContext).parameters
    return LegalQuestionContext(**{key: value for key, value in clean.items() if key in accepted})


async def _service_answer(
    service: object,
    question: str,
    context: LegalQuestionContext,
    *,
    intent_mode: Literal["auto", "legal"],
    before_generate: Callable[[], object] | None = None,
) -> object:
    method = service.answer  # type: ignore[attr-defined]
    parameters = inspect.signature(method).parameters
    kwargs: dict[str, Any] = {}
    if "intent_mode" in parameters:
        kwargs["intent_mode"] = intent_mode
    elif "mode" in parameters:
        kwargs["mode"] = intent_mode
    if "before_generate" in parameters and before_generate is not None:
        kwargs["before_generate"] = before_generate
    result = method(question, context, **kwargs)
    return await result if inspect.isawaitable(result) else result


def _result_payload(result: object) -> dict[str, Any]:
    if isinstance(result, Mapping):
        return dict(result)
    dump = getattr(result, "model_dump", None)
    if not callable(dump):
        return {}
    try:
        payload = dump(mode="json")
    except TypeError:
        payload = dump()
    return dict(payload) if isinstance(payload, Mapping) else {}


def _string_list(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [sanitize_text(str(item))[:1_000] for item in value if isinstance(item, str)]


def _dict_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _reason_code(raw: Mapping[str, Any], answer_status: str) -> str:
    provided = str(raw.get("reason_code", "")).strip()
    if provided:
        return sanitize_text(provided)[:100]
    return {
        "answered": "verified",
        "need_more_facts": "missing_facts",
        "conflicting_sources": "conflict",
        "human_legal_review": "unverified_ocr",
    }.get(answer_status, "unsupported_claim")


def _response(
    request_payload: LegalAnswerRequest,
    result: object,
    *,
    fallback_reason: str = "",
) -> LegalAnswerResponse:
    raw = _result_payload(result)
    answer_status = str(raw.get("status", "insufficient_legal_basis"))
    if answer_status not in _STATUS:
        answer_status = "insufficient_legal_basis"
        fallback_reason = "unsupported_claim"
    raw_reason = str(raw.get("reason_code", ""))
    if raw_reason == "unsupported_jurisdiction":
        # Missing jurisdiction is a fact question; an explicitly unsupported one
        # is outside corpus scope and cannot be repaired by guessing another country.
        answer_status = "insufficient_legal_basis"

    context = request_payload.legal_context or LegalContextInput()
    missing = _string_list(raw.get("missing_facts"))
    claims = _dict_list(raw.get("claims", raw.get("legal_conclusions")))
    citations = _dict_list(raw.get("citations"))
    uncertainties = _string_list(raw.get("uncertainties"))
    requires_review = bool(raw.get("requires_human_review", False)) or answer_status in {
        "conflicting_sources",
        "human_legal_review",
    }
    if answer_status == "answered" and requires_review:
        answer_status = "human_legal_review"
        fallback_reason = "unverified_ocr"
    if answer_status != "answered":
        # Never expose unverified model prose or candidate sources on a safe branch.
        answer = _safe_answer(answer_status, missing)
        claims = []
        citations = []
    else:
        answer = sanitize_text(str(raw.get("answer", "")))
        if not answer:
            answer = "\n\n".join(
                sanitize_text(str(claim.get("text", claim.get("claim", "")))) for claim in claims
            ).strip()
        if not answer or not claims or not citations:
            answer_status = "insufficient_legal_basis"
            fallback_reason = "unsupported_claim"
            answer = _safe_answer(answer_status, missing)
            claims = []
            citations = []

    corpus_raw = raw.get("corpus")
    corpus_map = corpus_raw if isinstance(corpus_raw, Mapping) else {}
    corpus = CorpusMetadata(
        release_id=str(corpus_map.get("release_id", raw.get("corpus_release_id", ""))),
        verified_through=str(corpus_map.get("verified_through", raw.get("verified_through", ""))),
        coverage_domains=_string_list(
            raw.get("corpus_coverage_domains", corpus_map.get("coverage_domains", []))
        ),
    )
    return LegalAnswerResponse(
        request_id=request_payload.request_id,
        status=answer_status,  # type: ignore[arg-type]
        reason_code=fallback_reason or _reason_code(raw, answer_status),
        jurisdiction=sanitize_text(str(raw.get("jurisdiction", context.jurisdiction))),
        as_of_date=sanitize_text(str(raw.get("as_of_date", context.as_of_date))),
        answer=answer,
        corpus=corpus,
        trace_id=sanitize_text(str(raw.get("trace_id", ""))) or str(uuid.uuid4()),
        claims=claims,
        citations=citations,
        missing_facts=missing,
        uncertainties=uncertainties,
        requires_human_review=requires_review,
        disclaimer=sanitize_text(str(raw.get("disclaimer", _DISCLAIMER))) or _DISCLAIMER,
    )


def _identity(actor: object) -> str:
    user = getattr(actor, "user", None)
    if user is not None:
        return f"user:{getattr(user, 'id', '')}"
    return f"anonymous:{getattr(actor, 'anonymous_id', '')}"


def _cache_key(actor: object, idempotency_key: str) -> str:
    return "legal:" + input_sha256(f"{_identity(actor)}\n{idempotency_key}")


def _fingerprint(payload: LegalAnswerRequest) -> str:
    canonical = json.dumps(payload.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)
    return input_sha256(canonical)


def _idempotency_conflict() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Idempotency key was already used for a different legal request.",
    )


def _pending_conflict() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="A request with this idempotency key is already in progress.",
        headers={"Retry-After": "2"},
    )


def _storage_failure() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Không thể bảo đảm idempotency cho yêu cầu pháp lý.",
    )


def _pending_envelope(fingerprint: str) -> dict[str, Any]:
    return {
        "fingerprint": fingerprint,
        "state": _IDEMPOTENCY_PENDING,
        "claimed_at": utcnow().isoformat(),
    }


def _read_claimed_row(
    row: AssessmentCache,
    fingerprint: str,
) -> LegalAnswerResponse:
    envelope = row.response if isinstance(row.response, dict) else {}
    if envelope.get("fingerprint") != fingerprint:
        raise _idempotency_conflict()
    state = str(envelope.get("state", ""))
    if state == _IDEMPOTENCY_PENDING:
        raise _pending_conflict()
    if state not in {"", _IDEMPOTENCY_COMPLETED}:
        raise _storage_failure()
    try:
        return LegalAnswerResponse.model_validate(envelope.get("payload", {}))
    except Exception as exc:
        raise _storage_failure() from exc


def _claim_idempotency(
    db: DbSession,
    key: str,
    fingerprint: str,
) -> LegalAnswerResponse | None:
    now = utcnow()
    try:
        row = db.get(AssessmentCache, key)
        if row is not None and row.expires_at > now:
            return _read_claimed_row(row, fingerprint)
        if row is not None:
            claimed = db.execute(
                update(AssessmentCache)
                .where(
                    AssessmentCache.cache_key == key,
                    AssessmentCache.expires_at <= now,
                )
                .values(
                    modality="legal",
                    response=_pending_envelope(fingerprint),
                    expires_at=now + _IDEMPOTENCY_TTL,
                )
            )
            db.commit()
            if claimed.rowcount == 1:
                return None
            db.expire_all()
            current = db.get(AssessmentCache, key)
            if current is None:
                raise _storage_failure()
            return _read_claimed_row(current, fingerprint)

        db.add(
            AssessmentCache(
                cache_key=key,
                modality="legal",
                response=_pending_envelope(fingerprint),
                expires_at=now + _IDEMPOTENCY_TTL,
            )
        )
        try:
            db.commit()
            return None
        except IntegrityError:
            db.rollback()
            current = db.get(AssessmentCache, key)
            if current is None or current.expires_at <= utcnow():
                raise _storage_failure() from None
            return _read_claimed_row(current, fingerprint)
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        db.rollback()
        raise _storage_failure() from exc


def _store_response(
    db: DbSession,
    key: str,
    fingerprint: str,
    response: LegalAnswerResponse,
) -> None:
    try:
        row = db.get(AssessmentCache, key)
        if row is None:
            raise _storage_failure()
        current = row.response if isinstance(row.response, dict) else {}
        if (
            current.get("fingerprint") != fingerprint
            or current.get("state") != _IDEMPOTENCY_PENDING
        ):
            raise _storage_failure()
        row.modality = "legal"
        row.response = {
            "fingerprint": fingerprint,
            "state": _IDEMPOTENCY_COMPLETED,
            "payload": response.model_dump(mode="json"),
        }
        row.expires_at = utcnow() + _IDEMPOTENCY_TTL
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except SQLAlchemyError as exc:
        db.rollback()
        raise _storage_failure() from exc


@router.post("/answers", response_model=LegalAnswerResponse)
async def answer_legal_question(
    payload: LegalAnswerRequest,
    request: Request,
    credentials: BearerCredentials,
    db: DbSession = Depends(get_db),
) -> LegalAnswerResponse:
    actor = resolve_actor(credentials, db, request)
    require_api_key_scope(actor, "assess:content")
    key = _cache_key(actor, payload.idempotency_key)
    fingerprint = _fingerprint(payload)
    cached = _claim_idempotency(db, key, fingerprint)
    if cached is not None:
        return cached

    reserve_scan_quota(db, actor, request)
    service = get_user_legal_answer_service(db, actor.user.id if actor.user is not None else None)
    # Supplying legal_context always forces the legal path, even when the client
    # selected auto.  There is intentionally no client-controlled normal bypass.
    effective_mode: Literal["auto", "legal"] = (
        "legal" if payload.intent_mode == "legal" or payload.legal_context is not None else "auto"
    )
    ai_reserved = False
    ai_refunded = False
    generation_succeeded = False
    reservation_error: HTTPException | None = None

    def reserve_generation_credit() -> None:
        nonlocal ai_reserved, reservation_error
        if ai_reserved:
            return
        try:
            reserve_ai_credits(db, actor, request, kind="explanation")
        except HTTPException as exc:
            reservation_error = exc
            raise
        ai_reserved = True

    def refund_generation_credit_once() -> None:
        nonlocal ai_refunded
        if not ai_reserved or ai_refunded:
            return
        # Set before the database call so even a refund failure cannot double-debit
        # on the outer fail-closed exception path.
        ai_refunded = True
        refund_ai_credits(db, actor, request, kind="explanation")

    try:
        result = await _service_answer(
            service,
            sanitize_text(payload.question),
            _context_model(payload.legal_context),
            intent_mode=effective_mode,
            before_generate=reserve_generation_credit,
        )
        if reservation_error is not None:
            raise reservation_error
        result_metadata = _result_payload(result)
        generation_attempted = result_metadata.get("generation_attempted") is True
        generation_succeeded = result_metadata.get("generation_succeeded") is True
        if generation_attempted and not generation_succeeded:
            refund_generation_credit_once()
        response = _response(
            payload,
            result,
            fallback_reason="not_legal_intent" if result is None else "",
        )
    except HTTPException:
        raise
    except Exception:
        if not generation_succeeded:
            try:
                refund_generation_credit_once()
            except Exception:
                # Quota refund errors cannot authorize or expose a model answer.
                pass
        # Provider, retrieval, schema, and integration failures are data, not 5xx
        # permission to expose an unverified legal answer.
        response = _response(payload, {}, fallback_reason="internal_failure")
    _store_response(db, key, fingerprint, response)
    return response


__all__ = [
    "LegalAnswerRequest",
    "LegalAnswerResponse",
    "LegalContextInput",
    "answer_legal_question",
    "router",
]
