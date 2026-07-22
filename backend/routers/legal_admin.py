"""Admin-only operational visibility for the local Legal RAG evidence engine."""

from __future__ import annotations

import math
from functools import lru_cache
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.middleware import sanitize_text
from backend.routers.auth import require_admin
from security.legal_rag import LegalReference, LocalLegalRAG

router = APIRouter(
    prefix="/admin/legal-rag",
    tags=["admin", "legal-rag"],
    dependencies=[Depends(require_admin)],
)


@lru_cache
def get_admin_legal_rag() -> LocalLegalRAG:
    return LocalLegalRAG()


class ManifestStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    present: bool
    verified: bool
    required: bool


class CorpusCounts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chunks: int
    searchable_chunks: int
    documents: int
    searchable_documents: int


class LegalRAGHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    available: bool
    ready: bool
    release_id: str
    schema_version: int
    verified_through: str
    sha256: str
    coverage_domains: list[str]
    manifest: ManifestStatus
    counts: CorpusCounts
    quick_check: str
    degraded_reasons: list[str]
    invalid_source_count: int
    missing_provenance_count: int


class DebugLegalContext(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    jurisdiction: str = Field(default="VN", max_length=64)
    as_of_date: str = Field(default="", max_length=10)
    actor: str = Field(default="", max_length=1_000)
    action: str = Field(default="", max_length=4_000)
    data_or_asset: str = Field(default="", max_length=4_000)
    recipient: str = Field(default="", max_length=2_000)
    purpose: str = Field(default="", max_length=2_000)
    consent_state: str = Field(default="", max_length=100)


class DebugRetrievalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    question: str = Field(min_length=1, max_length=20_000)
    context: DebugLegalContext = Field(default_factory=DebugLegalContext)
    top_k: int = Field(default=8, ge=1, le=12)
    preview_chars: int = Field(default=240, ge=0, le=500)

    @field_validator("question")
    @classmethod
    def question_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("question cannot be blank")
        return value


class DebugTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: str
    candidate_counts: dict[str, int] = Field(default_factory=dict)
    latency_ms: dict[str, float] = Field(default_factory=dict)
    degraded_reasons: list[str] = Field(default_factory=list)
    rejected_reasons: dict[str, int] = Field(default_factory=dict)
    plan: dict[str, Any] = Field(default_factory=dict)


class DebugReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chunk_id: str
    document_id: str
    title: str
    document_number: str
    document_type: str
    jurisdiction: str
    authority: str
    legal_weight: str
    status: str
    effective_date: str
    status_checked_at: str
    section: str
    page_start: int | None
    page_end: int | None
    source_page_url: str
    source_file_url: str
    source_pdf_sha256: str
    extraction_method: str
    text_verification_status: str
    corpus_release_id: str
    retrieval_score: float
    relevance_score: float
    retrieval_channels: list[str]
    is_primary: bool
    text_preview: str


class DebugRetrievalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    corpus: LegalRAGHealthResponse
    insufficient_reason: str
    trace: DebugTrace
    references: list[DebugReference]
    context_references: list[DebugReference]
    conflicts: list[dict[str, Any]]


def _bounded_text(value: object, limit: int) -> str:
    compact = " ".join(sanitize_text(str(value or "")).split())
    return compact[: max(0, limit)]


def _bounded_strings(value: object, *, count: int = 50, length: int = 120) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [_bounded_text(item, length) for item in value[:count] if str(item).strip()]


def _health_response(rag: LocalLegalRAG) -> LegalRAGHealthResponse:
    health = rag.health
    snapshot = health.snapshot
    reasons = [_bounded_text(reason, 120) for reason in health.reason_codes]
    required = bool(getattr(getattr(rag, "_retriever", None), "require_manifest", False))
    return LegalRAGHealthResponse(
        available=health.available,
        ready=health.ready,
        release_id=_bounded_text(snapshot.release_id, 200),
        schema_version=snapshot.schema_version,
        verified_through=_bounded_text(snapshot.verified_through, 10),
        sha256=_bounded_text(snapshot.sha256, 64),
        coverage_domains=_bounded_strings(snapshot.coverage_domains),
        manifest=ManifestStatus(
            present="manifest_missing" not in health.reason_codes,
            verified=snapshot.manifest_verified,
            required=required,
        ),
        counts=CorpusCounts(
            chunks=max(0, snapshot.chunk_count),
            searchable_chunks=max(0, snapshot.searchable_chunk_count),
            documents=max(0, snapshot.document_count),
            searchable_documents=max(0, snapshot.searchable_document_count),
        ),
        quick_check=_bounded_text(health.quick_check, 40),
        degraded_reasons=reasons,
        invalid_source_count=max(0, health.invalid_source_count),
        missing_provenance_count=max(0, health.missing_provenance_count),
    )


def _safe_number_map(value: object, *, floats: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, Any] = {}
    for key, raw in list(value.items())[:50]:
        name = _bounded_text(key, 80)
        if not name or isinstance(raw, bool):
            continue
        try:
            number = float(raw) if floats else int(raw)
        except (TypeError, ValueError, OverflowError):
            continue
        if floats:
            if math.isfinite(number):
                output[name] = round(max(0.0, number), 3)
        else:
            output[name] = max(0, number)
    return output


def _safe_trace(trace: object) -> DebugTrace:
    raw = trace.model_dump() if callable(getattr(trace, "model_dump", None)) else {}
    plan_raw = raw.get("plan", {}) if isinstance(raw, dict) else {}
    plan = plan_raw if isinstance(plan_raw, dict) else {}
    # Exclude original/normalized questions, dense query and generated FTS query
    # strings. The operational view needs routing decisions, not submitted prose.
    safe_plan = {
        "document_numbers": _bounded_strings(plan.get("document_numbers"), count=10, length=40),
        "article_numbers": _bounded_strings(plan.get("article_numbers"), count=20, length=20),
        "clause_numbers": _bounded_strings(plan.get("clause_numbers"), count=20, length=20),
        "concepts": _bounded_strings(plan.get("concepts"), count=30, length=80),
        "required_facets": _bounded_strings(plan.get("required_facets"), count=30, length=80),
        "out_of_scope_hint": bool(plan.get("out_of_scope_hint", False)),
    }
    return DebugTrace(
        mode=_bounded_text(raw.get("mode", ""), 120),
        candidate_counts=_safe_number_map(raw.get("candidate_counts")),
        latency_ms=_safe_number_map(raw.get("latency_ms"), floats=True),
        degraded_reasons=_bounded_strings(raw.get("degraded_reasons")),
        rejected_reasons=_safe_number_map(raw.get("rejected_reasons")),
        plan=safe_plan,
    )


def _debug_reference(reference: LegalReference, preview_chars: int) -> DebugReference:
    return DebugReference(
        chunk_id=_bounded_text(reference.chunk_id, 240),
        document_id=_bounded_text(reference.document_id, 240),
        title=_bounded_text(reference.title, 500),
        document_number=_bounded_text(reference.document_number, 100),
        document_type=_bounded_text(reference.document_type, 100),
        jurisdiction=_bounded_text(reference.jurisdiction, 64),
        authority=_bounded_text(reference.authority, 300),
        legal_weight=_bounded_text(reference.legal_weight, 100),
        status=_bounded_text(reference.status, 100),
        effective_date=_bounded_text(reference.effective_date, 10),
        status_checked_at=_bounded_text(reference.status_checked_at, 10),
        section=_bounded_text(reference.section, 500),
        page_start=reference.page_start,
        page_end=reference.page_end,
        source_page_url=_bounded_text(reference.source_page_url, 2_048),
        source_file_url=_bounded_text(reference.source_file_url, 2_048),
        source_pdf_sha256=_bounded_text(reference.source_pdf_sha256, 64),
        extraction_method=_bounded_text(reference.extraction_method, 100),
        text_verification_status=_bounded_text(reference.text_verification_status, 100),
        corpus_release_id=_bounded_text(reference.corpus_release_id, 200),
        retrieval_score=round(float(reference.retrieval_score), 8),
        relevance_score=round(float(reference.relevance_score), 8),
        retrieval_channels=_bounded_strings(reference.retrieval_channels, count=10, length=40),
        is_primary=bool(reference.is_primary),
        text_preview=_bounded_text(reference.text_preview, preview_chars),
    )


def _safe_conflicts(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    allowed = {
        "type",
        "left_chunk_id",
        "left_document_id",
        "left_polarity",
        "right_chunk_id",
        "right_document_id",
        "right_polarity",
        "token_overlap",
        "requires_human_review",
    }
    output: list[dict[str, Any]] = []
    for item in value[:10]:
        if not isinstance(item, dict):
            continue
        safe: dict[str, Any] = {}
        for key in allowed:
            if key not in item:
                continue
            raw = item[key]
            if key == "token_overlap":
                try:
                    number = float(raw)
                except (TypeError, ValueError, OverflowError):
                    continue
                if math.isfinite(number):
                    safe[key] = round(max(0.0, min(1.0, number)), 4)
            elif key == "requires_human_review":
                safe[key] = bool(raw)
            else:
                safe[key] = _bounded_text(raw, 240)
        output.append(safe)
    return output


@router.get("/health", response_model=LegalRAGHealthResponse)
def legal_rag_health(rag: LocalLegalRAG = Depends(get_admin_legal_rag)) -> LegalRAGHealthResponse:
    return _health_response(rag)


@router.post("/debug-retrieval", response_model=DebugRetrievalResponse)
def debug_legal_retrieval(
    payload: DebugRetrievalRequest,
    rag: LocalLegalRAG = Depends(get_admin_legal_rag),
) -> DebugRetrievalResponse:
    context = {
        key: sanitize_text(str(value)) for key, value in payload.context.model_dump().items()
    }
    result = rag.retrieve(
        sanitize_text(payload.question),
        context=context,
        top_k=payload.top_k,
    )
    return DebugRetrievalResponse(
        corpus=_health_response(rag),
        insufficient_reason=_bounded_text(result.insufficient_reason, 120),
        trace=_safe_trace(result.trace),
        references=[
            _debug_reference(reference, payload.preview_chars)
            for reference in result.references[: payload.top_k]
        ],
        context_references=[
            _debug_reference(reference, payload.preview_chars)
            for reference in result.context_references[:18]
        ],
        conflicts=_safe_conflicts(result.conflicts),
    )


__all__ = [
    "DebugRetrievalRequest",
    "DebugRetrievalResponse",
    "LegalRAGHealthResponse",
    "get_admin_legal_rag",
    "router",
]
