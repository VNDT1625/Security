"""Read-only local legal/policy RAG for action-compliance context.

The retriever is deliberately independent from the technical risk score. It only
queries a provenance-first SQLite FTS index built from official publications. A
retrieved passage is supporting context, not proof that an action is lawful.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Literal

from security.legal.corpus import CorpusHealth, CorpusSnapshot
from security.legal.query_planner import context_mapping
from security.legal.retrieval import HybridLegalRetriever, RetrievalTrace, RetrievedChunk
from shared.constants import SENSITIVE_DATA_TYPES

_EXTERNAL_TRANSFER_ACTIONS = frozenset(
    {"submit_form", "send_email", "copy_data", "call_api", "upload_file", "payment_or_transfer"}
)
_LEGAL_SENSITIVE_TYPES = frozenset(
    {
        *SENSITIVE_DATA_TYPES,
        "personal_data",
        "personal_information",
        "identity_document",
        "national_id",
        "passport",
        "biometric_data",
        "health_data",
        "location_data",
        "children_data",
        "child_data",
        "financial_data",
        "state_secret",
        "trade_secret",
        "source_code",
        "private_document",
        "confidential_document",
        "email",
        "cookie",
    }
)
_ACTION_QUERY_HINTS = {
    "submit_form": "cung cấp dữ liệu cá nhân biểu mẫu đồng ý mục đích xử lý dữ liệu",
    "send_email": "chia sẻ chuyển giao dữ liệu cá nhân bí mật thông tin qua thư điện tử",
    "copy_data": "sao chép chuyển giao dữ liệu cá nhân bí mật thông tin",
    "call_api": "truyền dữ liệu cá nhân cho bên thứ ba qua hệ thống thông tin API",
    "upload_file": "tải lên chuyển giao tệp dữ liệu cá nhân bí mật thông tin cho bên thứ ba",
    "payment_or_transfer": "thanh toán chuyển tiền dữ liệu tài chính xác thực giao dịch",
}


@dataclass(frozen=True)
class LegalReference:
    chunk_id: str
    document_id: str
    title: str
    document_number: str
    legal_weight: str
    status: str
    effective_date: str
    section: str
    page_start: int | None
    page_end: int | None
    source_page_url: str
    source_pdf_sha256: str
    extraction_method: str
    text_preview: str
    retrieval_score: float
    jurisdiction: str = ""
    status_checked_at: str = ""
    document_type: str = ""
    authority: str = ""
    source_file_url: str = ""
    topics: str = ""
    full_text: str = ""
    relevance_score: float = 0.0
    retrieval_channels: tuple[str, ...] = ()
    is_primary: bool = True
    text_verification_status: str = ""
    corpus_release_id: str = ""

    def model_dump(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "document_id": self.document_id,
            "title": self.title,
            "document_number": self.document_number,
            "legal_weight": self.legal_weight,
            "status": self.status,
            "effective_date": self.effective_date,
            "section": self.section,
            "page_start": self.page_start,
            "page_end": self.page_end,
            "source_page_url": self.source_page_url,
            "source_pdf_sha256": self.source_pdf_sha256,
            "extraction_method": self.extraction_method,
            "text_preview": self.text_preview,
            "retrieval_score": self.retrieval_score,
            "jurisdiction": self.jurisdiction,
            "status_checked_at": self.status_checked_at,
            "document_type": self.document_type,
            "authority": self.authority,
            "source_file_url": self.source_file_url,
            "topics": self.topics,
            "full_text": self.full_text,
            "relevance_score": self.relevance_score,
            "retrieval_channels": list(self.retrieval_channels),
            "is_primary": self.is_primary,
            "text_verification_status": self.text_verification_status,
            "corpus_release_id": self.corpus_release_id,
        }


@dataclass(frozen=True)
class LegalRetrievalResult:
    references: tuple[LegalReference, ...]
    context_references: tuple[LegalReference, ...]
    snapshot: CorpusSnapshot
    trace: RetrievalTrace
    conflicts: tuple[dict[str, Any], ...] = ()
    insufficient_reason: str = ""


@dataclass(frozen=True)
class LegalRAGAssessment:
    status: Literal["completed", "unavailable", "not_applicable"]
    requires_review: bool = False
    reason: str = ""
    references: tuple[LegalReference, ...] = field(default_factory=tuple)
    evidence_status: Literal[
        "not_applicable",
        "reference_found",
        "review_required",
        "insufficient_basis",
        "conflict_detected",
    ] = "not_applicable"

    @classmethod
    def unavailable(cls, reason: str) -> LegalRAGAssessment:
        return cls(
            status="unavailable",
            requires_review=True,
            reason=reason,
            evidence_status="insufficient_basis",
        )


class LocalLegalRAG:
    """Compatibility facade over the bounded hybrid legal retriever."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        top_k: int = 4,
        verification_overlay_path: str | Path | None = None,
        verification_signing_key_file: str | Path | None = None,
        verification_key_id: str | None = None,
        require_verification_overlay: bool | None = None,
    ) -> None:
        configured = db_path or os.getenv("PREWISE_LEGAL_RAG_DB", "")
        default_path = Path(__file__).resolve().parents[1] / "data" / "legal_rag" / "rag.sqlite3"
        self.db_path = Path(configured).expanduser() if configured else default_path
        self.top_k = max(1, min(20, int(top_k)))
        require_manifest = os.getenv("PREWISE_LEGAL_RAG_REQUIRE_MANIFEST", "").strip().casefold()
        require_overlay_env = (
            os.getenv("PREWISE_LEGAL_RAG_REQUIRE_VERIFICATION_OVERLAY", "").strip().casefold()
        )
        configured_overlay = verification_overlay_path or os.getenv(
            "PREWISE_LEGAL_RAG_VERIFICATION_OVERLAY", ""
        )
        configured_key_file = verification_signing_key_file or os.getenv(
            "PREWISE_LEGAL_RAG_VERIFICATION_KEY_FILE", ""
        )
        configured_key_id = verification_key_id or os.getenv(
            "PREWISE_LEGAL_RAG_VERIFICATION_KEY_ID", ""
        )
        self._retriever = HybridLegalRetriever(
            self.db_path,
            candidate_k=int(os.getenv("PREWISE_LEGAL_RAG_CANDIDATE_K", "50")),
            require_manifest=require_manifest in {"1", "true", "yes", "on"},
            verification_overlay_path=configured_overlay or None,
            verification_signing_key_file=configured_key_file or None,
            verification_key_id=configured_key_id or None,
            require_verification_overlay=(
                require_overlay_env in {"1", "true", "yes", "on"}
                if require_verification_overlay is None
                else require_verification_overlay
            ),
        )

    @property
    def available(self) -> bool:
        return self.db_path.is_file()

    @property
    def health(self) -> CorpusHealth:
        return self._retriever.health

    def refresh_health(self) -> CorpusHealth:
        return self._retriever.refresh_health()

    @staticmethod
    def _reference(chunk: RetrievedChunk, *, release_id: str) -> LegalReference:
        compact = " ".join(chunk.text.split())
        return LegalReference(
            chunk_id=chunk.chunk_id,
            document_id=chunk.document_id,
            title=chunk.title,
            document_number=chunk.document_number,
            legal_weight=chunk.legal_weight,
            status=chunk.status,
            effective_date=chunk.effective_date,
            section=chunk.section,
            page_start=chunk.page_start,
            page_end=chunk.page_end,
            source_page_url=chunk.source_page_url,
            source_pdf_sha256=chunk.source_pdf_sha256,
            extraction_method=chunk.extraction_method,
            text_preview=compact[:900],
            retrieval_score=chunk.retrieval_score,
            jurisdiction=chunk.jurisdiction,
            status_checked_at=chunk.status_checked_at,
            document_type=chunk.document_type,
            authority=chunk.authority,
            source_file_url=chunk.source_file_url,
            topics=chunk.topics,
            full_text=chunk.text,
            relevance_score=chunk.relevance_score,
            retrieval_channels=chunk.channels,
            is_primary=chunk.is_primary,
            text_verification_status=chunk.text_verification_status,
            corpus_release_id=release_id,
        )

    def retrieve(
        self,
        question: str,
        *,
        context: Any | None = None,
        top_k: int | None = None,
    ) -> LegalRetrievalResult:
        result = self._retriever.retrieve(
            question,
            context=context_mapping(context),
            top_k=max(1, min(20, int(top_k or self.top_k))),
        )
        release_id = result.snapshot.release_id
        return LegalRetrievalResult(
            references=tuple(
                self._reference(chunk, release_id=release_id) for chunk in result.references
            ),
            context_references=tuple(
                self._reference(chunk, release_id=release_id) for chunk in result.context_references
            ),
            snapshot=result.snapshot,
            trace=result.trace,
            conflicts=result.conflicts,
            insufficient_reason=result.insufficient_reason,
        )

    def query(self, question: str, *, top_k: int | None = None) -> tuple[LegalReference, ...]:
        return self.retrieve(question, top_k=top_k).references

    def legacy_query(
        self, question: str, *, top_k: int | None = None
    ) -> tuple[LegalReference, ...]:
        chunks = self._retriever.legacy_search(
            question, top_k=max(1, min(8, int(top_k or self.top_k)))
        )
        release_id = self.health.snapshot.release_id
        return tuple(self._reference(chunk, release_id=release_id) for chunk in chunks)

    @staticmethod
    def _normalized_data_types(
        data_types: list[str], available_assets: list[str]
    ) -> frozenset[str]:
        values = {
            str(item).strip().lower().replace("-", "_").replace(" ", "_")
            for item in [*data_types, *available_assets]
            if str(item).strip()
        }
        return frozenset(values)

    def assess_action(
        self,
        action_type: str,
        data_types: list[str],
        *,
        available_assets: list[str] | None = None,
        user_intent: str = "",
        planned_action: str = "",
    ) -> LegalRAGAssessment:
        normalized = self._normalized_data_types(data_types, available_assets or [])
        sensitive = sorted(normalized.intersection(_LEGAL_SENSITIVE_TYPES))
        if action_type not in _EXTERNAL_TRANSFER_ACTIONS or not sensitive:
            return LegalRAGAssessment(status="not_applicable", evidence_status="not_applicable")
        if not self.available:
            return LegalRAGAssessment.unavailable(
                "Không có chỉ mục pháp lý cục bộ; không được suy đoán rằng hành động tuân thủ."
            )

        query = " ".join(
            part
            for part in (
                _ACTION_QUERY_HINTS.get(action_type, action_type),
                " ".join(sensitive),
                user_intent[:500],
                planned_action[:500],
            )
            if part
        )
        try:
            retrieval = self.retrieve(
                query,
                context={
                    "jurisdiction": "VN",
                    "as_of_date": date.today().isoformat(),
                    "actor": "agent",
                    "action": planned_action or action_type,
                    "data_or_asset": ", ".join(sensitive),
                },
            )
            references = retrieval.references
        except (OSError, sqlite3.Error) as exc:
            return LegalRAGAssessment.unavailable(
                f"Không đọc được chỉ mục pháp lý cục bộ ({type(exc).__name__})."
            )

        reason = (
            "Hành động có thể chuyển dữ liệu nhạy cảm ra ngoài ranh giới tin cậy; "
            "cần người dùng xác nhận mục đích, phạm vi, bên nhận và căn cứ xử lý."
        )
        if not references:
            reason += " Không tìm thấy căn cứ đủ gần, vì vậy phải chuyển sang rà soát thủ công."
        return LegalRAGAssessment(
            status="completed" if references else "unavailable",
            requires_review=True,
            reason=reason,
            references=references,
            evidence_status=(
                "conflict_detected"
                if retrieval.conflicts
                else "review_required"
                if references
                else "insufficient_basis"
            ),
        )
