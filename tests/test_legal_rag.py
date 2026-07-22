from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from backend.services.inference_service import InferenceService
from scripts.export_legal_ocr_review_queue import export_queue
from scripts.import_legal_ocr_review import import_reviews
from security.legal.query_planner import LegalQueryPlanner
from security.legal.retrieval import HybridLegalRetriever
from security.legal_rag import LocalLegalRAG
from shared.schemas import AgentContext, Decision, LegalEvidenceStatus


def _build_test_db(path: Path, *, extraction_method: str = "native_pdf_text") -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE chunks (
          chunk_id TEXT PRIMARY KEY,
          document_id TEXT NOT NULL,
          title TEXT NOT NULL,
          document_number TEXT,
          document_type TEXT,
          jurisdiction TEXT,
          authority TEXT,
          legal_weight TEXT,
          status TEXT,
          effective_date TEXT,
          status_checked_at TEXT,
          retrieval_default INTEGER NOT NULL,
          language TEXT,
          topics TEXT,
          section TEXT,
          page_start INTEGER,
          page_end INTEGER,
          source_page_url TEXT,
          source_file_url TEXT,
          source_pdf_sha256 TEXT,
          extraction_method TEXT,
          text TEXT NOT NULL
        );
        CREATE VIRTUAL TABLE chunks_fts USING fts5(
          chunk_id UNINDEXED, title, document_number, topics, section, text,
          tokenize='unicode61 remove_diacritics 2'
        );
        """
    )
    values = (
        "vn_personal_data::c00001",
        "vn_personal_data",
        "Luật Bảo vệ dữ liệu cá nhân",
        "91/2025/QH15",
        "law",
        "VN",
        "Quốc hội",
        "binding",
        "current",
        "2026-01-01",
        "2026-07-22",
        1,
        "vi",
        '["personal_data"]',
        "Điều 20. Chuyển giao dữ liệu",
        12,
        12,
        "https://vanban.chinhphu.vn/",
        "https://datafiles.chinhphu.vn/example.pdf",
        "a" * 64,
        extraction_method,
        "Việc chuyển giao dữ liệu cá nhân cho bên thứ ba phải có mục đích và biện pháp bảo vệ phù hợp.",
    )
    connection.execute(
        "INSERT INTO chunks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values
    )
    connection.execute(
        "INSERT INTO chunks_fts VALUES (?,?,?,?,?,?)",
        (values[0], values[2], values[3], values[13], values[14], values[21]),
    )
    connection.commit()
    connection.close()


def _publish_overlay(
    db_path: Path,
    directory: Path,
    *,
    status: str,
) -> tuple[Path, Path]:
    queue = directory / f"queue-{status}.jsonl"
    reviews = directory / f"reviews-{status}.jsonl"
    overlay = directory / f"overlay-{status}.json"
    key_file = directory / "verification.key"
    key_file.write_bytes(b"runtime-verification-overlay-key-32-bytes")
    export_queue(db_path, queue, benchmark_path=None)
    review = json.loads(queue.read_text(encoding="utf-8"))
    review.update(
        review_status=status,
        reviewer="legal-reviewer@example.test",
        reviewed_at="2026-07-22T08:30:00Z",
        review_notes="Đã đối chiếu PDF chính thức.",
    )
    reviews.write_text(json.dumps(review, ensure_ascii=False) + "\n", encoding="utf-8")
    import_reviews(
        db_path,
        reviews,
        overlay,
        signing_key_path=key_file,
        key_id="runtime-review-key",
    )
    return overlay, key_file


def test_local_legal_rag_retrieves_only_local_official_context(tmp_path: Path) -> None:
    db_path = tmp_path / "rag.sqlite3"
    _build_test_db(db_path)
    rag = LocalLegalRAG(db_path)

    references = rag.query("chuyển giao dữ liệu cá nhân")

    assert references
    assert references[0].document_number == "91/2025/QH15"
    assert references[0].source_pdf_sha256 == "a" * 64
    assert references[0].page_start == 12


def test_signed_overlay_promotes_human_verified_status_to_reference(tmp_path: Path) -> None:
    db_path = tmp_path / "rag.sqlite3"
    _build_test_db(db_path, extraction_method="ocr_tesseract")
    overlay, key_file = _publish_overlay(db_path, tmp_path, status="human_verified")
    rag = LocalLegalRAG(
        db_path,
        verification_overlay_path=overlay,
        verification_signing_key_file=key_file,
        verification_key_id="runtime-review-key",
        require_verification_overlay=True,
    )

    result = rag.retrieve("chuyển giao dữ liệu cá nhân")

    assert result.insufficient_reason == ""
    assert result.references
    assert result.references[0].text_verification_status == "human_verified"


def test_rejected_overlay_record_is_never_returned_as_evidence(tmp_path: Path) -> None:
    db_path = tmp_path / "rag.sqlite3"
    _build_test_db(db_path, extraction_method="ocr_tesseract")
    overlay, key_file = _publish_overlay(db_path, tmp_path, status="rejected")
    rag = LocalLegalRAG(
        db_path,
        verification_overlay_path=overlay,
        verification_signing_key_file=key_file,
        verification_key_id="runtime-review-key",
        require_verification_overlay=True,
    )

    result = rag.retrieve("chuyển giao dữ liệu cá nhân")

    assert result.references == ()
    assert result.context_references == ()
    assert result.insufficient_reason == "low_relevance"
    assert result.trace.rejected_reasons["verification_overlay_rejected"] >= 1


def test_runtime_reloads_changed_overlay_and_fails_closed_on_tamper(tmp_path: Path) -> None:
    db_path = tmp_path / "rag.sqlite3"
    _build_test_db(db_path, extraction_method="ocr_tesseract")
    overlay, key_file = _publish_overlay(db_path, tmp_path, status="human_verified")
    rag = LocalLegalRAG(
        db_path,
        verification_overlay_path=overlay,
        verification_signing_key_file=key_file,
        verification_key_id="runtime-review-key",
        require_verification_overlay=True,
    )
    assert rag.query("chuyển giao dữ liệu cá nhân")
    value = json.loads(overlay.read_text(encoding="utf-8"))
    value["authentication"]["value"] = "0" * 64
    overlay.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    result = rag.retrieve("chuyển giao dữ liệu cá nhân")

    assert result.references == ()
    assert result.insufficient_reason == "verification_overlay_integrity_invalid"
    assert result.trace.degraded_reasons == ("verification_overlay_integrity_invalid",)


def test_overlay_for_previous_corpus_release_fails_closed(tmp_path: Path) -> None:
    first_db = tmp_path / "first.sqlite3"
    _build_test_db(first_db, extraction_method="ocr_tesseract")
    overlay, key_file = _publish_overlay(first_db, tmp_path, status="human_verified")
    replacement_db = tmp_path / "replacement.sqlite3"
    _build_test_db(replacement_db, extraction_method="ocr_tesseract")
    connection = sqlite3.connect(replacement_db)
    connection.execute("UPDATE chunks SET text = text || ' Bản phát hành mới.'")
    connection.commit()
    connection.close()
    rag = LocalLegalRAG(
        replacement_db,
        verification_overlay_path=overlay,
        verification_signing_key_file=key_file,
        verification_key_id="runtime-review-key",
        require_verification_overlay=True,
    )

    result = rag.retrieve("chuyển giao dữ liệu cá nhân")

    assert result.references == ()
    assert result.insufficient_reason == "verification_overlay_corpus_mismatch"


def test_no_accent_planner_detects_cross_border_personal_data_transfer() -> None:
    plan = LegalQueryPlanner().plan("doanh nghiep chuyen du lieu khach hang sang may chu singapore")

    assert "cross_border_transfer" in plan.concepts
    assert "personal_data_transfer" in plan.concepts
    assert "erasure" not in plan.concepts
    assert plan.out_of_scope_hint is False


def test_no_accent_cross_border_retrieval_without_char_ngrams() -> None:
    db_path = Path(__file__).resolve().parents[1] / "data" / "legal_rag" / "rag.sqlite3"
    if not db_path.is_file():
        pytest.skip("local legal corpus is not installed")
    retriever = HybridLegalRetriever(
        db_path,
        candidate_k=50,
        enable_char_ngrams=False,
    )

    result = retriever.retrieve(
        "doanh nghiep chuyen du lieu khach hang sang may chu singapore",
        context={"as_of_date": "2026-07-22"},
        top_k=10,
    )

    ids = {reference.chunk_id for reference in result.references}
    assert {
        "vn_decree_356_2025_personal_data::c00080",
        "vn_personal_data_91_2025::c00093",
    }.intersection(ids)
    assert result.trace.candidate_counts.get("char_ngram") == 0


def test_sensitive_external_transfer_requires_review(tmp_path: Path) -> None:
    db_path = tmp_path / "rag.sqlite3"
    _build_test_db(db_path)
    rag = LocalLegalRAG(db_path)

    assessment = rag.assess_action("upload_file", ["personal_data"])

    assert assessment.status == "completed"
    assert assessment.evidence_status == "review_required"
    assert assessment.requires_review is True
    assert assessment.references


def test_missing_index_fails_closed_for_sensitive_transfer(tmp_path: Path) -> None:
    rag = LocalLegalRAG(tmp_path / "missing.sqlite3")

    assessment = rag.assess_action("call_api", ["api_key"])

    assert assessment.status == "unavailable"
    assert assessment.evidence_status == "insufficient_basis"
    assert assessment.requires_review is True


def test_warm_health_is_invalidated_when_database_is_replaced(tmp_path: Path) -> None:
    db_path = tmp_path / "rag.sqlite3"
    _build_test_db(db_path)
    retriever = HybridLegalRetriever(db_path)
    assert retriever.health.ready is True

    db_path.write_bytes(b"not a sqlite legal corpus")

    result = retriever.retrieve(
        "chuyển giao dữ liệu cá nhân",
        context={"as_of_date": "2026-07-22"},
    )
    assert result.references == ()
    assert result.insufficient_reason == "corpus_unavailable"
    assert retriever.health.ready is False


def test_valid_legacy_database_replacement_requires_verified_manifest(tmp_path: Path) -> None:
    db_path = tmp_path / "rag.sqlite3"
    _build_test_db(db_path)
    retriever = HybridLegalRetriever(db_path)
    assert retriever.health.ready is True

    replacement = tmp_path / "other.sqlite3"
    _build_test_db(replacement)
    db_path.write_bytes(replacement.read_bytes())

    assert retriever.health.ready is False
    assert "corpus_changed_without_verified_manifest" in retriever.health.reason_codes


def test_warm_health_fails_closed_when_new_manifest_is_invalid(tmp_path: Path) -> None:
    db_path = tmp_path / "rag.sqlite3"
    _build_test_db(db_path)
    retriever = HybridLegalRetriever(db_path)
    assert retriever.health.ready is True

    (tmp_path / "manifest.json").write_text("{invalid", encoding="utf-8")

    assert retriever.health.ready is False
    assert "manifest_invalid" in retriever.health.reason_codes


def test_opposite_binding_polarity_across_documents_reports_conflict(tmp_path: Path) -> None:
    db_path = tmp_path / "rag.sqlite3"
    _build_test_db(db_path)
    connection = sqlite3.connect(db_path)
    prohibited = "Doanh nghiệp không được chuyển giao dữ liệu cá nhân cho bên thứ ba."
    permitted = "Doanh nghiệp được phép chuyển giao dữ liệu cá nhân cho bên thứ ba."
    connection.execute(
        "UPDATE chunks SET text = ? WHERE chunk_id = ?",
        (prohibited, "vn_personal_data::c00001"),
    )
    second = (
        "vn_data_rules::c00001",
        "vn_data_rules",
        "Nghị định dữ liệu",
        "99/2026/NĐ-CP",
        "decree",
        "VN",
        "Chính phủ",
        "binding",
        "current",
        "2026-01-01",
        "2026-07-22",
        1,
        "vi",
        json.dumps(["personal_data"]),
        "Điều 8. Chuyển giao dữ liệu",
        8,
        8,
        "https://vanban.chinhphu.vn/",
        "https://datafiles.chinhphu.vn/rules.pdf",
        "b" * 64,
        "native_pdf_text",
        permitted,
    )
    connection.execute(
        "INSERT INTO chunks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", second
    )
    connection.execute("DELETE FROM chunks_fts")
    for row in connection.execute(
        "SELECT chunk_id,title,document_number,topics,section,text FROM chunks"
    ).fetchall():
        connection.execute("INSERT INTO chunks_fts VALUES (?,?,?,?,?,?)", row)
    connection.commit()
    connection.close()

    result = HybridLegalRetriever(db_path).retrieve(
        "doanh nghiệp chuyển giao dữ liệu cá nhân cho bên thứ ba",
        context={"as_of_date": "2026-07-22"},
        top_k=8,
    )

    assert len(result.references) == 2
    assert result.conflicts
    conflict = result.conflicts[0]
    assert {conflict["left_polarity"], conflict["right_polarity"]} == {"permission", "prohibition"}
    assert conflict["left_document_id"] != conflict["right_document_id"]
    assert "text" not in conflict
    assert "relationship_metadata_unavailable" in result.trace.degraded_reasons


def test_inference_action_gate_never_weakens_and_adds_legal_reference(tmp_path: Path) -> None:
    db_path = tmp_path / "rag.sqlite3"
    _build_test_db(db_path)
    service = InferenceService(engine=object(), legal_rag=LocalLegalRAG(db_path))

    result = service.assess_action(
        "upload_file",
        None,
        ["personal_data"],
        AgentContext(agent_type="generic"),
    )

    assert result.decision == Decision.ASK_USER_CONFIRMATION
    assert result.requires_user_confirmation is True
    assert result.legal_review_required is True
    assert result.legal_rag_status == "completed"
    assert result.legal_evidence_status == LegalEvidenceStatus.REVIEW_REQUIRED
    assert result.legal_references
    assert any(item.source == "legal_rag" for item in result.evidence)


def test_inference_action_gate_legal_exception_fails_closed() -> None:
    class BrokenLegalRAG:
        def assess_action(self, *args, **kwargs):
            raise RuntimeError("broken legal index")

    service = InferenceService(engine=object(), legal_rag=BrokenLegalRAG())
    result = service.assess_action(
        "call_api",
        None,
        ["api_key"],
        AgentContext(agent_type="generic"),
    )

    assert result.legal_rag_status == "unavailable"
    assert result.legal_evidence_status == LegalEvidenceStatus.INSUFFICIENT_BASIS
    assert result.legal_review_required is True
    assert result.legal_references == []
    assert result.decision == Decision.ASK_USER_CONFIRMATION
