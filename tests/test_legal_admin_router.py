from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.routers import legal_admin
from backend.routers.auth import require_admin
from security.legal.corpus import CorpusHealth, CorpusSnapshot
from security.legal.retrieval import RetrievalTrace
from security.legal_rag import LegalReference, LegalRetrievalResult

client = TestClient(app)


def _health() -> CorpusHealth:
    return CorpusHealth(
        available=True,
        ready=True,
        quick_check="ok",
        reason_codes=("relationship_metadata_unavailable",),
        snapshot=CorpusSnapshot(
            release_id="vn-legal-test.1",
            schema_version=2,
            sha256="a" * 64,
            verified_through="2026-07-22",
            chunk_count=100,
            searchable_chunk_count=90,
            document_count=10,
            searchable_document_count=9,
            coverage_domains=("personal_data", "ai"),
            manifest_verified=True,
        ),
    )


def _reference() -> LegalReference:
    return LegalReference(
        chunk_id="law::c00001",
        document_id="law",
        title="Luật mẫu",
        document_number="91/2025/QH15",
        legal_weight="binding",
        status="current",
        effective_date="2026-01-01",
        section="Điều 20",
        page_start=12,
        page_end=12,
        source_page_url="https://vanban.chinhphu.vn/example",
        source_pdf_sha256="b" * 64,
        extraction_method="native_pdf_text",
        text_preview="P" * 900,
        retrieval_score=0.9,
        jurisdiction="VN",
        status_checked_at="2026-07-22",
        document_type="law",
        authority="Quốc hội",
        source_file_url="https://datafiles.chinhphu.vn/example.pdf",
        full_text="SECRET FULL CHUNK MUST NEVER LEAVE ADMIN DEBUG" * 20,
        relevance_score=0.8,
        retrieval_channels=("lexical", "dense"),
        is_primary=True,
        corpus_release_id="vn-legal-test.1",
    )


class StubRAG:
    def __init__(self):
        self.health = _health()
        self.calls = []

    def retrieve(self, question, *, context, top_k):
        self.calls.append((question, context, top_k))
        reference = _reference()
        return LegalRetrievalResult(
            references=(reference,),
            context_references=(reference,),
            snapshot=self.health.snapshot,
            trace=RetrievalTrace(
                mode="exact+lexical+dense",
                candidate_counts={"lexical": 12},
                latency_ms={"total": 4.56789},
                degraded_reasons=("relationship_metadata_unavailable",),
                rejected_reasons={"below_relevance_threshold": 2},
                plan={
                    "original_question": "PRIVATE QUESTION",
                    "dense_query": "PRIVATE DENSE QUERY",
                    "lexical_queries": ["PRIVATE FTS"],
                    "document_numbers": ["91/2025/QH15"],
                    "article_numbers": ["20"],
                    "clause_numbers": [],
                    "concepts": ["personal_data_transfer"],
                    "required_facets": ["exact_document"],
                    "out_of_scope_hint": False,
                },
            ),
            conflicts=(
                {
                    "type": "opposite_legal_polarity",
                    "left_chunk_id": "law::c00001",
                    "right_chunk_id": "law2::c00001",
                    "left_document_id": "law",
                    "right_document_id": "law2",
                    "left_polarity": "permission",
                    "right_polarity": "prohibition",
                    "token_overlap": 0.9,
                    "requires_human_review": True,
                    "text": "MUST NOT LEAK",
                },
            ),
        )


@pytest.fixture
def admin_api():
    stub = StubRAG()
    app.dependency_overrides[require_admin] = lambda: SimpleNamespace(
        user=SimpleNamespace(role="admin")
    )
    app.dependency_overrides[legal_admin.get_admin_legal_rag] = lambda: stub
    try:
        yield stub
    finally:
        app.dependency_overrides.pop(require_admin, None)
        app.dependency_overrides.pop(legal_admin.get_admin_legal_rag, None)


def test_legal_rag_admin_endpoints_are_not_public():
    assert client.get("/admin/legal-rag/health").status_code == 401
    assert (
        client.post("/admin/legal-rag/debug-retrieval", json={"question": "test"}).status_code
        == 401
    )


def test_health_exposes_release_and_counts_without_corpus_text(admin_api):
    response = client.get("/admin/legal-rag/health")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ready"] is True
    assert body["release_id"] == "vn-legal-test.1"
    assert body["verified_through"] == "2026-07-22"
    assert body["manifest"] == {"present": True, "verified": True, "required": False}
    assert body["counts"]["chunks"] == 100
    assert body["degraded_reasons"] == ["relationship_metadata_unavailable"]
    assert "text" not in json.dumps(body).casefold()


def test_debug_retrieval_is_bounded_and_sanitized_without_generation(admin_api):
    response = client.post(
        "/admin/legal-rag/debug-retrieval",
        json={
            "question": "Có được chuyển dữ liệu không?",
            "context": {"jurisdiction": "VN", "as_of_date": "2026-07-22"},
            "top_k": 3,
            "preview_chars": 80,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert admin_api.calls[0][2] == 3
    assert len(body["references"][0]["text_preview"]) == 80
    assert "full_text" not in body["references"][0]
    assert "SECRET FULL CHUNK" not in response.text
    assert "PRIVATE QUESTION" not in response.text
    assert "PRIVATE DENSE QUERY" not in response.text
    assert "PRIVATE FTS" not in response.text
    assert "MUST NOT LEAK" not in response.text
    assert body["trace"]["plan"]["document_numbers"] == ["91/2025/QH15"]
    assert body["conflicts"][0]["type"] == "opposite_legal_polarity"


def test_debug_request_schema_rejects_extra_and_unbounded_preview(admin_api):
    extra = client.post(
        "/admin/legal-rag/debug-retrieval",
        json={"question": "test", "generator": "must-not-exist"},
    )
    assert extra.status_code == 422
    oversized = client.post(
        "/admin/legal-rag/debug-retrieval",
        json={"question": "test", "preview_chars": 501},
    )
    assert oversized.status_code == 422
    assert admin_api.calls == []
