from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.services.legal_answer_service import LegalAnswerService, LegalQuestionContext
from backend.services.official_legal_web_service import OfficialWebSearchResult
from security.legal.query_planner import LegalQueryPlanner
from security.legal_rag import LegalReference, LocalLegalRAG

EVIDENCE_TEXT = "Doanh nghiệp phải có sự đồng ý trước khi chuyển dữ liệu cá nhân."


def _ref(**changes: object) -> LegalReference:
    base = LegalReference(
        chunk_id="vn_law::c1",
        document_id="vn_law",
        title="Luật mẫu",
        document_number="91/2025/QH15",
        legal_weight="binding",
        status="current",
        effective_date="2026-01-01",
        section="Điều 20",
        page_start=12,
        page_end=12,
        source_page_url="https://vanban.chinhphu.vn/x",
        source_pdf_sha256="a" * 64,
        extraction_method="native_pdf_text",
        text_preview=EVIDENCE_TEXT,
        full_text=EVIDENCE_TEXT,
        retrieval_score=-1.0,
        jurisdiction="VN",
        status_checked_at="2026-07-22",
        corpus_release_id="vn-legal-test",
    )
    return replace(base, **changes)


class QueryStubRAG:
    available = True

    def __init__(self, refs: tuple[LegalReference, ...] | list[LegalReference] = ()) -> None:
        self.refs = tuple(refs)
        self.query_text = ""
        self.query_calls = 0

    def query(self, question: str, *, top_k: int | None = None) -> tuple[LegalReference, ...]:
        self.query_text = question
        self.query_calls += 1
        return self.refs


class RetrieveStubRAG:
    available = True

    def __init__(
        self,
        refs: tuple[LegalReference, ...] | list[LegalReference] = (),
        *,
        context_refs: tuple[LegalReference, ...] | list[LegalReference] | None = None,
        insufficient_reason: str = "",
        conflicts: tuple[dict[str, object], ...] = (),
    ) -> None:
        references = tuple(refs)
        self.result = SimpleNamespace(
            references=references,
            context_references=tuple(context_refs) if context_refs is not None else references,
            snapshot=SimpleNamespace(
                release_id="vn-legal-2026-07-22.1",
                verified_through="2026-07-22",
                coverage_domains=("personal_data", "cybersecurity"),
            ),
            trace={
                "mode": "hybrid",
                "candidate_counts": {"lexical": 12, "dense": 10},
                "text": "must not escape",
            },
            insufficient_reason=insufficient_reason,
            conflicts=conflicts,
        )
        self.retrieve_calls = 0
        self.question = ""
        self.context: dict[str, str] = {}

    def retrieve(self, question: str, *, context: dict[str, str], top_k: int) -> SimpleNamespace:
        self.retrieve_calls += 1
        self.question = question
        self.context = context
        return self.result

    def query(self, *_args: object, **_kwargs: object) -> tuple[LegalReference, ...]:
        raise AssertionError("query fallback must not run when retrieve is available")


class WebStub:
    def __init__(self, refs: tuple[LegalReference, ...] = ()) -> None:
        self.refs = refs
        self.calls: list[tuple[str, str]] = []

    async def search(
        self,
        question: str,
        *,
        jurisdiction: str,
        reference_hints: tuple[str, ...] = (),
    ) -> OfficialWebSearchResult:
        self.calls.append((question, jurisdiction))
        return OfficialWebSearchResult(
            references=self.refs,
            query_count=2,
            candidate_count=len(self.refs),
            fetched_count=len(self.refs),
        )


CTX = LegalQuestionContext("VN", "2026-07-22", "doanh nghiệp", "chuyển dữ liệu", "dữ liệu cá nhân")


def _generation(
    *,
    chunk_id: str = "vn_law::c1",
    quote: str = EVIDENCE_TEXT,
    claim: str = EVIDENCE_TEXT,
    claim_type: str = "obligation",
) -> dict[str, object]:
    return {
        "status": "answered",
        "claims": [
            {
                "claim_id": "claim-1",
                "claim_type": claim_type,
                "text": claim,
                "evidence": [
                    {
                        "provision_id": "Điều 20",
                        "chunk_id": chunk_id,
                        "quote": quote,
                    }
                ],
            }
        ],
        "missing_facts": [],
        "uncertainties": [],
        "requires_human_review": False,
    }


@pytest.mark.asyncio
async def test_non_legal_question_uses_normal_pipeline() -> None:
    result = await LegalAnswerService(QueryStubRAG()).answer("Cách tránh phishing?", CTX)
    assert result is None


@pytest.mark.parametrize(
    "question",
    (
        "Cong ty co duoc phep chuyen du lieu khong?",
        "Luat quy dinh van de nay ra sao?",
        "Phap luat Viet Nam co cam hanh dong nay khong?",
    ),
)
def test_auto_legal_classifier_recognizes_vietnamese_without_accents(
    question: str,
) -> None:
    assert LegalAnswerService.is_legal_question(question) is True


def test_no_accent_legal_out_of_scope_question_still_abstains_in_planner() -> None:
    planner = LegalQueryPlanner()
    plan = planner.plan("Phap luat thue dat phi nong nghiep tinh nhu the nao?")

    assert planner.is_legal_question(plan.original_question) is True
    assert plan.out_of_scope_hint is True


@pytest.mark.asyncio
async def test_explicit_legal_mode_cannot_be_blocked_by_classifier() -> None:
    rag = QueryStubRAG()
    result = await LegalAnswerService(rag).answer(
        "Thu thập trường thông tin này", CTX, intent_mode="legal"
    )
    assert result is not None
    assert result.status == "insufficient_legal_basis"
    assert rag.query_calls == 1


@pytest.mark.asyncio
async def test_mode_remains_a_backwards_compatible_alias() -> None:
    result = await LegalAnswerService(QueryStubRAG()).answer(
        "Thu thập trường thông tin này", CTX, mode="legal"
    )
    assert result is not None
    assert result.status == "insufficient_legal_basis"


@pytest.mark.asyncio
async def test_missing_required_facts_stops_before_retrieval() -> None:
    rag = RetrieveStubRAG([_ref()])
    callback_calls = 0

    def before_generate() -> None:
        nonlocal callback_calls
        callback_calls += 1

    result = await LegalAnswerService(rag).answer(
        "Có vi phạm không?",
        LegalQuestionContext(action="thu thập dữ liệu"),
        before_generate=before_generate,
    )
    assert result is not None
    assert result.status == "need_more_facts"
    assert "jurisdiction" in result.missing_facts
    assert rag.retrieve_calls == 0
    assert callback_calls == 0
    assert result.generation_attempted is False
    assert result.generation_succeeded is False


@pytest.mark.asyncio
async def test_ai_infers_missing_legal_context_before_hybrid_retrieval() -> None:
    rag = RetrieveStubRAG([_ref()])
    web = WebStub()
    generator_calls = 0
    callback_calls = 0

    async def generator(system: str, _prompt: str) -> dict[str, object]:
        nonlocal generator_calls
        generator_calls += 1
        if "trích xuất bối cảnh" in system:
            return {
                "actor": "doanh nghiệp",
                "action": "thông báo sự cố",
                "data_or_asset": "dữ liệu cá nhân khách hàng",
            }
        return _generation()

    def before_generate() -> None:
        nonlocal callback_calls
        callback_calls += 1

    result = await LegalAnswerService(
        rag,
        generator,
        web_retriever=web,
    ).answer(
        "Doanh nghiệp phải thông báo sự cố dữ liệu cá nhân thế nào?",
        LegalQuestionContext(jurisdiction="VN", as_of_date="2026-07-22"),
        intent_mode="legal",
        before_generate=before_generate,
    )

    assert result is not None
    assert result.status == "answered"
    # Explicit Vietnamese phrases are extracted locally, so the model is used
    # only once for the evidence-grounded legal claims.
    assert generator_calls == 1
    assert callback_calls == 1
    assert rag.context["actor"] == "doanh nghiệp"
    assert rag.context["action"] == "thông báo sự cố"
    assert rag.context["data_or_asset"] == "dữ liệu cá nhân"


@pytest.mark.asyncio
async def test_clear_vietnamese_incident_question_works_when_generator_is_unavailable() -> None:
    rag = RetrieveStubRAG([_ref()])
    result = await LegalAnswerService(
        rag,
        generator=None,
        web_retriever=WebStub(),
    ).answer(
        "Doanh nghiệp tại Việt Nam cần làm gì khi phát hiện sự cố rò rỉ dữ liệu cá nhân?",
        LegalQuestionContext(jurisdiction="VN", as_of_date="2026-07-22"),
        intent_mode="legal",
    )

    assert result is not None
    assert result.status == "insufficient_legal_basis"
    assert result.reason_code == "generator_unavailable"
    assert rag.context["actor"] == "doanh nghiệp"
    assert rag.context["action"] == "ứng phó và thông báo sự cố rò rỉ dữ liệu"
    assert rag.context["data_or_asset"] == "dữ liệu cá nhân"
    assert result.citations
    assert result.citations[0]["source_page_url"]


@pytest.mark.asyncio
async def test_official_web_sources_merge_with_local_rag_and_expose_provenance() -> None:
    web_ref = _ref(
        chunk_id="official-web::1",
        document_id="official-web::doc",
        legal_weight="official_guidance",
        document_type="official_web",
        authority="Bộ Công an",
        retrieval_channels=("official_web",),
        extraction_method="official_html_text",
        source_page_url="https://bocongan.gov.vn/canh-bao",
        corpus_release_id="official-web-2026-07-22",
    )
    rag = RetrieveStubRAG([_ref()])

    result = await LegalAnswerService(
        rag,
        lambda *_: _generation(),
        web_retriever=WebStub((web_ref,)),
    ).answer("Có phải xin sự đồng ý không?", CTX)

    assert result is not None
    assert result.status == "answered"
    assert result.retrieval_mode == "hybrid+official_web"
    assert result.retrieval_trace["official_web"]["fetched_count"] == 1
    assert result.corpus_coverage_domains == [
        "personal_data",
        "cybersecurity",
        "official_web",
    ]
    assert result.citations[0]["source_kind"] == "corpus"


@pytest.mark.asyncio
async def test_verified_factual_claim_can_link_to_retrieved_official_page() -> None:
    official_fact = "Bộ Công an công bố cảnh báo về nguy cơ lộ lọt dữ liệu trên không gian mạng."
    web_ref = _ref(
        chunk_id="official-web::fact",
        document_id="official-web::doc",
        legal_weight="official_guidance",
        document_type="official_web",
        authority="Bộ Công an",
        retrieval_channels=("official_web",),
        extraction_method="official_html_text",
        source_page_url="https://bocongan.gov.vn/canh-bao",
        corpus_release_id="official-web-2026-07-22",
        text_preview=official_fact,
        full_text=official_fact,
    )

    result = await LegalAnswerService(
        RetrieveStubRAG(insufficient_reason="corpus_stale"),
        lambda *_: _generation(
            chunk_id="official-web::fact",
            claim_type="fact",
            quote=official_fact,
            claim=official_fact,
        ),
        web_retriever=WebStub((web_ref,)),
    ).answer("Cơ quan chức năng đang cảnh báo điều gì?", CTX, intent_mode="legal")

    assert result is not None
    assert result.status == "answered"
    assert result.citations[0]["source_kind"] == "official_web"
    assert result.citations[0]["authority"] == "Bộ Công an"
    assert result.citations[0]["source_page_url"] == "https://bocongan.gov.vn/canh-bao"


@pytest.mark.asyncio
async def test_missing_database_fails_closed(tmp_path: Path) -> None:
    result = await LegalAnswerService(LocalLegalRAG(tmp_path / "missing.db")).answer(
        "Có được phép không?", CTX
    )
    assert result is not None
    assert result.status == "insufficient_legal_basis"
    assert result.reason_code == "corpus_unavailable"


@pytest.mark.asyncio
async def test_retrieve_is_preferred_and_receives_structured_context() -> None:
    rag = RetrieveStubRAG([_ref()])
    result = await LegalAnswerService(rag).answer("Có phải xin sự đồng ý không?", CTX)
    assert result is not None
    assert result.status == "insufficient_legal_basis"
    assert rag.retrieve_calls == 1
    assert rag.question == "Có phải xin sự đồng ý không?"
    assert rag.context["actor"] == "doanh nghiệp"
    assert rag.context["as_of_date"] == "2026-07-22"
    assert result.corpus_release_id == "vn-legal-2026-07-22.1"
    assert result.retrieval_mode == "hybrid"
    assert result.retrieval_trace["candidate_counts"]["lexical"] == 12
    assert "text" not in result.retrieval_trace
    assert result.corpus_coverage_domains == ["personal_data", "cybersecurity"]


@pytest.mark.asyncio
async def test_query_fallback_keeps_legacy_test_rag_compatible() -> None:
    rag = QueryStubRAG([_ref()])
    result = await LegalAnswerService(rag).answer("Có phải xin sự đồng ý không?", CTX)
    assert result is not None
    assert result.status == "insufficient_legal_basis"
    assert "Việt Nam" in rag.query_text
    assert "2026-07-22" in rag.query_text
    assert result.retrieval_mode == "legacy_query"


@pytest.mark.asyncio
async def test_before_generate_is_not_called_when_retrieval_has_no_references() -> None:
    callback_calls = 0

    async def before_generate() -> None:
        nonlocal callback_calls
        callback_calls += 1

    result = await LegalAnswerService(QueryStubRAG(), lambda *_: _generation()).answer(
        "Có phải xin sự đồng ý không?", CTX, before_generate=before_generate
    )
    assert result is not None
    assert result.status == "insufficient_legal_basis"
    assert callback_calls == 0
    assert result.generation_attempted is False
    assert result.generation_succeeded is False


@pytest.mark.asyncio
async def test_stale_fallback_source_stops_before_generation() -> None:
    called = False

    def generator(*_args: object) -> dict[str, object]:
        nonlocal called
        called = True
        return _generation()

    result = await LegalAnswerService(
        QueryStubRAG([_ref(status_checked_at="2026-07-21")]), generator
    ).answer("Có phải xin sự đồng ý không?", CTX)
    assert result is not None
    assert result.status == "insufficient_legal_basis"
    assert called is False


@pytest.mark.asyncio
async def test_retriever_stale_state_stops_before_generation() -> None:
    called = False

    def generator(*_args: object) -> dict[str, object]:
        nonlocal called
        called = True
        return _generation()

    rag = RetrieveStubRAG(insufficient_reason="corpus_stale")
    result = await LegalAnswerService(rag, generator).answer("Có được phép không?", CTX)
    assert result is not None
    assert result.status == "insufficient_legal_basis"
    assert result.reason_code == "corpus_stale"
    assert called is False


@pytest.mark.asyncio
async def test_conflict_is_preserved_and_stops_before_generation() -> None:
    called = False

    def generator(*_args: object) -> dict[str, object]:
        nonlocal called
        called = True
        return _generation()

    rag = RetrieveStubRAG([_ref()], conflicts=({"kind": "supersedes", "document_id": "vn_law"},))
    result = await LegalAnswerService(rag, generator).answer("Có được phép không?", CTX)
    assert result is not None
    assert result.status == "conflicting_sources"
    assert result.requires_human_review is True
    assert called is False


@pytest.mark.asyncio
async def test_hallucinated_citation_is_rejected() -> None:
    def generator(*_args: object) -> dict[str, object]:
        return _generation(chunk_id="invented::chunk")

    result = await LegalAnswerService(QueryStubRAG([_ref()]), generator).answer(
        "Có phải xin sự đồng ý không?", CTX
    )
    assert result is not None
    assert result.status == "insufficient_legal_basis"
    assert result.reason_code == "unknown_chunk_id"
    assert result.legal_conclusions == []
    assert result.citations == []
    assert "Hướng xử lý thận trọng" in result.answer


@pytest.mark.asyncio
async def test_non_exact_quote_is_rejected() -> None:
    def generator(*_args: object) -> dict[str, object]:
        return _generation(quote="Doanh nghiệp chắc chắn được phép chuyển dữ liệu.")

    result = await LegalAnswerService(QueryStubRAG([_ref()]), generator).answer(
        "Có phải xin sự đồng ý không?", CTX
    )
    assert result is not None
    assert result.status == "insufficient_legal_basis"
    assert result.reason_code == "quote_not_found"


@pytest.mark.asyncio
async def test_valid_answer_is_composed_only_from_verified_claim_and_database_metadata() -> None:
    callback_calls = 0

    async def before_generate() -> None:
        nonlocal callback_calls
        callback_calls += 1

    async def generator(_system: str, prompt: str) -> dict[str, object]:
        assert EVIDENCE_TEXT in prompt
        return _generation()

    result = await LegalAnswerService(RetrieveStubRAG([_ref()]), generator).answer(
        "Có phải xin sự đồng ý không?", CTX, before_generate=before_generate
    )
    assert result is not None
    assert result.status == "answered"
    assert result.answer == f"{EVIDENCE_TEXT} [1]"
    assert result.citations[0]["document_number"] == "91/2025/QH15"
    assert result.citations[0]["page_start"] == 12
    assert result.citations[0]["status_checked_at"] == "2026-07-22"
    assert result.citations[0]["quotes"] == [EVIDENCE_TEXT]
    assert result.legal_conclusions[0]["claim_type"] == "obligation"
    assert result.retrieval_trace["mode"] == "hybrid"
    assert result.corpus_coverage_domains == ["personal_data", "cybersecurity"]
    assert callback_calls == 1
    assert result.generation_attempted is True
    assert result.generation_succeeded is True


@pytest.mark.asyncio
async def test_sync_before_generate_runs_once_and_generator_failure_is_tracked() -> None:
    callback_calls = 0
    generator_calls = 0

    def before_generate() -> None:
        nonlocal callback_calls
        callback_calls += 1

    def generator(*_args: object) -> dict[str, object]:
        nonlocal generator_calls
        generator_calls += 1
        raise RuntimeError("provider unavailable")

    result = await LegalAnswerService(QueryStubRAG([_ref()]), generator).answer(
        "Có phải xin sự đồng ý không?", CTX, before_generate=before_generate
    )
    assert result is not None
    assert result.status == "insufficient_legal_basis"
    assert callback_calls == 1
    assert generator_calls == 1
    assert result.generation_attempted is True
    assert result.generation_succeeded is False


@pytest.mark.asyncio
async def test_before_generate_failure_does_not_mark_generation_attempted() -> None:
    generator_calls = 0

    async def before_generate() -> None:
        raise RuntimeError("quota unavailable")

    def generator(*_args: object) -> dict[str, object]:
        nonlocal generator_calls
        generator_calls += 1
        return _generation()

    result = await LegalAnswerService(QueryStubRAG([_ref()]), generator).answer(
        "Có phải xin sự đồng ý không?", CTX, before_generate=before_generate
    )
    assert result is not None
    assert result.reason_code == "before_generate_failed"
    assert generator_calls == 0
    assert result.generation_attempted is False
    assert result.generation_succeeded is False


@pytest.mark.asyncio
async def test_legacy_generator_payload_is_verified_and_freeform_answer_is_ignored() -> None:
    def generator(*_args: object) -> dict[str, object]:
        return {
            "status": "answered",
            "answer": "MODEL FREEFORM MUST NOT DISPLAY",
            "legal_conclusions": [{"claim": EVIDENCE_TEXT, "citation_ids": ["vn_law::c1"]}],
        }

    result = await LegalAnswerService(QueryStubRAG([_ref()]), generator).answer(
        "Có phải xin sự đồng ý không?", CTX
    )
    assert result is not None
    assert result.status == "answered"
    assert "MODEL FREEFORM" not in result.answer
    assert result.answer == f"{EVIDENCE_TEXT} [1]"


@pytest.mark.asyncio
async def test_unverified_ocr_never_becomes_answered() -> None:
    def generator(*_args: object) -> dict[str, object]:
        return _generation()

    result = await LegalAnswerService(
        QueryStubRAG([_ref(extraction_method="pending_ocr_review")]), generator
    ).answer("Có phải xin sự đồng ý không?", CTX)
    assert result is not None
    assert result.status == "human_legal_review"
    assert result.requires_human_review is True
    assert result.legal_conclusions == []
    assert result.citations == []


@pytest.mark.asyncio
async def test_normative_claim_requires_binding_source() -> None:
    def generator(*_args: object) -> dict[str, object]:
        return _generation()

    result = await LegalAnswerService(
        QueryStubRAG([_ref(legal_weight="policy_strategy")]), generator
    ).answer("Có phải xin sự đồng ý không?", CTX)
    assert result is not None
    assert result.status == "insufficient_legal_basis"
    assert result.reason_code == "binding_basis_required"
