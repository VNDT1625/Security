from __future__ import annotations

import inspect
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from backend.db import initialize_database
from backend.main import app
from backend.routers import legal as legal_router

client = TestClient(app)


def request_payload(**updates):
    payload = {
        "schema_version": "legal-answer.v2",
        "request_id": str(uuid.uuid4()),
        "idempotency_key": f"legal-{uuid.uuid4().hex}",
        "intent_mode": "legal",
        "question": "Doanh nghiệp có phải xóa dữ liệu cá nhân không?",
        "legal_context": {
            "jurisdiction": "VN",
            "as_of_date": "2026-07-22",
            "actor": "doanh nghiệp",
            "action": "xóa dữ liệu",
            "data_or_asset": "dữ liệu cá nhân",
            "recipient": "",
            "purpose": "thực hiện quyền của chủ thể dữ liệu",
            "consent_state": "unknown",
        },
    }
    payload.update(updates)
    return payload


class StubService:
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def answer(self, question, context, *, intent_mode, before_generate=None):
        self.calls.append((question, context, intent_mode))
        if isinstance(self.result, Exception):
            raise self.result
        if (
            isinstance(self.result, dict)
            and self.result.get("generation_attempted") is True
            and before_generate is not None
        ):
            callback_result = before_generate()
            if inspect.isawaitable(callback_result):
                await callback_result
        return self.result


def answered_result():
    return {
        "status": "answered",
        "reason_code": "verified",
        "jurisdiction": "VN",
        "as_of_date": "2026-07-22",
        "answer": "Bên kiểm soát dữ liệu phải xóa dữ liệu theo căn cứ được trích dẫn.",
        "claims": [{"claim_id": "claim-1", "text": "Bên kiểm soát phải xóa dữ liệu."}],
        "citations": [{"chunk_id": "law::c1", "document_number": "91/2025/QH15"}],
        "missing_facts": [],
        "uncertainties": [],
        "requires_human_review": False,
        "corpus": {
            "release_id": "vn-legal-2026-07-22.1",
            "verified_through": "2026-07-22",
            "coverage_domains": ["personal_data"],
        },
        "trace_id": "trace-test",
        "generation_attempted": True,
        "generation_succeeded": True,
        "corpus_coverage_domains": ["personal_data", "ai"],
    }


def install(
    monkeypatch,
    service,
    quota_calls=None,
    ai_reserve_calls=None,
    ai_refund_calls=None,
):
    initialize_database()
    monkeypatch.setattr(
        legal_router, "get_user_legal_answer_service", lambda _db, _user_id: service
    )
    if quota_calls is not None:
        monkeypatch.setattr(
            legal_router,
            "reserve_scan_quota",
            lambda *_args, **_kwargs: quota_calls.append(True),
        )
    monkeypatch.setattr(
        legal_router,
        "reserve_ai_credits",
        lambda *_args, **_kwargs: (
            ai_reserve_calls.append(True) if ai_reserve_calls is not None else None
        ),
    )
    monkeypatch.setattr(
        legal_router,
        "refund_ai_credits",
        lambda *_args, **_kwargs: (
            ai_refund_calls.append(True) if ai_refund_calls is not None else None
        ),
    )


def test_legal_endpoint_returns_verified_contract(monkeypatch):
    service = StubService(answered_result())
    install(monkeypatch, service)

    response = client.post("/v1/legal/answers", json=request_payload())

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_version"] == "legal-answer.v2"
    assert body["status"] == "answered"
    assert body["reason_code"] == "verified"
    assert body["citations"][0]["chunk_id"] == "law::c1"
    assert body["corpus"]["verified_through"] == "2026-07-22"
    assert body["corpus"]["coverage_domains"] == ["personal_data", "ai"]
    assert "retrieval_trace" not in body
    assert service.calls[0][2] == "legal"


def test_context_forces_legal_mode_when_request_says_auto(monkeypatch):
    service = StubService(answered_result())
    install(monkeypatch, service)
    payload = request_payload(intent_mode="auto")

    response = client.post("/v1/legal/answers", json=payload)

    assert response.status_code == 200
    assert service.calls[0][2] == "legal"


def test_idempotent_retry_skips_service_and_quota(monkeypatch):
    service = StubService(answered_result())
    quota_calls = []
    ai_reserve_calls = []
    ai_refund_calls = []
    install(monkeypatch, service, quota_calls, ai_reserve_calls, ai_refund_calls)
    payload = request_payload()

    first = client.post("/v1/legal/answers", json=payload)
    second = client.post("/v1/legal/answers", json=payload)

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert len(service.calls) == 1
    assert len(quota_calls) == 1
    assert len(ai_reserve_calls) == 1
    assert ai_refund_calls == []


def test_concurrent_duplicate_is_pending_before_any_second_quota(monkeypatch):
    started = threading.Event()
    release = threading.Event()

    class BlockingService(StubService):
        async def answer(self, question, context, *, intent_mode, before_generate=None):
            self.calls.append((question, context, intent_mode))
            started.set()
            assert release.wait(timeout=10)
            if before_generate is not None:
                before_generate()
            return self.result

    service = BlockingService(answered_result())
    quota_calls: list[bool] = []
    ai_reserve_calls: list[bool] = []
    install(
        monkeypatch,
        service,
        quota_calls=quota_calls,
        ai_reserve_calls=ai_reserve_calls,
    )
    payload = request_payload()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(
            client.post,
            "/v1/legal/answers",
            json=payload,
        )
        assert started.wait(timeout=10)
        duplicate = client.post("/v1/legal/answers", json=payload)
        mismatched = client.post(
            "/v1/legal/answers",
            json=dict(payload, question="Một câu hỏi khác dùng cùng idempotency key"),
        )
        release.set()
        first = first_future.result(timeout=10)

    assert first.status_code == 200
    assert duplicate.status_code == 409
    assert "in progress" in duplicate.json()["detail"]
    assert mismatched.status_code == 409
    assert "different legal request" in mismatched.json()["detail"]
    assert len(service.calls) == 1
    assert len(quota_calls) == 1
    assert len(ai_reserve_calls) == 1


def test_final_storage_failure_leaves_pending_claim_and_prevents_double_debit(
    monkeypatch,
):
    service = StubService(answered_result())
    quota_calls: list[bool] = []
    ai_reserve_calls: list[bool] = []
    install(
        monkeypatch,
        service,
        quota_calls=quota_calls,
        ai_reserve_calls=ai_reserve_calls,
    )
    payload = request_payload()
    original_store = legal_router._store_response

    def fail_store(*_args, **_kwargs):
        raise legal_router._storage_failure()

    monkeypatch.setattr(legal_router, "_store_response", fail_store)
    first = client.post("/v1/legal/answers", json=payload)
    monkeypatch.setattr(legal_router, "_store_response", original_store)
    retry = client.post("/v1/legal/answers", json=payload)

    assert first.status_code == 503
    assert retry.status_code == 409
    assert len(service.calls) == 1
    assert len(quota_calls) == 1
    assert len(ai_reserve_calls) == 1


def test_pre_generation_safe_status_does_not_consume_ai_credit(monkeypatch):
    service = StubService(
        {
            "status": "need_more_facts",
            "reason_code": "missing_required_context",
            "missing_facts": ["actor"],
            "generation_attempted": False,
            "generation_succeeded": False,
        }
    )
    ai_reserve_calls = []
    ai_refund_calls = []
    install(
        monkeypatch,
        service,
        ai_reserve_calls=ai_reserve_calls,
        ai_refund_calls=ai_refund_calls,
    )

    response = client.post("/v1/legal/answers", json=request_payload())

    assert response.status_code == 200
    assert response.json()["status"] == "need_more_facts"
    assert ai_reserve_calls == []
    assert ai_refund_calls == []


def test_failed_generation_refunds_reserved_ai_credit_exactly_once(monkeypatch):
    service = StubService(
        {
            "status": "insufficient_legal_basis",
            "reason_code": "generation_failed",
            "generation_attempted": True,
            "generation_succeeded": False,
        }
    )
    ai_reserve_calls = []
    ai_refund_calls = []
    install(
        monkeypatch,
        service,
        ai_reserve_calls=ai_reserve_calls,
        ai_refund_calls=ai_refund_calls,
    )

    response = client.post("/v1/legal/answers", json=request_payload())

    assert response.status_code == 200
    assert response.json()["status"] == "insufficient_legal_basis"
    assert len(ai_reserve_calls) == 1
    assert len(ai_refund_calls) == 1


def test_reusing_idempotency_key_for_different_payload_returns_conflict(monkeypatch):
    service = StubService(answered_result())
    install(monkeypatch, service)
    payload = request_payload()
    assert client.post("/v1/legal/answers", json=payload).status_code == 200
    changed = dict(payload, question="Một câu hỏi pháp lý khác")

    response = client.post("/v1/legal/answers", json=changed)

    assert response.status_code == 409
    assert len(service.calls) == 1


def test_service_failure_and_nonlegal_auto_fail_closed(monkeypatch):
    failing = StubService(RuntimeError("secret provider failure"))
    install(monkeypatch, failing)
    failed = client.post("/v1/legal/answers", json=request_payload())
    assert failed.status_code == 200
    assert failed.json()["status"] == "insufficient_legal_basis"
    assert failed.json()["reason_code"] == "internal_failure"
    assert "secret provider failure" not in failed.text

    nonlegal = StubService(None)
    install(monkeypatch, nonlegal)
    payload = request_payload(
        request_id=str(uuid.uuid4()),
        idempotency_key=f"legal-{uuid.uuid4().hex}",
        intent_mode="auto",
        question="Cách tránh phishing?",
        legal_context=None,
    )
    response = client.post("/v1/legal/answers", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "insufficient_legal_basis"
    assert response.json()["reason_code"] == "not_legal_intent"


def test_safe_status_never_exposes_unverified_model_prose(monkeypatch):
    service = StubService(
        {
            "status": "human_legal_review",
            "answer": "RAW MODEL CLAIM: hành động chắc chắn hợp pháp",
            "claims": [{"text": "hành động chắc chắn hợp pháp"}],
            "citations": [{"chunk_id": "candidate-only"}],
            "requires_human_review": True,
        }
    )
    install(monkeypatch, service)

    response = client.post("/v1/legal/answers", json=request_payload())

    body = response.json()
    assert body["status"] == "human_legal_review"
    assert body["claims"] == []
    assert body["citations"] == []
    assert "RAW MODEL CLAIM" not in body["answer"]


def test_answered_with_review_flag_is_downgraded_and_hidden(monkeypatch):
    result = answered_result()
    result["requires_human_review"] = True
    service = StubService(result)
    install(monkeypatch, service)

    response = client.post("/v1/legal/answers", json=request_payload())

    body = response.json()
    assert body["status"] == "human_legal_review"
    assert body["reason_code"] == "unverified_ocr"
    assert body["claims"] == []
    assert body["citations"] == []


def test_unsupported_jurisdiction_is_out_of_scope_not_missing_fact(monkeypatch):
    service = StubService(
        {
            "status": "need_more_facts",
            "reason_code": "unsupported_jurisdiction",
            "missing_facts": ["jurisdiction_supported"],
        }
    )
    install(monkeypatch, service)

    response = client.post("/v1/legal/answers", json=request_payload())

    assert response.json()["status"] == "insufficient_legal_basis"
    assert response.json()["reason_code"] == "unsupported_jurisdiction"


def test_request_schema_is_strict(monkeypatch):
    service = StubService(answered_result())
    install(monkeypatch, service)
    invalid = request_payload(intent_mode="normal", unexpected=True)

    response = client.post("/v1/legal/answers", json=invalid)

    assert response.status_code == 422
    assert service.calls == []
