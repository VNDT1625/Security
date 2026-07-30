from __future__ import annotations

import asyncio
import inspect
import json
import uuid
from dataclasses import dataclass

from fastapi import WebSocketDisconnect

from backend.routers import chat


class _WebSocket:
    def __init__(self, payload: dict) -> None:
        self._messages = [json.dumps(payload)]
        self.sent: list[dict] = []

    async def accept(self) -> None:
        return None

    async def receive_text(self) -> str:
        if not self._messages:
            raise WebSocketDisconnect()
        return self._messages.pop(0)

    async def send_text(self, value: str) -> None:
        self.sent.append(json.loads(value))


@dataclass(frozen=True)
class _ExpandedContext:
    jurisdiction: str = ""
    as_of_date: str = ""
    actor: str = ""
    action: str = ""
    data_or_asset: str = ""
    purpose: str = ""
    recipient: str = ""
    consent_state: str = ""
    mode: str = ""


class _Result:
    def __init__(self, *, reason_code: str = "", status: str = "answered") -> None:
        self.answer = "Câu trả lời an toàn"
        self.payload = {
            "status": status,
            "answer": self.answer,
            "reason_code": reason_code,
            "retrieval_trace": {
                "trace_id": "legal-trace-1",
                "mode": "hybrid",
                "candidate_count": 12,
                "planner": {"concepts": ["personal_data"]},
            },
            "corpus": {"release_id": "vn-2026.1", "verified_through": "2026-07-22"},
            "generation_attempted": True,
            "generation_succeeded": reason_code != "generation_failed",
        }

    def model_dump(self, *, mode: str = "python") -> dict:
        assert mode == "json"
        return dict(self.payload)


class _Actor:
    user = None


class _Plan:
    chatFollowupLimit = 3
    autoWebContext = False
    autoMessageContext = False


def _prepare(
    monkeypatch,
    service,
    events: list[str],
    *,
    intent_mode: str = "legal",
) -> tuple[_WebSocket, list[str]]:
    payload = {
        "question": "Có phải xin đồng ý không?",
        "intent_mode": intent_mode,
        "legal_context": {
            "jurisdiction": "VN",
            "as_of_date": "2026-07-22",
            "actor": "doanh nghiệp",
            "action": "chuyển dữ liệu",
            "data_or_asset": "dữ liệu cá nhân",
            "purpose": "cung cấp dịch vụ",
            "recipient": "nhà cung cấp Singapore",
            "consent_state": "chưa rõ",
        },
    }
    ws = _WebSocket(payload)
    refunds: list[str] = []
    monkeypatch.setattr(chat, "LegalQuestionContext", _ExpandedContext)
    monkeypatch.setattr(chat, "get_explanation_service", lambda: object())
    monkeypatch.setattr(chat, "get_user_explanation_service", lambda *_: object())
    monkeypatch.setattr(chat, "get_user_legal_answer_service", lambda *_: service)
    monkeypatch.setattr(chat, "resolve_actor", lambda *_: _Actor())
    monkeypatch.setattr(chat, "build_actor_plan_info", lambda *_: _Plan())
    monkeypatch.setattr(
        chat,
        "reserve_ai_credits",
        lambda *args, **kwargs: events.append(f"reserve:{kwargs['kind']}"),
    )
    monkeypatch.setattr(
        chat,
        "refund_ai_credits",
        lambda *args, **kwargs: refunds.append(kwargs["kind"]),
    )
    return ws, refunds


def test_legal_websocket_reserves_immediately_before_generation(monkeypatch) -> None:
    events: list[str] = []

    class Service:
        async def answer(self, question, context, *, intent_mode, before_generate):
            assert intent_mode == "legal"
            assert context.purpose == "cung cấp dịch vụ"
            assert context.recipient == "nhà cung cấp Singapore"
            assert context.consent_state == "chưa rõ"
            events.append("answer")
            callback_result = before_generate()
            if inspect.isawaitable(callback_result):
                await callback_result
            events.append("model")
            return _Result()

    ws, refunds = _prepare(monkeypatch, Service(), events)
    asyncio.run(chat.chat_ws(ws, db=object()))

    assert events == ["answer", "reserve:explanation", "model"]
    assert refunds == []
    final = next(item for item in ws.sent if item["type"] == "final")
    assert uuid.UUID(final["message_id"])
    assert "retrieval_trace" not in final
    assert "retrieval_trace" not in final["legal_answer"]
    assert "generation_attempted" not in final["legal_answer"]
    assert "generation_succeeded" not in final["legal_answer"]
    assert final["trace_id"] == "legal-trace-1"
    assert final["retrieval_mode"] == "hybrid"
    assert final["corpus"]["release_id"] == "vn-2026.1"


def test_nonempty_legal_context_forces_legal_mode_over_requested_auto(monkeypatch) -> None:
    events: list[str] = []

    class Service:
        async def answer(self, question, context, *, intent_mode, before_generate):
            assert intent_mode == "legal"
            return _Result(reason_code="missing_required_context", status="need_more_facts")

    ws, refunds = _prepare(
        monkeypatch,
        Service(),
        events,
        intent_mode="auto",
    )
    asyncio.run(chat.chat_ws(ws, db=object()))

    assert events == []
    assert refunds == []
    assert any(item["type"] == "final" for item in ws.sent)


def test_legal_websocket_non_generation_state_costs_no_credit(monkeypatch) -> None:
    events: list[str] = []

    class Service:
        async def answer(self, question, context, *, intent_mode, before_generate):
            return _Result(reason_code="missing_required_context", status="need_more_facts")

    ws, refunds = _prepare(monkeypatch, Service(), events)
    asyncio.run(chat.chat_ws(ws, db=object()))

    assert events == []
    assert refunds == []
    assert any(item["type"] == "final" for item in ws.sent)


def test_legal_websocket_refunds_failed_model_attempt(monkeypatch) -> None:
    events: list[str] = []

    class Service:
        async def answer(self, question, context, *, intent_mode, before_generate):
            before_generate()
            events.append("model_failed")
            return _Result(reason_code="generation_failed", status="insufficient_legal_basis")

    ws, refunds = _prepare(monkeypatch, Service(), events)
    asyncio.run(chat.chat_ws(ws, db=object()))

    assert events == ["reserve:explanation", "model_failed"]
    assert refunds == ["explanation"]
