from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, WebSocketDisconnect

from backend.routers import chat
from backend.routers.chat import _load_owned_history_context


class _ScalarResult:
    def __init__(self, row) -> None:
        self.row = row

    def scalar_one_or_none(self):
        return self.row


class _Db:
    def __init__(self, row) -> None:
        self.row = row
        self.statement = None

    def execute(self, statement):
        self.statement = statement
        return _ScalarResult(self.row)


def _scan():
    return SimpleNamespace(
        request_id="scan-owned-123",
        user_id="user-1",
        modality="url",
        risk_score=0.82,
        risk_level="high",
        decision="BLOCK",
        confidence=0.91,
        evidence=[
            SimpleNamespace(
                id="evidence-1",
                source="risk-core",
                message="Tên miền có dấu hiệu giả mạo.",
                severity="high",
                feature="lookalike_domain",
                contribution=0.42,
            ),
            SimpleNamespace(
                id="evidence-2",
                source="legacy",
                message="Mức cũ không còn trong enum.",
                severity="unexpected",
                feature=None,
                contribution=None,
            ),
        ],
    )


def test_history_context_loads_owned_redacted_assessment_without_rescan() -> None:
    db = _Db(_scan())

    row, evidence, assessment = _load_owned_history_context(
        db,
        user_id="user-1",
        request_id="scan-owned-123",
    )

    assert row.request_id == "scan-owned-123"
    assert [item.severity.value for item in evidence] == ["high", "info"]
    assert assessment == {
        "risk_score": 82,
        "risk_level": "high",
        "decision": "BLOCK",
        "confidence": 91,
        "reasons": [
            "Tên miền có dấu hiệu giả mạo.",
            "Mức cũ không còn trong enum.",
        ],
    }
    compiled = db.statement.compile()
    assert compiled.params["request_id_1"] == "scan-owned-123"
    assert compiled.params["user_id_1"] == "user-1"


def test_history_context_requires_login_and_hides_foreign_ownership() -> None:
    with pytest.raises(HTTPException) as anonymous:
        _load_owned_history_context(_Db(_scan()), user_id=None, request_id="scan-owned-123")
    assert anonymous.value.status_code == 401

    with pytest.raises(HTTPException) as missing:
        _load_owned_history_context(
            _Db(None),
            user_id="user-2",
            request_id="scan-owned-123",
        )
    assert missing.value.status_code == 404
    assert "tài khoản" not in str(missing.value.detail).lower()


class _WebSocket:
    def __init__(self) -> None:
        self._payloads = [
            json.dumps(
                {
                    "question": "Tại sao kết quả này bị cảnh báo?",
                    "context": {
                        "content": "",
                        "modality": "text",
                        "analysis_id": "scan-owned-123",
                    },
                }
            )
        ]
        self.sent: list[dict] = []

    async def accept(self) -> None:
        return None

    async def receive_text(self) -> str:
        if not self._payloads:
            raise WebSocketDisconnect()
        return self._payloads.pop(0)

    async def send_text(self, value: str) -> None:
        self.sent.append(json.loads(value))


def test_chat_reuses_owned_history_without_running_analyze(monkeypatch) -> None:
    captured: dict = {}

    class _Explanation:
        llm_ready = False
        available = True

        async def generate(
            self,
            evidence,
            excerpt,
            question,
            *,
            operator_context,
            assessment_context,
        ):
            captured.update(
                evidence=evidence,
                excerpt=excerpt,
                question=question,
                operator_context=operator_context,
                assessment_context=assessment_context,
            )
            yield "Đây là phần giải thích từ kết quả đã lưu."

    class _Legal:
        async def answer(self, *args, **kwargs):
            raise AssertionError("@ID history must not be swallowed by legal Q&A")

    actor = SimpleNamespace(user=SimpleNamespace(id="user-1"))
    plan = SimpleNamespace(chatFollowupLimit=3)
    explanation = _Explanation()
    ws = _WebSocket()

    monkeypatch.setattr(chat, "get_explanation_service", lambda: explanation)
    monkeypatch.setattr(chat, "get_user_explanation_service", lambda *_: explanation)
    monkeypatch.setattr(chat, "get_user_legal_answer_service", lambda *_: _Legal())
    monkeypatch.setattr(chat, "resolve_actor", lambda *_: actor)
    monkeypatch.setattr(chat, "build_actor_plan_info", lambda *_: plan)
    monkeypatch.setattr(
        chat,
        "reserve_ai_credits",
        lambda *_args, **_kwargs: pytest.fail("fallback explanation uses no AI credit"),
    )

    asyncio.run(chat.chat_ws(ws, db=_Db(_scan())))

    assert captured["excerpt"] == "Kết quả lịch sử scan-owned-123"
    assert captured["question"] == "Tại sao kết quả này bị cảnh báo?"
    assert captured["assessment_context"]["risk_score"] == 82
    assert [item.evidence_id for item in captured["evidence"]] == [
        "evidence-1",
        "evidence-2",
    ]
    assert any(item["type"] == "delta" for item in ws.sent)
    final = next(item for item in ws.sent if item["type"] == "final")
    assert final["analysis_id"] == "scan-owned-123"
    assert final["message_id"] == "scan-owned-123"
