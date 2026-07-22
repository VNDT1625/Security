from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.db import SessionLocal, initialize_database
from backend.main import app
from backend.models import ScanEvent, User, UserFeedback

client = TestClient(app)


def _register(label: str) -> tuple[str, str]:
    suffix = uuid.uuid4().hex[:10]
    email = f"feedback-{suffix}@example.test"
    response = client.post(
        "/v1/auth/register",
        json={"displayName": label, "email": email, "password": "StrongPassword123"},
    )
    assert response.status_code == 200, response.text
    return response.json()["user"]["id"], response.json()["token"]


def _scan(user_id: str) -> str:
    request_id = f"feedback-test-{uuid.uuid4().hex}"
    initialize_database()
    with SessionLocal() as db:
        assert db.get(User, user_id) is not None
        db.add(
            ScanEvent(
                request_id=request_id,
                user_id=user_id,
                channel="web",
                modality="url",
                normalized_url="https://example.test",
                risk_score=82,
                risk_level="danger",
                decision="block",
                confidence=0.9,
                model_version="test",
                latency_ms=1,
            )
        )
        db.commit()
    return request_id


def test_feedback_is_authenticated_private_redacted_and_idempotent() -> None:
    user_id, token = _register("Feedback owner")
    _, other_token = _register("Other user")
    request_id = _scan(user_id)
    payload = {
        "requestId": request_id,
        "feedbackType": "false_positive",
        "reason": "incorrect_verdict",
        "details": "Liên hệ owner@example.com, +84 912 345 678 tại https://evil.test/login?otp=123",
        "idempotencyKey": f"feedback-{uuid.uuid4().hex}",
    }

    assert client.post("/v1/feedback", json=payload).status_code == 401
    assert client.post(
        "/v1/feedback", json=payload, headers={"Authorization": f"Bearer {other_token}"}
    ).status_code == 403

    headers = {"Authorization": f"Bearer {token}"}
    created = client.post("/v1/feedback", json=payload, headers=headers)
    assert created.status_code == 201, created.text
    duplicate = client.post("/v1/feedback", json=payload, headers=headers)
    assert duplicate.status_code == 200
    assert duplicate.json()["id"] == created.json()["id"]

    with SessionLocal() as db:
        rows = db.execute(
            select(UserFeedback).where(UserFeedback.id == created.json()["id"])
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].comment == "Liên hệ [email đã ẩn], [số điện thoại đã ẩn] tại [URL đã ẩn]"
        assert rows[0].comment_sha256 is not None
        assert rows[0].idempotency_key != payload["idempotencyKey"]


def test_feedback_validates_type_reason_and_request() -> None:
    user_id, token = _register("Validation owner")
    request_id = _scan(user_id)
    headers = {"Authorization": f"Bearer {token}"}
    invalid = client.post(
        "/v1/feedback",
        headers=headers,
        json={"requestId": request_id, "feedbackType": "anything", "reason": "unknown"},
    )
    assert invalid.status_code == 422
    mismatched_reason = client.post(
        "/v1/feedback",
        headers=headers,
        json={"requestId": request_id, "feedbackType": "report_site", "reason": "missed_threat"},
    )
    assert mismatched_reason.status_code == 422
    missing = client.post(
        "/v1/feedback",
        headers=headers,
        json={"requestId": f"missing-{uuid.uuid4().hex}", "feedbackType": "report_site", "reason": "suspicious_site"},
    )
    assert missing.status_code == 404
