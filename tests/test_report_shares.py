from __future__ import annotations

import json
import uuid
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.db import SessionLocal, initialize_database
from backend.main import app
from backend.models import ReportShare, ScanEvent, ScanEvidence, User
from backend.security_utils import utcnow
from backend.services.report_share_service import MAX_SNAPSHOT_BYTES, build_redacted_snapshot

client = TestClient(app)


def _register(label: str) -> tuple[str, str]:
    suffix = uuid.uuid4().hex[:10]
    response = client.post("/v1/auth/register", json={
        "displayName": label, "email": f"share-{suffix}@example.test", "password": "StrongPassword123",
    })
    assert response.status_code == 200, response.text
    return response.json()["user"]["id"], response.json()["token"]


def _scan(user_id: str) -> str:
    request_id = f"share-test-{uuid.uuid4().hex}"
    initialize_database()
    with SessionLocal() as db:
        assert db.get(User, user_id) is not None
        scan = ScanEvent(
            request_id=request_id, user_id=user_id, channel="web", modality="url",
            normalized_url="https://private.example/login?token=secret", input_preview="OTP 123456",
            input_sha256="a" * 64, risk_score=0.82, risk_level="danger", decision="BLOCK",
            confidence=0.91, model_version="test", latency_ms=1,
        )
        db.add(scan)
        db.flush()
        db.add(ScanEvidence(
            scan_event_id=scan.id, source="provider", severity="high", feature="credential_theft",
            message="Open https://evil.test/x?api=secret and email owner@example.test with sk_live_12345678901234567890",
        ))
        db.commit()
    return request_id


def test_share_is_private_to_create_hashes_token_and_redacts_snapshot() -> None:
    owner_id, owner_token = _register("Share owner")
    _, other_token = _register("Other user")
    request_id = _scan(owner_id)
    payload = {"requestId": request_id, "expiresIn": "24h"}

    assert client.post("/v1/report-shares", json=payload).status_code == 401
    assert client.post("/v1/report-shares", json=payload, headers={"Authorization": f"Bearer {other_token}"}).status_code == 403
    created = client.post("/v1/report-shares", json=payload, headers={"Authorization": f"Bearer {owner_token}"})
    assert created.status_code == 201, created.text
    token = created.json()["shareToken"]
    assert len(token) >= 40

    with SessionLocal() as db:
        row = db.get(ReportShare, created.json()["id"])
        assert row is not None
        assert row.token_hash != token
        assert len(row.token_hash) == 64
        assert set(row.snapshot) == {"score", "type", "decision", "riskLevel", "confidence", "evidence"}
        serialized = json.dumps(row.snapshot)
        assert "private.example" not in serialized
        assert "evil.test" not in serialized
        assert "owner@example" not in serialized
        assert "sk_live" not in serialized
        assert len(serialized.encode()) <= MAX_SNAPSHOT_BYTES

    public = client.get(f"/v1/report-shares/public/{token}")
    assert public.status_code == 200
    assert public.json()["snapshot"]["score"] == 82
    assert "shareToken" not in public.json()


def test_share_expiry_revocation_and_owner_authorization() -> None:
    owner_id, owner_token = _register("Expiry owner")
    _, other_token = _register("Expiry other")
    request_id = _scan(owner_id)
    created = client.post(
        "/v1/report-shares", json={"requestId": request_id, "expiresIn": "1h"},
        headers={"Authorization": f"Bearer {owner_token}"},
    ).json()
    token, share_id = created["shareToken"], created["id"]

    denied = client.delete(f"/v1/report-shares/{share_id}", headers={"Authorization": f"Bearer {other_token}"})
    assert denied.status_code == 403
    revoked = client.delete(f"/v1/report-shares/{share_id}", headers={"Authorization": f"Bearer {owner_token}"})
    assert revoked.status_code == 204
    assert client.get(f"/v1/report-shares/public/{token}").status_code == 404

    second = client.post(
        "/v1/report-shares", json={"requestId": request_id, "expiresIn": "7d"},
        headers={"Authorization": f"Bearer {owner_token}"},
    ).json()
    with SessionLocal() as db:
        row = db.get(ReportShare, second["id"])
        row.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    expired = client.get(f"/v1/report-shares/public/{second['shareToken']}")
    assert expired.status_code == 410
    assert "hết hạn" in expired.json()["detail"]


def test_share_validates_expiry_and_snapshot_size_bound() -> None:
    owner_id, token = _register("Bounds owner")
    request_id = _scan(owner_id)
    invalid = client.post(
        "/v1/report-shares", json={"requestId": request_id, "expiresIn": "30d"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert invalid.status_code == 422
    with SessionLocal() as db:
        scan = db.execute(select(ScanEvent).where(ScanEvent.request_id == request_id)).scalar_one()
        snapshot = build_redacted_snapshot(scan)
        assert len(json.dumps(snapshot, ensure_ascii=False).encode()) <= MAX_SNAPSHOT_BYTES
