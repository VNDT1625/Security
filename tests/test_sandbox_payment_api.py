from __future__ import annotations

import secrets
from datetime import timedelta

from fastapi.testclient import TestClient

from backend.config import settings
from backend.db import SessionLocal
from backend.main import app
from backend.models import CloudSandboxSession
from backend.security_utils import utcnow

client = TestClient(app)


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _settle(reference: str, amount: int, transaction_id: str) -> None:
    response = client.post(
        "/v1/sandbox-cloud/webhooks/sepay",
        headers={"Authorization": "Apikey sandbox-test-key"},
        json={
            "id": transaction_id,
            "transferAmount": amount,
            "transferType": "in",
            "content": reference,
            "referenceCode": transaction_id,
        },
    )
    assert response.status_code == 200
    assert response.json()["success"] is True


def test_cloud_session_rejects_a_second_executable() -> None:
    registration = client.post(
        "/v1/auth/register",
        json={
            "email": f"one-file-{secrets.token_hex(6)}@example.com",
            "password": "StrongPass!123",
            "displayName": "One File Session",
        },
    )
    assert registration.status_code == 200
    body = registration.json()
    session = CloudSandboxSession(
        user_id=body["user"]["id"],
        status="ready",
        provider="aws",
        sandbox_tier="pro",
        expires_at=utcnow() + timedelta(minutes=15),
        sample_status="completed",
        sample_report={"status": "completed"},
    )
    with SessionLocal() as db:
        db.add(session)
        db.commit()
        session_id = session.id

    duplicate = client.post(
        f"/v1/sandbox-cloud/sessions/{session_id}/exe",
        headers=_headers(body["token"]),
        files={"file": ("second.exe", b"MZdemo", "application/octet-stream")},
        data={"consent": "true"},
    )

    assert duplicate.status_code == 409
    assert "chỉ phân tích một file" in duplicate.json()["detail"]


def test_sepay_team_and_credit_flow_unlocks_max_without_charging_unconfigured_aws(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "sepay_webhook_secret", "")
    monkeypatch.setattr(settings, "sepay_webhook_api_key", "sandbox-test-key")
    monkeypatch.setattr(settings, "sepay_bank_account", "123456789")
    monkeypatch.setattr(settings, "sepay_bank_name", "TestBank")
    monkeypatch.setattr(settings, "sepay_account_name", "PREWISE TEST")
    monkeypatch.setattr(settings, "aws_sandbox_max_ami_id", "")
    monkeypatch.setattr(settings, "aws_sandbox_subnet_id", "")
    monkeypatch.setattr(settings, "aws_sandbox_security_group_id", "")

    email = f"sandbox-{secrets.token_hex(6)}@example.com"
    registration = client.post(
        "/v1/auth/register",
        json={
            "email": email,
            "password": "StrongPass!123",
            "displayName": "Sandbox Buyer",
        },
    )
    assert registration.status_code == 200
    token = registration.json()["token"]
    headers = _headers(token)

    subscription = client.post(
        "/v1/sandbox-cloud/subscription-payments",
        headers=headers,
        json={"planTier": "team", "billingPeriod": "monthly"},
    )
    assert subscription.status_code == 200
    subscription_body = subscription.json()
    assert subscription_body["amountVnd"] == 29_000
    assert subscription_body["planTier"] == "team"
    assert subscription_body["includedCredits"] == 6
    assert subscription_body["qrUrl"]

    _settle(
        subscription_body["reference"],
        subscription_body["amountVnd"],
        f"sub-{secrets.token_hex(8)}",
    )

    status = client.get("/v1/sandbox-cloud/status", headers=headers)
    assert status.status_code == 200
    assert status.json()["accountTier"] == "max"
    assert status.json()["credits"] == 6

    credit_order = client.post(
        "/v1/sandbox-cloud/payments",
        headers=headers,
        json={"credits": 1},
    )
    assert credit_order.status_code == 200
    credit_body = credit_order.json()
    assert credit_body["credits"] == 1
    assert credit_body["qrUrl"]

    pending = client.get(
        f"/v1/sandbox-cloud/payments/{credit_body['orderId']}",
        headers=headers,
    )
    assert pending.status_code == 200
    assert pending.json()["status"] == "pending"

    _settle(
        credit_body["reference"],
        credit_body["amountVnd"],
        f"credit-{secrets.token_hex(8)}",
    )

    paid_status = client.get("/v1/sandbox-cloud/status", headers=headers)
    assert paid_status.status_code == 200
    assert paid_status.json()["credits"] == 7

    unavailable = client.post(
        "/v1/sandbox-cloud/sessions",
        headers=headers,
        json={"tier": "max"},
    )
    assert unavailable.status_code == 503
    assert "chưa được cấu hình" in unavailable.json()["detail"]

    after_failure = client.get("/v1/sandbox-cloud/status", headers=headers)
    assert after_failure.status_code == 200
    assert after_failure.json()["credits"] == 7


def test_active_pro_account_cannot_buy_pro_again(monkeypatch) -> None:
    monkeypatch.setattr(settings, "sepay_webhook_secret", "")
    monkeypatch.setattr(settings, "sepay_webhook_api_key", "sandbox-test-key")
    monkeypatch.setattr(settings, "sepay_bank_account", "123456789")
    monkeypatch.setattr(settings, "sepay_bank_name", "TestBank")
    monkeypatch.setattr(settings, "sepay_account_name", "PREWISE TEST")

    email = f"existing-paid-{secrets.token_hex(6)}@example.com"
    registration = client.post(
        "/v1/auth/register",
        json={"email": email, "password": "StrongPass!123", "displayName": "Existing Pro"},
    )
    headers = _headers(registration.json()["token"])
    first = client.post(
        "/v1/sandbox-cloud/subscription-payments",
        headers=headers,
        json={"planTier": "pro", "billingPeriod": "monthly"},
    )
    assert first.status_code == 200
    body = first.json()
    _settle(body["reference"], body["amountVnd"], f"pro-{secrets.token_hex(8)}")

    duplicate = client.post(
        "/v1/sandbox-cloud/subscription-payments",
        headers=headers,
        json={"planTier": "pro", "billingPeriod": "monthly"},
    )
    assert duplicate.status_code == 409
    assert "không cần mua lại" in duplicate.json()["detail"]


def test_sepay_can_match_reference_from_code_field(monkeypatch) -> None:
    monkeypatch.setattr(settings, "sepay_webhook_secret", "")
    monkeypatch.setattr(settings, "sepay_webhook_api_key", "sandbox-test-key")
    monkeypatch.setattr(settings, "sepay_bank_account", "123456789")
    monkeypatch.setattr(settings, "sepay_bank_name", "TestBank")
    monkeypatch.setattr(settings, "sepay_account_name", "PREWISE TEST")

    email = f"code-field-{secrets.token_hex(6)}@example.com"
    registration = client.post(
        "/v1/auth/register",
        json={"email": email, "password": "StrongPass!123", "displayName": "Code Field"},
    )
    headers = _headers(registration.json()["token"])
    order = client.post(
        "/v1/sandbox-cloud/subscription-payments",
        headers=headers,
        json={"planTier": "pro", "billingPeriod": "monthly"},
    ).json()
    settled = client.post(
        "/v1/sandbox-cloud/webhooks/sepay",
        headers={"Authorization": "Apikey sandbox-test-key"},
        json={
            "id": f"code-{secrets.token_hex(8)}",
            "transferAmount": order["amountVnd"],
            "transferType": "in",
            "content": "chuyen tien",
            "code": order["reference"],
        },
    )
    assert settled.status_code == 200
    status = client.get(
        f"/v1/sandbox-cloud/subscription-payments/{order['orderId']}", headers=headers,
    )
    assert status.json()["status"] == "paid"
