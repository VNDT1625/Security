from __future__ import annotations

import secrets
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.db import SessionLocal
from backend.main import app
from backend.models import CloudSandboxSession
from backend.routers import sandbox_cloud
from backend.security_utils import utcnow
from backend.services.cloud_sandbox_service import CloudSandboxService


client = TestClient(app)
_DEFAULT_PROVIDER_INSTANCE_ID = object()


def _register(label: str) -> tuple[str, str]:
    response = client.post(
        "/v1/auth/register",
        json={
            "email": f"{label}-{secrets.token_hex(6)}@example.test",
            "password": "StrongPass!123",
            "displayName": label,
        },
    )
    assert response.status_code == 200
    body = response.json()
    return body["user"]["id"], body["token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _ready_interactive_row(
    user_id: str,
    *,
    provider_instance_id: str | None | object = _DEFAULT_PROVIDER_INSTANCE_ID,
    with_lease: bool = True,
) -> CloudSandboxSession:
    now = utcnow()
    lease = now + timedelta(minutes=5) if with_lease else None
    resolved_instance_id = (
        f"i-interactive-{secrets.token_hex(8)}"
        if provider_instance_id is _DEFAULT_PROVIDER_INSTANCE_ID
        else provider_instance_id
    )
    return CloudSandboxSession(
        user_id=user_id,
        status="ready",
        provider="aws",
        sandbox_tier="pro",
        mode="interactive",
        lease_minutes=5,
        provider_instance_id=resolved_instance_id,
        remote_url="https://broker.example.test/connect/session",
        ready_at=now,
        lease_expires_at=lease,
        expires_at=lease or now + timedelta(minutes=5),
        sample_status="staged",
        sample_report={"mode": "interactive", "phase": "staged"},
    )


def _healthy_broker() -> dict:
    return {"available": True, "reason": None, "missing": []}


def test_broker_health_contract_requires_all_security_capabilities() -> None:
    service = CloudSandboxService()
    payload = {
        "status": "ok",
        "ready": True,
        "protocolVersion": "1",
        "capabilities": [
            "one_time_token_consume",
            "lease_enforcement",
            "remote_desktop",
        ],
    }

    assert service._validate_broker_health_payload(payload) == (True, None)

    without_disconnect_boundary = dict(payload)
    without_disconnect_boundary["capabilities"] = [
        "one_time_token_consume",
        "remote_desktop",
    ]
    assert service._validate_broker_health_payload(without_disconnect_boundary) == (
        False,
        "broker_health_not_ready",
    )


def test_broker_health_probe_is_cached_for_status_polling(monkeypatch) -> None:
    service = CloudSandboxService()
    service.clear_broker_health_cache()
    calls: list[str] = []

    def probe(url: str) -> tuple[bool, str | None]:
        calls.append(url)
        return True, None

    monkeypatch.setattr(CloudSandboxService, "_probe_broker_health", staticmethod(probe))
    url = "https://broker.example.test/healthz"

    assert service._broker_health_status(url) == (True, None)
    assert service._broker_health_status(url) == (True, None)
    assert calls == [url]


@pytest.mark.parametrize(
    ("url", "environment"),
    [
        ("http://broker.example.test/connect", "development"),
        ("http://localhost:8080/connect", "production"),
        ("https://demo.trycloudflare.com/connect", "production"),
        ("https://user:password@broker.example.test/connect", "production"),
        ("https://broker.example.test/connect?prewise_access_token=old", "production"),
        ("https://broker.example.test:invalid/connect", "production"),
    ],
)
def test_remote_url_rejects_unsafe_browser_targets(
    monkeypatch,
    url: str,
    environment: str,
) -> None:
    monkeypatch.setattr(settings, "app_env", environment)

    with pytest.raises(RuntimeError):
        CloudSandboxService._validated_remote_url(url)


def test_availability_rejects_unknown_template_before_ec2_launch(monkeypatch) -> None:
    service = CloudSandboxService()
    monkeypatch.setattr(settings, "aws_sandbox_interactive_ami_id", "ami-interactive")
    monkeypatch.setattr(settings, "aws_sandbox_subnet_id", "subnet-private")
    monkeypatch.setattr(
        settings,
        "aws_sandbox_interactive_security_group_id",
        "sg-interactive",
    )
    monkeypatch.setattr(settings, "sandbox_public_base_url", "https://api.example.test")
    monkeypatch.setattr(
        settings,
        "sandbox_remote_broker_url_template",
        "https://broker.example.test/connect/{unsupported}",
    )
    monkeypatch.setattr(settings, "aws_sandbox_remote_url_tag", "")
    monkeypatch.setattr(settings, "sandbox_remote_broker_secret", "s" * 40)
    monkeypatch.setattr(
        settings,
        "sandbox_remote_broker_health_url",
        "https://broker.example.test/healthz",
    )
    monkeypatch.setattr(
        service,
        "_broker_health_status",
        lambda _url: pytest.fail("health must not be probed for an invalid template"),
    )

    assert service.availability("pro", "interactive") == {
        "available": False,
        "reason": "invalid_remote_url_template",
        "missing": [],
    }


@pytest.mark.parametrize(
    ("provider_instance_id", "with_lease"),
    [(None, True), (f"i-interactive-{secrets.token_hex(8)}", False)],
)
def test_issue_remote_access_requires_instance_and_explicit_lease(
    monkeypatch,
    provider_instance_id: str | None,
    with_lease: bool,
) -> None:
    monkeypatch.setattr(settings, "sandbox_remote_broker_secret", "s" * 40)
    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "broker_availability",
        _healthy_broker,
    )
    user_id, token = _register("Remote fail closed")
    row = _ready_interactive_row(
        user_id,
        provider_instance_id=provider_instance_id,
        with_lease=with_lease,
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    response = client.post(
        f"/v1/sandbox-cloud/sessions/{session_id}/remote-access",
        headers=_auth(token),
    )

    assert response.status_code == 503
    with SessionLocal() as db:
        stored = db.get(CloudSandboxSession, session_id)
        assert stored is not None
        assert stored.remote_access_token_hash is None


def test_status_turns_remote_off_when_broker_runtime_is_lost(monkeypatch) -> None:
    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "broker_availability",
        lambda: {
            "available": False,
            "reason": "broker_health_unreachable",
            "missing": [],
        },
    )
    user_id, token = _register("Broker lost")
    row = _ready_interactive_row(user_id)
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    response = client.get(
        f"/v1/sandbox-cloud/sessions/{session_id}",
        headers=_auth(token),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["remoteAvailable"] is False
    assert body["remoteStatus"] == "unavailable"
    assert body["remoteUnavailableReason"] == "broker_health_unreachable"
    assert body["remoteUrl"] is None


def test_second_remote_token_invalidates_first_and_responses_are_not_cached(
    monkeypatch,
) -> None:
    broker_secret = "s" * 40
    monkeypatch.setattr(settings, "sandbox_remote_broker_secret", broker_secret)
    monkeypatch.setattr(settings, "sandbox_remote_access_token_ttl_seconds", 45)
    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "broker_availability",
        _healthy_broker,
    )
    user_id, token = _register("Token rotation")
    row = _ready_interactive_row(user_id)
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    first = client.post(
        f"/v1/sandbox-cloud/sessions/{session_id}/remote-access",
        headers=_auth(token),
    )
    second = client.post(
        f"/v1/sandbox-cloud/sessions/{session_id}/remote-access",
        headers=_auth(token),
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.headers["cache-control"] == "no-store"
    assert second.headers["cache-control"] == "no-store"
    assert first.json()["accessToken"] != second.json()["accessToken"]

    old_token = client.post(
        "/v1/sandbox-cloud/broker/remote-access/consume",
        headers={"X-Sandbox-Broker-Secret": broker_secret},
        json={
            "sessionId": session_id,
            "accessToken": first.json()["accessToken"],
        },
    )
    current_token = client.post(
        "/v1/sandbox-cloud/broker/remote-access/consume",
        headers={"X-Sandbox-Broker-Secret": broker_secret},
        json={
            "sessionId": session_id,
            "accessToken": second.json()["accessToken"],
        },
    )

    assert old_token.status_code == 401
    assert current_token.status_code == 200
    assert "password" not in current_token.json()
    assert "remoteUrl" not in current_token.json()


def test_broker_consume_rejects_weak_configured_secret(monkeypatch) -> None:
    monkeypatch.setattr(settings, "sandbox_remote_broker_secret", "too-short")

    response = client.post(
        "/v1/sandbox-cloud/broker/remote-access/consume",
        headers={"X-Sandbox-Broker-Secret": "too-short"},
        json={
            "sessionId": secrets.token_hex(16),
            "accessToken": "a" * 32,
        },
    )

    assert response.status_code == 503
