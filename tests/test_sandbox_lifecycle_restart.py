from __future__ import annotations

import asyncio
import secrets
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from backend.db import SessionLocal
from backend.main import app
from backend.models import CloudSandboxSession, SandboxWallet
from backend.routers import sandbox_cloud
from backend.security_utils import utcnow

client = TestClient(app)


def _register(label: str) -> str:
    response = client.post(
        "/v1/auth/register",
        json={
            "email": f"{label}-{secrets.token_hex(5)}@example.com",
            "password": "StrongPass!123",
            "displayName": label,
        },
    )
    assert response.status_code == 200
    return response.json()["user"]["id"]


@pytest.fixture(autouse=True)
def close_sessions_from_other_contract_tests() -> None:
    """The process-owned SQLite DB is shared by tests but lifecycle work is not."""

    now = utcnow()
    with SessionLocal() as db:
        db.execute(
            update(CloudSandboxSession)
            .where(CloudSandboxSession.status.in_(sandbox_cloud.ACTIVE_SESSION_STATES))
            .values(
                status="terminated",
                cleanup_completed_at=now,
                terminated_at=now,
                remote_url=None,
                remote_access_token_hash=None,
                remote_access_token_expires_at=None,
            )
        )
        db.commit()


def test_restart_recovers_interrupted_provisioning_without_launching_a_vm(
    monkeypatch,
) -> None:
    user_id = _register("Restart provisioning")
    row = CloudSandboxSession(
        user_id=user_id,
        status="provisioning",
        provider="aws",
        sandbox_tier="pro",
        mode="auto",
        lease_minutes=15,
        expires_at=utcnow() + timedelta(minutes=20),
        remote_access_token_hash="a" * 64,
        remote_access_token_expires_at=utcnow() + timedelta(seconds=30),
    )
    with SessionLocal() as db:
        wallet = db.get(SandboxWallet, user_id)
        if wallet is None:
            wallet = SandboxWallet(user_id=user_id, credits=4)
            db.add(wallet)
        else:
            wallet.credits = 4
        db.add(row)
        db.commit()
        session_id = row.id

    recovered: list[str] = []
    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "terminate_session_instances",
        lambda value: recovered.append(value) or ["i-recovered-by-tag"],
    )
    result = asyncio.run(
        sandbox_cloud.reconcile_cloud_sandbox_sessions_after_restart(
            provisioning_grace_seconds=0
        )
    )

    assert result["provisioningRecovered"] == 1
    assert recovered == [session_id]
    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        wallet = db.get(SandboxWallet, user_id)
        assert current is not None
        assert current.status == "terminated"
        assert current.termination_reason == "provisioning_interrupted"
        assert current.provider_instance_id == "i-recovered-by-tag"
        assert current.cleanup_completed_at is not None
        assert current.remote_access_token_hash is None
        assert current.sample_report["credit_refund_amount"] == 1
        assert wallet is not None and wallet.credits == 5


def test_restart_reclaims_a_fresh_terminating_claim_immediately(monkeypatch) -> None:
    user_id = _register("Restart terminating")
    instance_id = f"i-{secrets.token_hex(6)}"
    row = CloudSandboxSession(
        user_id=user_id,
        status="terminating",
        provider="aws",
        provider_instance_id=instance_id,
        sandbox_tier="pro",
        mode="interactive",
        lease_minutes=5,
        expires_at=utcnow() + timedelta(minutes=5),
        termination_reason="user_requested",
        termination_requested_at=utcnow(),
        remote_url="https://broker.example.test/session",
        remote_access_token_hash="b" * 64,
        remote_access_token_expires_at=utcnow() + timedelta(seconds=30),
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    terminated: list[str] = []
    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "terminate",
        lambda value: terminated.append(value),
    )
    result = asyncio.run(
        sandbox_cloud.reconcile_cloud_sandbox_sessions_after_restart(
            provisioning_grace_seconds=0
        )
    )

    assert result["cleanupRecovered"] == 1
    assert terminated == [instance_id]
    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        assert current is not None
        assert current.status == "terminated"
        assert current.remote_url is None
        assert current.remote_access_token_hash is None
        assert current.cleanup_completed_at is not None


def test_restart_expires_ready_lease_and_revokes_remote_access(monkeypatch) -> None:
    user_id = _register("Restart expired")
    instance_id = f"i-{secrets.token_hex(6)}"
    expired = utcnow() - timedelta(seconds=1)
    row = CloudSandboxSession(
        user_id=user_id,
        status="ready",
        provider="aws",
        provider_instance_id=instance_id,
        sandbox_tier="pro",
        mode="interactive",
        lease_minutes=5,
        expires_at=expired,
        lease_expires_at=expired,
        remote_url="https://broker.example.test/session",
        remote_access_token_hash="c" * 64,
        remote_access_token_expires_at=utcnow() + timedelta(seconds=30),
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    terminated: list[str] = []
    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "terminate",
        lambda value: terminated.append(value),
    )
    result = asyncio.run(
        sandbox_cloud.reconcile_cloud_sandbox_sessions_after_restart(
            provisioning_grace_seconds=0
        )
    )

    assert result["expiredRecovered"] == 1
    assert terminated == [instance_id]
    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        assert current is not None
        assert current.status == "expired"
        assert current.termination_reason == "lease_expired"
        assert current.remote_url is None
        assert current.remote_access_token_hash is None
