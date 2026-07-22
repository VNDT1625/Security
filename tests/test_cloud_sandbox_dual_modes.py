from __future__ import annotations

import asyncio
import hashlib
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.db import SessionLocal
from backend.main import app
from backend.models import CloudSandboxSession
from backend.routers import sandbox_cloud
from backend.security_utils import utcnow

client = TestClient(app)


def _register(label: str) -> tuple[str, str]:
    response = client.post(
        "/v1/auth/register",
        json={
            "email": f"{label}-{secrets.token_hex(5)}@example.com",
            "password": "StrongPass!123",
            "displayName": label,
        },
    )
    assert response.status_code == 200
    body = response.json()
    return body["user"]["id"], body["token"]


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_agent_bootstrap_download_is_authenticated_during_provisioning() -> None:
    user_id, _auth_token = _register("Bootstrap agent")
    agent_token = secrets.token_urlsafe(32)
    row = CloudSandboxSession(
        user_id=user_id,
        status="provisioning",
        provider="aws",
        sandbox_tier="pro",
        mode="auto",
        lease_minutes=15,
        agent_token_hash=hashlib.sha256(agent_token.encode("utf-8")).hexdigest(),
        expires_at=utcnow() + timedelta(minutes=20),
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    endpoint = f"/v1/sandbox-cloud/agent/sessions/{session_id}/bootstrap"
    rejected = client.get(
        endpoint,
        headers={"X-Sandbox-Agent-Token": "wrong-token"},
    )
    assert rejected.status_code == 401

    delivered = client.get(
        endpoint,
        headers={"X-Sandbox-Agent-Token": agent_token},
    )
    assert delivered.status_code == 200
    assert "text/plain" in delivered.headers["content-type"]
    assert b"PREWISE_SANDBOX_TOKEN" in delivered.content
    assert len(delivered.content) > 1_000
    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        assert current is not None
        assert current.sample_report["agent_bootstrap_at"]


def test_interactive_remote_access_is_short_lived_bound_and_one_time(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "sandbox_remote_broker_secret", "s" * 40)
    monkeypatch.setattr(settings, "sandbox_remote_access_token_ttl_seconds", 45)
    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "broker_availability",
        lambda: {"available": True, "reason": None, "missing": []},
    )
    user_id, auth_token = _register("Interactive owner")
    now = utcnow()
    row = CloudSandboxSession(
        user_id=user_id,
        status="ready",
        provider="aws",
        sandbox_tier="pro",
        mode="interactive",
        lease_minutes=5,
        provider_instance_id=f"i-{secrets.token_hex(6)}",
        remote_url="https://broker.example.test/connect/interactive-session",
        ready_at=now,
        lease_expires_at=now + timedelta(minutes=5),
        expires_at=now + timedelta(minutes=5),
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    state = client.get(
        f"/v1/sandbox-cloud/sessions/{session_id}",
        headers=_headers(auth_token),
    )
    assert state.status_code == 200
    assert state.json()["remoteAvailable"] is False
    assert state.json()["remoteUnavailableReason"] == "sample_staging"
    assert state.json()["remoteUrl"] is None

    with SessionLocal() as db:
        staged = db.get(CloudSandboxSession, session_id)
        assert staged is not None
        staged.sample_status = "staged"
        staged.sample_report = {"mode": "interactive", "phase": "staged"}
        db.commit()
    ready_state = client.get(
        f"/v1/sandbox-cloud/sessions/{session_id}",
        headers=_headers(auth_token),
    )
    assert ready_state.json()["remoteAvailable"] is True

    issued = client.post(
        f"/v1/sandbox-cloud/sessions/{session_id}/remote-access",
        headers=_headers(auth_token),
    )
    assert issued.status_code == 200
    access = issued.json()
    assert access["oneTime"] is True
    assert access["connectUrl"] == access["remoteUrl"]
    assert "prewise_access_token=" in access["connectUrl"]
    assert "rdp" not in access

    with SessionLocal() as db:
        persisted = db.get(CloudSandboxSession, session_id)
        assert persisted is not None
        assert persisted.remote_access_token_hash == hashlib.sha256(
            access["accessToken"].encode("utf-8")
        ).hexdigest()
        assert access["accessToken"] not in str(persisted.remote_access_token_hash)

    consumed = client.post(
        "/v1/sandbox-cloud/broker/remote-access/consume",
        headers={"X-Sandbox-Broker-Secret": "s" * 40},
        json={
            "sessionId": session_id,
            "accessToken": access["accessToken"],
        },
    )
    assert consumed.status_code == 200
    assert consumed.json()["authorized"] is True
    assert consumed.json()["userId"] == user_id
    assert "password" not in consumed.json()

    replay = client.post(
        "/v1/sandbox-cloud/broker/remote-access/consume",
        headers={"X-Sandbox-Broker-Secret": "s" * 40},
        json={
            "sessionId": session_id,
            "accessToken": access["accessToken"],
        },
    )
    assert replay.status_code == 401


def test_agent_contract_stages_interactive_sample_before_completion(
    tmp_path,
) -> None:
    user_id, _auth_token = _register("Interactive agent")
    agent_token = secrets.token_urlsafe(32)
    sample_path = tmp_path / "sample.exe"
    sample_path.write_bytes(b"MZ-safe-contract-fixture")
    now = utcnow()
    row = CloudSandboxSession(
        user_id=user_id,
        status="provisioning",
        provider="aws",
        sandbox_tier="pro",
        mode="interactive",
        lease_minutes=5,
        provider_instance_id=f"i-{secrets.token_hex(6)}",
        remote_url="https://broker.example.test/connect/agent-session",
        expires_at=now + timedelta(minutes=15),
        agent_token_hash=hashlib.sha256(agent_token.encode("utf-8")).hexdigest(),
        sample_filename="sample.exe",
        sample_storage_path=str(sample_path),
        sample_status="queued",
        sample_report={"mode": "interactive", "phase": "queued"},
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    agent_headers = {"X-Sandbox-Agent-Token": agent_token}
    too_early = client.get(
        f"/v1/sandbox-cloud/agent/sessions/{session_id}/exe",
        headers=agent_headers,
    )
    assert too_early.status_code == 425

    with SessionLocal() as db:
        ready = db.get(CloudSandboxSession, session_id)
        assert ready is not None
        ready.status = "ready"
        ready.ready_at = utcnow()
        ready.lease_expires_at = ready.ready_at + timedelta(minutes=5)
        ready.expires_at = ready.lease_expires_at
        db.commit()

    download = client.get(
        f"/v1/sandbox-cloud/agent/sessions/{session_id}/exe",
        headers=agent_headers,
    )
    assert download.status_code == 200
    assert download.headers["x-sandbox-mode"] == "interactive"
    assert download.headers["x-sandbox-auto-execute"] == "false"
    assert 0 < int(download.headers["x-sandbox-lease-seconds"]) <= 300

    for phase in ("staged", "running"):
        report = client.post(
            f"/v1/sandbox-cloud/agent/sessions/{session_id}/report",
            headers=agent_headers,
            json={"status": phase, "phase": phase, "mode": "interactive"},
        )
        assert report.status_code == 200
        assert report.json()["phase"] == phase
        with SessionLocal() as db:
            current = db.get(CloudSandboxSession, session_id)
            assert current is not None
            assert current.sample_status == phase
            assert current.sample_completed_at is None

    completed = client.post(
        f"/v1/sandbox-cloud/agent/sessions/{session_id}/report",
        headers=agent_headers,
        json={
            "status": "completed",
            "phase": "completed",
            "mode": "interactive",
            "verdict": "needs_review",
        },
    )
    assert completed.status_code == 200
    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        assert current is not None
        assert current.sample_status == "completed"
        assert current.sample_completed_at is not None
        assert current.sample_report["mode"] == "interactive"
        assert current.sample_report["phase"] == "completed"


def test_paid_lease_clock_starts_only_after_provider_readiness(monkeypatch) -> None:
    user_id, _auth_token = _register("Ready clock")
    agent_token = secrets.token_urlsafe(32)
    created_at = utcnow() - timedelta(minutes=2)
    row = CloudSandboxSession(
        user_id=user_id,
        status="provisioning",
        provider="aws",
        sandbox_tier="pro",
        mode="interactive",
        lease_minutes=5,
        agent_token_hash=hashlib.sha256(agent_token.encode("utf-8")).hexdigest(),
        expires_at=utcnow() + timedelta(minutes=13),
        created_at=created_at,
        sample_report={"agent_bootstrap_at": utcnow().isoformat()},
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    def provision(*_args):
        return "i-ready-clock", "https://broker.example.test/connect/ready-clock"

    monkeypatch.setattr(sandbox_cloud.cloud_sandbox_service, "provision", provision)
    asyncio.run(sandbox_cloud.provision_task(session_id, agent_token))

    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        assert current is not None
        assert current.status == "ready"
        assert current.ready_at is not None
        assert current.ready_at > created_at
        assert current.lease_expires_at is not None
        assert int((current.lease_expires_at - current.ready_at).total_seconds()) == 300
        assert current.expires_at == current.lease_expires_at
        assert current.remote_url == "https://broker.example.test/connect/ready-clock"


def test_failed_termination_revokes_remote_access_and_stays_fail_visible(
    monkeypatch,
) -> None:
    user_id, auth_token = _register("Cleanup failure")
    now = utcnow()
    row = CloudSandboxSession(
        user_id=user_id,
        status="ready",
        provider="aws",
        sandbox_tier="pro",
        mode="interactive",
        lease_minutes=5,
        provider_instance_id=f"i-{secrets.token_hex(6)}",
        remote_url="https://broker.example.test/connect/cleanup-failure",
        remote_access_token_hash="a" * 64,
        remote_access_token_expires_at=now + timedelta(seconds=30),
        ready_at=now,
        lease_expires_at=now + timedelta(minutes=5),
        expires_at=now + timedelta(minutes=5),
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    def fail_terminate(_instance_id: str) -> None:
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "terminate",
        fail_terminate,
    )
    stopped = client.delete(
        f"/v1/sandbox-cloud/sessions/{session_id}",
        headers=_headers(auth_token),
    )
    assert stopped.status_code == 200
    assert stopped.json()["cleanupPending"] is True

    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        assert current is not None
        assert current.status == "cleanup_failed"
        assert current.termination_reason == "user_requested"
        assert current.remote_url is None
        assert current.remote_access_token_hash is None
        assert current.cleanup_completed_at is None


def test_auto_final_report_persists_evidence_then_cleans_worker(monkeypatch) -> None:
    user_id, auth_token = _register("Auto cleanup")
    agent_token = secrets.token_urlsafe(32)
    instance_id = f"i-{secrets.token_hex(6)}"
    terminated: list[str] = []
    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "terminate",
        lambda value: terminated.append(value),
    )
    now = utcnow()
    row = CloudSandboxSession(
        user_id=user_id,
        status="ready",
        provider="aws",
        sandbox_tier="pro",
        mode="auto",
        lease_minutes=15,
        provider_instance_id=instance_id,
        ready_at=now,
        lease_expires_at=now + timedelta(minutes=15),
        expires_at=now + timedelta(minutes=15),
        agent_token_hash=hashlib.sha256(agent_token.encode("utf-8")).hexdigest(),
        sample_filename="sample.exe",
        sample_status="delivered",
        sample_report={"mode": "auto", "phase": "delivered"},
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    completed = client.post(
        f"/v1/sandbox-cloud/agent/sessions/{session_id}/report",
        headers={"X-Sandbox-Agent-Token": agent_token},
        json={
            "status": "completed",
            "mode": "auto",
            "verdict": "no_obvious_behavior",
            "summary": "evidence retained after VM cleanup",
        },
    )

    assert completed.status_code == 200
    assert completed.json()["cleanupScheduled"] is True
    assert terminated == [instance_id]
    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        assert current is not None
        assert current.status == "terminated"
        assert current.termination_reason == "auto_analysis_completed"
        assert current.cleanup_completed_at is not None
        assert current.sample_report["verdict"] == "no_obvious_behavior"
        assert current.sample_report["summary"] == "evidence retained after VM cleanup"

    status = client.get(
        "/v1/sandbox-cloud/status",
        headers=_headers(auth_token),
    )
    assert status.status_code == 200
    assert status.json()["session"] is None
    assert status.json()["recentSession"]["id"] == session_id
    assert (
        status.json()["recentSession"]["sample"]["report"]["verdict"]
        == "no_obvious_behavior"
    )


def test_interactive_agent_can_finalize_inside_post_lease_grace(monkeypatch) -> None:
    monkeypatch.setattr(settings, "sandbox_agent_report_grace_seconds", 15)
    user_id, _auth_token = _register("Report grace")
    agent_token = secrets.token_urlsafe(32)
    instance_id = f"i-{secrets.token_hex(6)}"
    now = utcnow()
    row = CloudSandboxSession(
        user_id=user_id,
        status="termination_requested",
        provider="aws",
        sandbox_tier="pro",
        mode="interactive",
        lease_minutes=5,
        provider_instance_id=instance_id,
        ready_at=now - timedelta(minutes=5, seconds=5),
        lease_expires_at=now - timedelta(seconds=5),
        expires_at=now - timedelta(seconds=5),
        termination_reason="lease_expired",
        termination_requested_at=now - timedelta(seconds=5),
        agent_token_hash=hashlib.sha256(agent_token.encode("utf-8")).hexdigest(),
        sample_status="running",
        sample_report={"mode": "interactive", "phase": "running"},
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    final_report = client.post(
        f"/v1/sandbox-cloud/agent/sessions/{session_id}/report",
        headers={"X-Sandbox-Agent-Token": agent_token},
        json={
            "status": "completed",
            "mode": "interactive",
            "verdict": "manual_review_complete",
        },
    )
    assert final_report.status_code == 200
    assert final_report.json()["cleanupScheduled"] is False

    terminated: list[str] = []
    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "terminate",
        lambda value: terminated.append(value),
    )
    asyncio.run(sandbox_cloud.cleanup_session_by_id(session_id))
    assert terminated == [instance_id]
    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        assert current is not None
        assert current.status == "expired"
        assert current.sample_status == "completed"
        assert current.sample_report["verdict"] == "manual_review_complete"


def test_restart_cleanup_finds_worker_by_session_tag_when_instance_id_was_not_saved(
    monkeypatch,
) -> None:
    user_id, _auth_token = _register("Restart recovery")
    row = CloudSandboxSession(
        user_id=user_id,
        status="termination_requested",
        provider="aws",
        sandbox_tier="pro",
        mode="auto",
        lease_minutes=15,
        expires_at=utcnow() - timedelta(seconds=1),
        termination_reason="provisioning_timeout",
        termination_requested_at=utcnow(),
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    recovered: list[str] = []

    def terminate_tagged(value: str) -> list[str]:
        recovered.append(value)
        return ["i-recovered-after-restart"]

    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "terminate_session_instances",
        terminate_tagged,
    )
    asyncio.run(sandbox_cloud.cleanup_session_by_id(session_id))

    assert recovered == [session_id]
    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        assert current is not None
        assert current.status == "expired"
        assert current.provider_instance_id == "i-recovered-after-restart"
        assert current.cleanup_completed_at is not None


def test_stale_terminating_claim_is_reconciled_after_api_restart(monkeypatch) -> None:
    user_id, _auth_token = _register("Stale cleanup claim")
    instance_id = f"i-{secrets.token_hex(6)}"
    old = utcnow() - timedelta(
        minutes=sandbox_cloud.CLEANUP_CLAIM_STALE_MINUTES + 1
    )
    row = CloudSandboxSession(
        user_id=user_id,
        status="terminating",
        provider="aws",
        provider_instance_id=instance_id,
        sandbox_tier="pro",
        mode="auto",
        lease_minutes=15,
        expires_at=utcnow() - timedelta(seconds=1),
        termination_reason="user_requested",
        termination_requested_at=old,
        updated_at=old,
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

    asyncio.run(sandbox_cloud.cleanup_session_by_id(session_id))

    assert terminated == [instance_id]
    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        assert current is not None
        assert current.status == "terminated"
        assert current.cleanup_completed_at is not None


def test_late_provision_result_is_terminated_after_cancel_race(monkeypatch) -> None:
    user_id, _auth_token = _register("Late provision")
    row = CloudSandboxSession(
        user_id=user_id,
        status="provisioning",
        provider="aws",
        sandbox_tier="pro",
        mode="auto",
        lease_minutes=15,
        expires_at=utcnow() + timedelta(minutes=25),
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    def provision_then_observe_cancel(*_args):
        with SessionLocal() as db:
            canceled = db.get(CloudSandboxSession, session_id)
            assert canceled is not None
            canceled.status = "terminated"
            canceled.termination_reason = "user_requested"
            canceled.termination_requested_at = utcnow()
            canceled.cleanup_completed_at = utcnow()
            canceled.terminated_at = utcnow()
            db.commit()
        return "i-late-result", ""

    terminated: list[str] = []
    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "provision",
        provision_then_observe_cancel,
    )
    monkeypatch.setattr(
        sandbox_cloud.cloud_sandbox_service,
        "terminate",
        lambda value: terminated.append(value),
    )

    asyncio.run(sandbox_cloud.provision_task(session_id, "agent-token"))

    assert terminated == ["i-late-result"]
    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        assert current is not None
        assert current.status == "terminated"
        assert current.cleanup_completed_at is not None


def test_concurrent_sample_upload_claim_accepts_exactly_one(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(settings, "sandbox_public_base_url", "https://api.example.test")
    monkeypatch.setattr(settings, "sandbox_sample_storage_path", str(tmp_path))
    user_id, auth_token = _register("Upload race")
    now = utcnow()
    row = CloudSandboxSession(
        user_id=user_id,
        status="ready",
        provider="aws",
        sandbox_tier="pro",
        mode="auto",
        lease_minutes=15,
        ready_at=now,
        lease_expires_at=now + timedelta(minutes=15),
        expires_at=now + timedelta(minutes=15),
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id

    entered_store = threading.Event()
    release_store = threading.Event()
    original_store = sandbox_cloud.store_sample

    def blocked_store(*args):
        entered_store.set()
        assert release_store.wait(timeout=5)
        return original_store(*args)

    monkeypatch.setattr(sandbox_cloud, "store_sample", blocked_store)

    def upload(filename: str):
        return client.post(
            f"/v1/sandbox-cloud/sessions/{session_id}/exe",
            headers=_headers(auth_token),
            files={"file": (filename, b"MZ-race-fixture")},
            data={"consent": "true"},
        )

    with ThreadPoolExecutor(max_workers=1) as executor:
        first_future = executor.submit(upload, "first.exe")
        assert entered_store.wait(timeout=5)
        second = upload("second.exe")
        release_store.set()
        first = first_future.result(timeout=10)

    assert first.status_code == 200
    assert second.status_code == 409
    with SessionLocal() as db:
        current = db.get(CloudSandboxSession, session_id)
        assert current is not None
        assert current.sample_status == "queued"
        assert current.sample_filename == "first.exe"


def test_agent_report_rejects_contents_nested_values_and_oversize(
    monkeypatch,
) -> None:
    user_id, _auth_token = _register("Telemetry bounds")
    agent_token = secrets.token_urlsafe(32)
    now = utcnow()
    row = CloudSandboxSession(
        user_id=user_id,
        status="ready",
        provider="aws",
        sandbox_tier="pro",
        mode="auto",
        lease_minutes=15,
        ready_at=now,
        lease_expires_at=now + timedelta(minutes=15),
        expires_at=now + timedelta(minutes=15),
        agent_token_hash=hashlib.sha256(agent_token.encode("utf-8")).hexdigest(),
        sample_status="delivered",
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        session_id = row.id
    endpoint = f"/v1/sandbox-cloud/agent/sessions/{session_id}/report"
    headers = {"X-Sandbox-Agent-Token": agent_token}

    raw_content = client.post(
        endpoint,
        headers=headers,
        json={
            "status": "running",
            "file_events": [{"file_contents": "not-metadata"}],
        },
    )
    nested = client.post(
        endpoint,
        headers=headers,
        json={
            "status": "running",
            "process_tree": [{"child": {"pid": 7}}],
        },
    )
    oversized = client.post(
        endpoint,
        headers=headers,
        json={
            "status": "running",
            "file_events": [
                {"relative_path": "x" * 4000, "event_type": "file_change"}
                for _ in range(150)
            ],
        },
    )

    assert raw_content.status_code == 422
    assert nested.status_code == 422
    assert oversized.status_code == 413


def test_agent_report_accepts_legacy_process_image_path_only() -> None:
    from pydantic import ValidationError

    from backend.routers.sandbox_cloud import SandboxAgentReport

    report = SandboxAgentReport(
        status="running",
        process_tree=[{"image": r"C:\\Sandbox\\sample.exe", "pid": 42}],
    )
    assert report.process_tree[0]["image"].endswith("sample.exe")

    with pytest.raises(ValidationError):
        SandboxAgentReport(
            status="running",
            file_events=[{"image": "not-allowed"}],
        )
