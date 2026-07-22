"""Run one harmless end-to-end AWS Sandbox PRO smoke test.

The local backend must be running with a public SANDBOX_PUBLIC_BASE_URL. The
script creates a temporary account, grants one local test entitlement, launches
one sandbox, runs a no-op CMD sample, terminates the instance, and removes all
temporary database rows.
"""

from __future__ import annotations

import secrets
import time
from datetime import timedelta

import requests
from sqlalchemy import delete, select

from backend.db import SessionLocal
from backend.models import (
    ApiKey,
    CloudSandboxSession,
    SandboxWallet,
    Subscription,
    User,
)
from backend.security_utils import utcnow

BASE_URL = "http://127.0.0.1:8000"


def main() -> None:
    email = f"aws-smoke-{secrets.token_hex(5)}@example.test"
    password = "SmokeTest!" + secrets.token_hex(8)
    token: str | None = None
    session_id: str | None = None
    user_id: str | None = None

    def api(method: str, path: str, **kwargs):
        headers = kwargs.pop("headers", {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return requests.request(
            method, BASE_URL + path, headers=headers, timeout=30, **kwargs
        )

    try:
        registration = requests.post(
            BASE_URL + "/v1/auth/register",
            json={
                "email": email,
                "password": password,
                "displayName": "AWS Smoke Test",
            },
            timeout=30,
        )
        registration.raise_for_status()
        token = registration.json()["token"]
        with SessionLocal() as db:
            user = db.execute(select(User).where(User.email == email)).scalar_one()
            user_id = user.id
            db.execute(delete(Subscription).where(Subscription.user_id == user.id))
            wallet = db.get(SandboxWallet, user.id)
            if wallet is None:
                db.add(SandboxWallet(user_id=user.id, credits=1))
            else:
                wallet.credits = 1
            db.add(
                Subscription(
                    user_id=user.id,
                    plan_tier="pro",
                    status="active",
                    provider="smoke-test",
                    renews_at=utcnow() + timedelta(days=1),
                )
            )
            db.commit()
        print("SMOKE_USER_READY", flush=True)

        created = api("POST", "/v1/sandbox-cloud/sessions", json={"tier": "pro"})
        if created.status_code != 200:
            raise RuntimeError(
                f"create session {created.status_code}: {created.text[:500]}"
            )
        body = created.json()
        session_id = body["id"]
        print(
            f"SESSION_CREATED={session_id} STATUS={body['status']}", flush=True
        )

        deadline = time.time() + 360
        last_status = None
        while time.time() < deadline:
            current = api("GET", f"/v1/sandbox-cloud/sessions/{session_id}")
            current.raise_for_status()
            body = current.json()
            if body["status"] != last_status:
                last_status = body["status"]
                print(f"PROVISION_STATUS={last_status}", flush=True)
            if last_status == "ready":
                break
            if last_status in {"failed", "expired", "terminated"}:
                raise RuntimeError(
                    f"provision ended {last_status}: {body.get('error')}"
                )
            time.sleep(5)
        else:
            raise TimeoutError("EC2 provisioning timeout")

        harmless = (
            b"@echo off\r\necho Prewise sandbox smoke test\r\nexit /b 0\r\n"
        )
        upload = api(
            "POST",
            f"/v1/sandbox-cloud/sessions/{session_id}/exe",
            files={
                "file": ("prewise-smoke.cmd", harmless, "application/octet-stream")
            },
            data={"consent": "true"},
        )
        if upload.status_code != 200:
            raise RuntimeError(f"upload {upload.status_code}: {upload.text[:500]}")
        print("SAMPLE_QUEUED=true", flush=True)

        deadline = time.time() + 480
        last_sample_status = None
        while time.time() < deadline:
            current = api("GET", f"/v1/sandbox-cloud/sessions/{session_id}")
            current.raise_for_status()
            sample = current.json()["sample"]
            if sample["status"] != last_sample_status:
                last_sample_status = sample["status"]
                print(f"SAMPLE_STATUS={last_sample_status}", flush=True)
            if last_sample_status == "completed":
                report = sample.get("report") or {}
                print(
                    "AGENT_REPORT_OK=" + str(report.get("status") == "completed"),
                    flush=True,
                )
                print("AGENT_VERDICT=" + str(report.get("verdict", "")), flush=True)
                break
            if last_sample_status == "failed":
                raise RuntimeError(f"agent report failed: {sample.get('report')}")
            time.sleep(5)
        else:
            raise TimeoutError("Sandbox agent report timeout")
    finally:
        if session_id and token:
            try:
                stopped = api("DELETE", f"/v1/sandbox-cloud/sessions/{session_id}")
                print(
                    "SESSION_TERMINATED=" + str(stopped.status_code == 200),
                    flush=True,
                )
            except Exception as exc:  # pragma: no cover - emergency cleanup log
                print("TERMINATION_ERROR=" + str(exc), flush=True)
        if user_id:
            with SessionLocal() as db:
                db.execute(
                    delete(CloudSandboxSession).where(
                        CloudSandboxSession.user_id == user_id
                    )
                )
                db.execute(delete(SandboxWallet).where(SandboxWallet.user_id == user_id))
                db.execute(delete(Subscription).where(Subscription.user_id == user_id))
                db.execute(delete(ApiKey).where(ApiKey.user_id == user_id))
                db.execute(delete(User).where(User.id == user_id))
                db.commit()
            print("SMOKE_USER_REMOVED=true", flush=True)


if __name__ == "__main__":
    main()
