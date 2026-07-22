"""Production sandbox entitlement API: Free Web, Pro EXE, and Max GPU."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from datetime import timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, ValidationInfo, field_validator, model_validator
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session as DbSession

from backend.config import settings
from backend.db import get_db
from backend.models import (
    CloudSandboxSession,
    PaymentOrder,
    SandboxWallet,
    Subscription,
    User,
)
from backend.routers.auth import CurrentSession
from backend.security_utils import create_session_token, utcnow
from backend.services.cloud_sandbox_sample_service import (
    remove_session_samples,
    safe_sample_name,
    store_sample,
    verify_agent_token,
)
from backend.services.cloud_sandbox_service import (
    CloudSandboxProvisioningError,
    cloud_sandbox_service,
)
from security.free_web_sandbox import free_web_sandbox

router = APIRouter(prefix="/v1/sandbox-cloud", tags=["sandbox-cloud"])
logger = logging.getLogger(__name__)
TIER_RANK = {"free": 0, "pro": 1, "max": 2}
FREE_DAILY_SESSION_LIMIT = 10
PRO_MONTHLY_PRICE_VND = 5_000
PRO_YEARLY_PRICE_VND = 50_000
TEAM_MONTHLY_PRICE_VND = 29_000
TEAM_YEARLY_PRICE_VND = 290_000
PLAN_INCLUDED_CREDITS = {"pro": 2, "team": 6}
ACTIVE_SESSION_STATES = {
    "provisioning",
    "ready",
    "termination_requested",
    "terminating",
    "cleanup_failed",
}
TERMINAL_SESSION_STATES = {"terminated", "expired", "failed"}
INTERACTIVE_LEASE_MINUTES = {5, 10}
MAX_SANDBOX_REPORT_BYTES = 512 * 1024
MAX_TELEMETRY_EVENT_FIELDS = 32
MAX_TELEMETRY_TEXT_LENGTH = 4096
CLEANUP_CLAIM_STALE_MINUTES = 10
FORBIDDEN_TELEMETRY_FIELDS = {
    "content",
    "contents",
    "file_content",
    "file_contents",
    "raw_value",
    "registry_value_data",
    "pixels",
    "pixel_data",
    "screenshot",
    "screenshot_base64",
    "image",
    "image_data",
}
TIER_CAPABILITIES = {
    "free": {
        "web": True,
        "exe": False,
        "gpu": False,
        "minutes": settings.free_sandbox_daily_minutes,
        "provider": "local",
        "creditCost": 0,
    },
    "pro": {
        "web": True,
        "exe": True,
        "gpu": False,
        "minutes": settings.pro_sandbox_session_minutes,
        "provider": "aws",
        "creditCost": 1,
    },
    "max": {
        "web": True,
        "exe": True,
        "gpu": True,
        "minutes": settings.max_sandbox_session_minutes,
        "provider": "aws",
        "creditCost": 3,
    },
}


class BuyCreditsInput(BaseModel):
    credits: int = Field(default=1, ge=1, le=100)


class CreateSubscriptionPaymentInput(BaseModel):
    planTier: str = Field(pattern="^(pro|team)$")
    billingPeriod: str = Field(pattern="^(monthly|yearly)$")


class CreateSessionInput(BaseModel):
    tier: str = "free"
    mode: Literal["auto", "interactive"] = "auto"
    leaseMinutes: Literal[5, 10] | None = None


class SandboxAgentReport(BaseModel):
    status: str = Field(pattern="^(staged|running|completed|failed)$")
    phase: str | None = Field(
        default=None,
        pattern="^(staged|running|completed|failed)$",
    )
    mode: Literal["auto", "interactive"] | None = None
    verdict: str = Field(default="unknown", max_length=40)
    summary: str = Field(default="", max_length=2000)
    process_tree: list[dict] = Field(default_factory=list, max_length=100)
    file_events: list[dict] = Field(default_factory=list, max_length=200)
    registry_events: list[dict] = Field(default_factory=list, max_length=200)
    network_events: list[dict] = Field(default_factory=list, max_length=200)

    @field_validator(
        "process_tree",
        "file_events",
        "registry_events",
        "network_events",
    )
    @classmethod
    def validate_bounded_event_metadata(
        cls, events: list[dict], info: ValidationInfo
    ) -> list[dict]:
        for event in events:
            if len(event) > MAX_TELEMETRY_EVENT_FIELDS:
                raise ValueError("Sandbox telemetry event có quá nhiều trường")
            for key, value in event.items():
                normalized_key = str(key).strip().lower().replace("-", "_")
                if not normalized_key or len(str(key)) > 80:
                    raise ValueError("Sandbox telemetry key không hợp lệ")
                # Older Windows agents used `image` for the executable path in
                # process-tree metadata. Keep that bounded compatibility case
                # while continuing to reject image/pixel payloads everywhere
                # else. New agents send the unambiguous `executable_path` key.
                legacy_process_image_path = (
                    info.field_name == "process_tree"
                    and normalized_key == "image"
                    and isinstance(value, str)
                    and len(value) <= 520
                    and "\r" not in value
                    and "\n" not in value
                )
                if (
                    normalized_key in FORBIDDEN_TELEMETRY_FIELDS
                    and not legacy_process_image_path
                ):
                    raise ValueError("Sandbox telemetry chỉ được gửi metadata")
                if not isinstance(value, (str, int, float, bool, type(None))):
                    raise ValueError("Sandbox telemetry phải là metadata phẳng")
                if isinstance(value, str) and len(value) > MAX_TELEMETRY_TEXT_LENGTH:
                    raise ValueError("Sandbox telemetry text vượt giới hạn")
        return events

    @model_validator(mode="after")
    def validate_total_report_size(self) -> SandboxAgentReport:
        if len(self.model_dump_json().encode("utf-8")) > MAX_SANDBOX_REPORT_BYTES:
            raise ValueError("Sandbox telemetry report vượt giới hạn")
        return self


class ConsumeRemoteAccessInput(BaseModel):
    sessionId: str = Field(min_length=1, max_length=36)
    accessToken: str = Field(min_length=32, max_length=512)


class FreeNavigateInput(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class FreeClickInput(BaseModel):
    x: float = Field(ge=0, le=1280)
    y: float = Field(ge=0, le=720)


class FreeKeyInput(BaseModel):
    key: str = Field(min_length=1, max_length=40)


class FreeTypeInput(BaseModel):
    text: str = Field(max_length=500)


class SePayWebhook(BaseModel):
    id: str | int | None = None
    transferAmount: int | float = 0
    transferType: str = ""
    content: str = ""
    code: str | None = None
    description: str = ""
    referenceCode: str | None = None


def verify_sepay_webhook_hmac(
    raw_body: bytes,
    signature: str | None,
    timestamp: str | None,
    secret: str,
    *,
    now: int | None = None,
) -> bool:
    """Verify SePay's ``sha256={hex}`` signature and reject replayed requests."""
    if not signature or not timestamp:
        return False
    signed_timestamp = timestamp.strip()
    try:
        timestamp_seconds = int(signed_timestamp)
    except (TypeError, ValueError):
        return False
    current_time = int(time.time()) if now is None else now
    if abs(current_time - timestamp_seconds) > 300:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        f"{signed_timestamp}.".encode() + raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(signature.strip(), expected)


def is_incoming_sepay_transaction(transfer_type: str) -> bool:
    """Only incoming transfers can settle an order, even if a webhook is misconfigured."""
    return transfer_type.strip().lower() in {"in", "income", "incoming"}


def wallet_for(db: DbSession, user_id: str) -> SandboxWallet:
    wallet = db.get(SandboxWallet, user_id)
    if wallet is None:
        wallet = SandboxWallet(user_id=user_id, credits=0)
        db.add(wallet)
        db.flush()
    return wallet


def refund_session_credit(db: DbSession, row: CloudSandboxSession) -> bool:
    """Refund a paid session at most once when provisioning never becomes usable."""
    report = dict(row.sample_report or {})
    if report.get("credit_refunded_at"):
        return False
    credit_cost = int(TIER_CAPABILITIES.get(row.sandbox_tier, {}).get("creditCost", 0))
    if credit_cost <= 0:
        return False
    wallet_for(db, row.user_id).credits += credit_cost
    report["credit_refunded_at"] = utcnow().isoformat()
    report["credit_refund_amount"] = credit_cost
    row.sample_report = report
    return True


def provisioning_deadline(row: CloudSandboxSession):
    return row.created_at + timedelta(
        minutes=settings.sandbox_cloud_provision_timeout_minutes
    )


def effective_session_deadline(row: CloudSandboxSession):
    if row.status == "provisioning":
        return min(row.expires_at, provisioning_deadline(row))
    return row.lease_expires_at or row.expires_at


def session_has_expired(row: CloudSandboxSession) -> bool:
    return effective_session_deadline(row) <= utcnow()


def invalidate_remote_access(row: CloudSandboxSession) -> None:
    row.remote_access_token_hash = None
    row.remote_access_token_expires_at = None
    row.remote_access_token_used_at = None
    row.remote_url = None


def make_sepay_qr_url(amount_vnd: int, reference: str) -> str:
    """Create a dynamic VietQR image containing the fixed order amount and reference."""
    if not settings.sepay_bank_account or not settings.sepay_bank_name:
        return ""
    base = settings.sepay_qr_base_url.rstrip("/")
    account = quote(settings.sepay_bank_account, safe="")
    bank = quote(settings.sepay_bank_name, safe="")
    content = quote(sepay_transfer_content(reference), safe="")
    return f"{base}?acc={account}&bank={bank}&amount={amount_vnd}&des={content}"


def sepay_transfer_content(reference: str) -> str:
    """Keep VietinBank API Banking transfers visible to SePay."""
    return f"SEVQR {reference}"


def subscription_amount_vnd(plan_tier: str, billing_period: str) -> int:
    prices = {
        ("pro", "monthly"): PRO_MONTHLY_PRICE_VND,
        ("pro", "yearly"): PRO_YEARLY_PRICE_VND,
        ("team", "monthly"): TEAM_MONTHLY_PRICE_VND,
        ("team", "yearly"): TEAM_YEARLY_PRICE_VND,
    }
    try:
        return prices[(plan_tier, billing_period)]
    except KeyError as exc:
        raise ValueError("Gói hoặc chu kỳ thanh toán không hợp lệ") from exc


def sandbox_credit_payment_dict(order: PaymentOrder) -> dict:
    return {
        "orderId": order.id,
        "reference": order.reference,
        "amountVnd": order.amount_vnd,
        "credits": order.credits,
        "expiresAt": order.expires_at.isoformat() if order.expires_at else None,
        "bankAccount": settings.sepay_bank_account,
        "bankName": settings.sepay_bank_name,
        "accountName": settings.sepay_account_name,
        "transferContent": sepay_transfer_content(order.reference),
        "qrUrl": make_sepay_qr_url(order.amount_vnd, order.reference),
        "status": order.status,
    }


def subscription_payment_dict(order: PaymentOrder) -> dict:
    return {
        "orderId": order.id,
        "reference": order.reference,
        "amountVnd": order.amount_vnd,
        "planTier": order.plan_tier,
        "billingPeriod": order.billing_period,
        "includedCredits": order.credits,
        "expiresAt": order.expires_at.isoformat() if order.expires_at else None,
        "bankAccount": settings.sepay_bank_account,
        "bankName": settings.sepay_bank_name,
        "accountName": settings.sepay_account_name,
        "transferContent": sepay_transfer_content(order.reference),
        "qrUrl": make_sepay_qr_url(order.amount_vnd, order.reference),
        "status": order.status,
    }


def activate_subscription(db: DbSession, order: PaymentOrder) -> None:
    """Idempotently replace the active plan only after an exact paid order."""
    if not order.plan_tier or not order.billing_period:
        return
    now = utcnow()
    db.execute(
        Subscription.__table__.update()
        .where(
            Subscription.user_id == order.user_id,
            Subscription.status.in_(("trialing", "active")),
        )
        .values(status="canceled", canceled_at=now)
    )
    days = 365 if order.billing_period == "yearly" else 30
    db.add(
        Subscription(
            user_id=order.user_id,
            plan_tier=order.plan_tier,
            status="active",
            provider="sepay",
            provider_subscription_id=order.id,
            renews_at=now + timedelta(days=days),
        )
    )
    # Credits live on the order so the paid webhook grants them exactly once.
    if order.credits > 0:
        wallet_for(db, order.user_id).credits += order.credits


def account_tier(db: DbSession, user_id: str) -> str:
    rows = db.execute(
        select(Subscription).where(
            Subscription.user_id == user_id,
            Subscription.status.in_(("trialing", "active")),
        ).order_by(Subscription.created_at.desc())
    ).scalars().all()
    # Historical/imported data can temporarily contain more than one active
    # subscription. Resolve to the strongest entitlement instead of returning
    # HTTP 500; the payment path still cancels prior active rows on upgrade.
    now = utcnow()
    tiers = [
        "max" if row.plan_tier in {"team", "enterprise"} else row.plan_tier
        for row in rows
        if (
            row.trial_ends_at
            if row.status == "trialing" and row.trial_ends_at is not None
            else row.renews_at
        ) is None
        or (
            row.trial_ends_at
            if row.status == "trialing" and row.trial_ends_at is not None
            else row.renews_at
        ) > now
    ]
    valid = [tier for tier in tiers if tier in TIER_RANK]
    return max(valid, key=TIER_RANK.get) if valid else "free"


def session_dict(row: CloudSandboxSession) -> dict:
    now = utcnow()
    deadline = effective_session_deadline(row)
    broker_availability = (
        cloud_sandbox_service.broker_availability()
        if row.mode == "interactive"
        else {"available": False, "reason": "auto_mode_agent_only", "missing": []}
    )
    broker_available = bool(broker_availability["available"])
    remote_available = bool(
        row.mode == "interactive"
        and row.status == "ready"
        and row.remote_url
        and row.provider_instance_id
        and row.lease_expires_at
        and broker_available
        and row.sample_status in {"staged", "running"}
        and deadline > now
    )
    if row.mode != "interactive":
        remote_reason = "auto_mode_agent_only"
        remote_status = "unavailable"
    elif row.status == "provisioning":
        remote_reason = "provisioning"
        remote_status = "provisioning"
    elif row.status == "ready" and not broker_available:
        remote_reason = broker_availability["reason"] or "broker_not_ready"
        remote_status = "unavailable"
    elif row.status == "ready" and (
        not row.remote_url
        or not row.provider_instance_id
        or row.lease_expires_at is None
    ):
        remote_reason = "broker_not_ready"
        remote_status = "unavailable"
    elif row.status == "ready" and deadline <= now:
        remote_reason = "lease_expired"
        remote_status = "expired"
    elif (
        row.status == "ready"
        and row.remote_url
        and row.sample_status not in {"staged", "running"}
    ):
        remote_reason = "sample_staging"
        remote_status = "staging"
    elif row.status in {"termination_requested", "terminating"}:
        remote_reason = "terminating"
        remote_status = "terminating"
    elif row.status == "cleanup_failed":
        remote_reason = "cleanup_failed"
        remote_status = "failed"
    elif row.status in TERMINAL_SESSION_STATES:
        remote_reason = row.status
        remote_status = row.status
    else:
        remote_reason = None
        remote_status = "available"
    if remote_available:
        remote_reason = None
        remote_status = "available"

    cleanup_state = "active"
    if row.status == "termination_requested":
        cleanup_state = "requested"
    elif row.status == "terminating":
        cleanup_state = "running"
    elif row.status in {"terminated", "expired"}:
        cleanup_state = "complete"
    elif row.status == "cleanup_failed":
        cleanup_state = "failed"
    elif row.status == "failed":
        cleanup_state = "complete" if row.cleanup_completed_at else "failed"

    report = dict(row.sample_report or {})
    report["mode"] = row.mode
    return {
        "id": row.id,
        "tier": row.sandbox_tier,
        "mode": row.mode,
        "phase": row.status,
        "status": row.status,
        "leaseMinutes": row.lease_minutes,
        "readyAt": row.ready_at.isoformat() if row.ready_at else None,
        "leaseExpiresAt": (
            row.lease_expires_at.isoformat() if row.lease_expires_at else None
        ),
        # Never expose the internal broker target. A short-lived direct URL is
        # issued by POST /sessions/{id}/remote-access only.
        "remoteUrl": None,
        "remoteAvailable": remote_available,
        "remoteStatus": remote_status,
        "remoteUnavailableReason": remote_reason,
        "expiresAt": deadline.isoformat(),
        "cleanupState": cleanup_state,
        "terminationReason": row.termination_reason,
        "error": row.error,
        "sample": {
            "filename": row.sample_filename,
            "sha256": row.sample_sha256,
            "size": row.sample_size,
            "status": row.sample_status,
            "phase": row.sample_status,
            "report": report,
        },
    }


async def cleanup_session(
    db: DbSession,
    row: CloudSandboxSession,
    *,
    terminal_status: Literal["terminated", "expired", "failed"],
    reason: str,
    refund_if_provisioning: bool = True,
) -> bool:
    """Revoke access, destroy the worker, and expose cleanup failures.

    If a provisioning task has not persisted its instance id yet, cleanup
    reconciles EC2 by the durable ``PrewiseSession`` tag.
    """
    if row.status in {"terminated", "expired", "failed"} and row.cleanup_completed_at:
        return True
    if row.status not in {"termination_requested", "cleanup_failed"}:
        request_session_cleanup(
            db,
            row,
            reason=reason,
            refund_if_provisioning=refund_if_provisioning,
        )

    claimed = db.execute(
        update(CloudSandboxSession)
        .where(
            CloudSandboxSession.id == row.id,
            CloudSandboxSession.status.in_(("termination_requested", "cleanup_failed")),
        )
        .values(status="terminating", updated_at=utcnow())
    )
    db.commit()
    if claimed.rowcount != 1:
        db.refresh(row)
        return row.status in TERMINAL_SESSION_STATES
    db.refresh(row)
    failures: list[str] = []
    if row.provider == "aws" and row.provider_instance_id:
        try:
            await asyncio.to_thread(
                cloud_sandbox_service.terminate,
                row.provider_instance_id,
            )
        except Exception as exc:  # pragma: no cover - external AWS state
            logger.exception(
                "Could not terminate sandbox instance %s",
                row.provider_instance_id,
            )
            failures.append(f"AWS terminate: {exc}")
    elif row.provider == "aws":
        try:
            discovered = await asyncio.to_thread(
                cloud_sandbox_service.terminate_session_instances,
                row.id,
            )
            if discovered:
                # Preserve a useful audit binding even though every matching
                # worker has already been terminated by the recovery call.
                row.provider_instance_id = discovered[0]
        except Exception as exc:  # pragma: no cover - external AWS state
            logger.exception(
                "Could not reconcile sandbox instances for session %s",
                row.id,
            )
            failures.append(f"AWS reconcile/terminate: {exc}")
    if row.sandbox_tier == "free":
        try:
            await asyncio.to_thread(free_web_sandbox.close, row.id)
        except Exception as exc:  # pragma: no cover - local browser failure
            failures.append(f"browser close: {exc}")
    try:
        await asyncio.to_thread(remove_session_samples, row.id)
    except Exception as exc:  # pragma: no cover - local storage failure
        failures.append(f"sample cleanup: {exc}")

    if failures:
        row.status = "cleanup_failed"
        row.error = ("Không thể hủy hoàn toàn Sandbox: " + "; ".join(failures))[:1000]
        db.commit()
        return False

    now = utcnow()
    row.status = terminal_status
    row.terminated_at = now
    row.cleanup_completed_at = now
    if terminal_status != "failed":
        row.error = None
    db.commit()
    return True


def request_session_cleanup(
    db: DbSession,
    row: CloudSandboxSession,
    *,
    reason: str,
    refund_if_provisioning: bool = True,
) -> bool:
    """Durably revoke access before any slow provider cleanup starts."""
    if row.status in {"terminated", "expired", "terminating"}:
        return False
    if row.status == "provisioning" and refund_if_provisioning:
        refund_session_credit(db, row)
    row.status = "termination_requested"
    row.termination_reason = reason
    row.termination_requested_at = row.termination_requested_at or utcnow()
    invalidate_remote_access(row)
    db.commit()
    return True


async def cleanup_session_by_id(session_id: str) -> None:
    """Reconcile one requested cleanup in a fresh database transaction."""
    from backend.db import SessionLocal

    with SessionLocal() as db:
        row = db.get(CloudSandboxSession, session_id)
        if row is None:
            return
        if row.status == "terminating":
            stale_before = utcnow() - timedelta(minutes=CLEANUP_CLAIM_STALE_MINUTES)
            reclaimed = db.execute(
                update(CloudSandboxSession)
                .where(
                    CloudSandboxSession.id == session_id,
                    CloudSandboxSession.status == "terminating",
                    CloudSandboxSession.updated_at <= stale_before,
                )
                .values(status="termination_requested", updated_at=utcnow())
            )
            db.commit()
            if reclaimed.rowcount != 1:
                return
            db.refresh(row)
        elif row.status not in {"termination_requested", "cleanup_failed"}:
            return
        if (
            row.mode == "interactive"
            and row.termination_reason == "lease_expired"
            and row.sample_status in {"staged", "running"}
        ):
            # Remote input is already revoked. Keep only a short authenticated
            # finalization window so the agent can upload its final telemetry.
            grace_seconds = max(
                0,
                min(settings.sandbox_agent_report_grace_seconds, 30),
            )
            wait_until = (row.termination_requested_at or utcnow()) + timedelta(
                seconds=grace_seconds
            )
            while utcnow() < wait_until and row.sample_status in {
                "staged",
                "running",
            }:
                remaining = max(0.0, (wait_until - utcnow()).total_seconds())
                db.rollback()
                await asyncio.sleep(min(1.0, remaining))
                row = db.get(CloudSandboxSession, session_id)
                if row is None or row.status != "termination_requested":
                    return
        terminal_status: Literal["terminated", "expired"] = (
            "expired"
            if row.termination_reason in {"lease_expired", "provisioning_timeout"}
            else "terminated"
        )
        await cleanup_session(
            db,
            row,
            terminal_status=terminal_status,
            reason=row.termination_reason or "cleanup_reconciliation",
        )


def schedule_session_cleanup(
    background_tasks: BackgroundTasks,
    db: DbSession,
    row: CloudSandboxSession,
    *,
    reason: str,
    refund_if_provisioning: bool = True,
) -> None:
    request_session_cleanup(
        db,
        row,
        reason=reason,
        refund_if_provisioning=refund_if_provisioning,
    )
    background_tasks.add_task(cleanup_session_by_id, row.id)


def schedule_completed_auto_cleanup(
    background_tasks: BackgroundTasks,
    db: DbSession,
    row: CloudSandboxSession,
) -> bool:
    if row.mode != "auto" or row.sample_status not in {"completed", "failed"}:
        return False
    schedule_session_cleanup(
        background_tasks,
        db,
        row,
        reason="auto_analysis_completed",
        # A final report proves the paid run was usable even if it raced the
        # readiness commit, so it must not be refunded.
        refund_if_provisioning=False,
    )
    return True


@router.get("/status")
async def get_status(
    background_tasks: BackgroundTasks,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> dict:
    wallet = wallet_for(db, auth.user.id)
    plan = account_tier(db, auth.user.id)
    active = db.execute(
        select(CloudSandboxSession).where(
            CloudSandboxSession.user_id == auth.user.id,
            CloudSandboxSession.status.in_(ACTIVE_SESSION_STATES),
        ).order_by(CloudSandboxSession.created_at.desc())
    ).scalars().first()
    if (
        active is not None
        and active.status in {"provisioning", "ready"}
        and session_has_expired(active)
    ):
        schedule_session_cleanup(
            background_tasks,
            db,
            active,
            reason="lease_expired",
        )
    elif active is not None and active.status in {
        "termination_requested",
        "cleanup_failed",
        "terminating",
    }:
        background_tasks.add_task(cleanup_session_by_id, active.id)
    db.commit()
    recent = db.execute(
        select(CloudSandboxSession)
        .where(
            CloudSandboxSession.user_id == auth.user.id,
            CloudSandboxSession.status.in_(TERMINAL_SESSION_STATES),
            CloudSandboxSession.sample_status.in_(("completed", "failed")),
        )
        .order_by(CloudSandboxSession.updated_at.desc())
    ).scalars().first()
    available_tiers = []
    for tier, capability in TIER_CAPABILITIES.items():
        if tier == "free":
            auto_availability = {"available": True, "reason": None, "missing": []}
            interactive_availability = {
                "available": False,
                "reason": "windows_interactive_requires_paid_tier",
                "missing": [],
            }
        else:
            auto_availability = cloud_sandbox_service.availability(tier, "auto")
            interactive_availability = cloud_sandbox_service.availability(
                tier,
                "interactive",
            )
        configured = bool(auto_availability["available"])
        available_tiers.append(
            {
                "tier": tier,
                **capability,
                "allowed": TIER_RANK[plan] >= TIER_RANK[tier],
                "configured": configured,
                "modes": {
                    "auto": {
                        **auto_availability,
                        "leaseMinutes": capability["minutes"],
                    },
                    "interactive": {
                        **interactive_availability,
                        "leaseMinutes": [5, 10],
                    },
                },
            }
        )
    return {
        "accountTier": plan,
        "credits": wallet.credits,
        "availableTiers": available_tiers,
        "cloudConfigured": (
            cloud_sandbox_service.configured("pro")
            or cloud_sandbox_service.configured("max")
        ),
        "interactiveAvailable": (
            cloud_sandbox_service.configured("pro", "interactive")
            or cloud_sandbox_service.configured("max", "interactive")
        ),
        "freeConfigured": True,
        "session": session_dict(active) if active else None,
        # Auto workers terminate immediately after their final report. Keep the
        # latest evidence discoverable without treating that VM as active.
        "recentSession": session_dict(recent) if recent else None,
    }


@router.post("/payments")
def create_payment(
    payload: BuyCreditsInput,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> dict:
    if not settings.sepay_bank_account or not settings.sepay_bank_name:
        raise HTTPException(503, "Thanh toán SePay chưa được cấu hình.")
    reference = f"PW{secrets.token_hex(6).upper()}"
    order = PaymentOrder(
        user_id=auth.user.id,
        reference=reference,
        credits=payload.credits,
        amount_vnd=payload.credits * settings.sandbox_credit_price_vnd,
        expires_at=utcnow() + timedelta(minutes=settings.sepay_payment_expiry_minutes),
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    return sandbox_credit_payment_dict(order)


@router.get("/payments/{order_id}")
def get_payment(
    order_id: str,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> dict:
    order = db.get(PaymentOrder, order_id)
    if order is None or order.user_id != auth.user.id or order.plan_tier is not None:
        raise HTTPException(404, "Không tìm thấy đơn mua lượt Sandbox.")
    if order.status == "pending" and order.expires_at is not None and order.expires_at <= utcnow():
        order.status = "expired"
        db.commit()
        db.refresh(order)
    return sandbox_credit_payment_dict(order)


@router.post("/subscription-payments")
def create_subscription_payment(
    payload: CreateSubscriptionPaymentInput,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> dict:
    if not settings.sepay_bank_account or not settings.sepay_bank_name:
        raise HTTPException(503, "Thanh toán SePay chưa được cấu hình.")
    current_tier = account_tier(db, auth.user.id)
    requested_tier = "max" if payload.planTier == "team" else payload.planTier
    if TIER_RANK[current_tier] >= TIER_RANK[requested_tier]:
        raise HTTPException(
            409,
            f"Tài khoản đang ở gói {current_tier.upper()}, không cần mua lại gói này.",
        )
    amount = subscription_amount_vnd(payload.planTier, payload.billingPeriod)
    reference = f"PP{secrets.token_hex(6).upper()}"
    order = PaymentOrder(
        user_id=auth.user.id,
        reference=reference,
        amount_vnd=amount,
        credits=PLAN_INCLUDED_CREDITS[payload.planTier],
        plan_tier=payload.planTier,
        billing_period=payload.billingPeriod,
        expires_at=utcnow() + timedelta(minutes=settings.sepay_payment_expiry_minutes),
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    return subscription_payment_dict(order)


@router.get("/subscription-payments/{order_id}")
def get_subscription_payment(order_id: str, auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict:
    order = db.get(PaymentOrder, order_id)
    if order is None or order.user_id != auth.user.id or order.plan_tier is None:
        raise HTTPException(404, "Không tìm thấy đơn thanh toán gói.")
    if order.status == "pending" and order.expires_at is not None and order.expires_at <= utcnow():
        order.status = "expired"
        db.commit()
        db.refresh(order)
    return subscription_payment_dict(order)


@router.post("/webhooks/sepay")
async def sepay_webhook(
    request: Request,
    db: DbSession = Depends(get_db),
    authorization: str | None = Header(default=None),
    x_sepay_signature: str | None = Header(default=None),
    x_sepay_timestamp: str | None = Header(default=None),
) -> dict:
    raw_body = await request.body()
    if settings.sepay_webhook_secret:
        if not verify_sepay_webhook_hmac(
            raw_body, x_sepay_signature, x_sepay_timestamp, settings.sepay_webhook_secret,
        ):
            raise HTTPException(401, "Chữ ký webhook không hợp lệ")
    else:
        supplied = (authorization or "").removeprefix("Apikey ").removeprefix("Bearer ").strip()
        if not settings.sepay_webhook_api_key or not secrets.compare_digest(supplied, settings.sepay_webhook_api_key):
            raise HTTPException(401, "Webhook không hợp lệ")
    try:
        payload = SePayWebhook.model_validate(json.loads(raw_body))
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(400, "Dữ liệu webhook JSON không hợp lệ") from exc
    if not is_incoming_sepay_transaction(payload.transferType):
        return {"success": True, "ignored": "not_incoming"}
    reference_text = " ".join(
        value for value in (payload.code, payload.content, payload.description) if value
    ).upper()
    match = re.search(r"(?<![A-F0-9])((?:PW|PP)[A-F0-9]{12})(?![A-F0-9])", reference_text)
    if not match:
        return {"success": True, "ignored": "missing_reference"}
    order = db.execute(select(PaymentOrder).where(PaymentOrder.reference == match.group(1))).scalar_one_or_none()
    if order is None or order.status == "expired" or (order.expires_at is not None and order.expires_at <= utcnow()):
        return {"success": True, "ignored": "unknown_or_expired"}
    if payload.transferAmount < order.amount_vnd:
        return {"success": True, "ignored": "insufficient"}
    transaction_id = str(payload.id or payload.referenceCode or "")
    duplicate = transaction_id and db.execute(
        select(PaymentOrder).where(PaymentOrder.provider_transaction_id == transaction_id)
    ).scalar_one_or_none()
    if duplicate:
        return {"success": True, "duplicate": True}
    if order.status != "paid":
        order.status = "paid"
        order.paid_at = utcnow()
        order.provider_transaction_id = transaction_id or None
        order.provider_payload = payload.model_dump()
        if order.plan_tier:
            activate_subscription(db, order)
        else:
            wallet_for(db, order.user_id).credits += order.credits
        db.commit()
    return {"success": True}


async def provision_task(session_id: str, agent_token: str) -> None:
    from backend.db import SessionLocal

    with SessionLocal() as db:
        row = db.get(CloudSandboxSession, session_id)
        if row is None or row.status != "provisioning":
            return
        try:
            instance_id, remote_url = await asyncio.to_thread(
                cloud_sandbox_service.provision,
                row.id,
                row.user_id,
                row.expires_at.isoformat(),
                row.sandbox_tier,
                agent_token,
                row.mode,
                row.lease_minutes,
            )
            db.refresh(row)
            row.provider_instance_id = instance_id
            db.commit()
            db.refresh(row)
            timed_out = utcnow() >= provisioning_deadline(row)
            if row.status != "provisioning" or timed_out:
                reason = row.termination_reason or "provisioning_timeout"
                terminal_status: Literal["terminated", "expired", "failed"] = (
                    "expired" if timed_out or reason == "lease_expired" else "terminated"
                )
                if timed_out:
                    refund_session_credit(db, row)
                if row.status in TERMINAL_SESSION_STATES:
                    # Cleanup may have found no instance while RunInstances was
                    # still in flight. Re-open cleanup so the newly returned id
                    # cannot become an orphan after cancellation/restart races.
                    row.status = "termination_requested"
                    row.cleanup_completed_at = None
                    row.terminated_at = None
                    row.termination_reason = reason
                    row.termination_requested_at = utcnow()
                    invalidate_remote_access(row)
                    db.commit()
                await cleanup_session(
                    db,
                    row,
                    terminal_status=terminal_status,
                    reason=reason,
                )
            else:
                heartbeat_deadline = min(
                    provisioning_deadline(row),
                    utcnow()
                    + timedelta(
                        seconds=settings.sandbox_agent_bootstrap_timeout_seconds
                    ),
                )
                while utcnow() < heartbeat_deadline:
                    db.expire_all()
                    row = db.get(CloudSandboxSession, session_id)
                    if row is None:
                        return
                    if row.status != "provisioning":
                        break
                    if (row.sample_report or {}).get("agent_bootstrap_at"):
                        break
                    await asyncio.sleep(2)
                if row.status != "provisioning":
                    await cleanup_session(
                        db,
                        row,
                        terminal_status="terminated",
                        reason=row.termination_reason or "provisioning_cancelled",
                    )
                    return
                if not (row.sample_report or {}).get("agent_bootstrap_at"):
                    raise RuntimeError(
                        "Windows Sandbox agent không callback; kiểm tra NAT/outbound HTTPS và SANDBOX_PUBLIC_BASE_URL"
                    )
                ready_at = utcnow()
                row.ready_at = ready_at
                row.lease_expires_at = ready_at + timedelta(
                    minutes=row.lease_minutes
                )
                # Preserve the old expiresAt contract while making the paid
                # timer start only once the worker is actually ready.
                row.expires_at = row.lease_expires_at
                row.remote_url = remote_url if row.mode == "interactive" else None
                row.status = "ready"
                row.error = None
        except Exception as exc:
            db.rollback()
            db.refresh(row)
            if isinstance(exc, CloudSandboxProvisioningError):
                row.provider_instance_id = exc.instance_id
            if row.status == "provisioning":
                row.error = str(exc)[:1000]
                request_session_cleanup(
                    db,
                    row,
                    reason="provisioning_failed",
                )
                await cleanup_session(
                    db,
                    row,
                    terminal_status="failed",
                    reason="provisioning_failed",
                )
                return
            if row.status in TERMINAL_SESSION_STATES and isinstance(
                exc,
                CloudSandboxProvisioningError,
            ):
                prior_status = row.status
                row.status = "termination_requested"
                row.cleanup_completed_at = None
                row.terminated_at = None
                row.termination_reason = row.termination_reason or "provisioning_failed"
                row.termination_requested_at = utcnow()
                invalidate_remote_access(row)
                db.commit()
                await cleanup_session(
                    db,
                    row,
                    terminal_status=(
                        "expired"
                        if prior_status == "expired"
                        else "failed" if prior_status == "failed" else "terminated"
                    ),
                    reason=row.termination_reason,
                )
                return
            if row.status in {"termination_requested", "cleanup_failed"}:
                reason = row.termination_reason or "provisioning_failed"
                await cleanup_session(
                    db,
                    row,
                    terminal_status=(
                        "expired"
                        if reason in {"lease_expired", "provisioning_timeout"}
                        else "terminated"
                    ),
                    reason=reason,
                )
                return
        db.commit()


@router.post("/sessions")
async def create_session(
    payload: CreateSessionInput,
    background_tasks: BackgroundTasks,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> dict:
    requested = payload.tier.lower()
    mode = payload.mode
    if requested not in TIER_RANK:
        raise HTTPException(400, "Tier Sandbox không hợp lệ")
    if requested == "free" and mode == "interactive":
        raise HTTPException(
            400,
            "Interactive Windows Sandbox chỉ có ở gói PRO hoặc MAX",
        )
    if mode == "auto" and payload.leaseMinutes is not None:
        raise HTTPException(
            400,
            "leaseMinutes 5/10 chỉ áp dụng cho Interactive Sandbox",
        )
    # Serialize entitlement/credit/session creation per account in PostgreSQL.
    # The later state checks remain authoritative; this lock closes the normal
    # double-click/racing-request window without coupling users to each other.
    db.execute(
        select(User.id).where(User.id == auth.user.id).with_for_update()
    ).scalar_one()
    plan = account_tier(db, auth.user.id)
    if TIER_RANK[requested] > TIER_RANK[plan]:
        raise HTTPException(403, f"Gói {plan.upper()} không được dùng Sandbox {requested.upper()}")
    existing = db.execute(select(CloudSandboxSession).where(
        CloudSandboxSession.user_id == auth.user.id,
        CloudSandboxSession.status.in_(ACTIVE_SESSION_STATES),
    ).order_by(CloudSandboxSession.created_at.desc())).scalars().first()
    if (
        existing
        and existing.status in {"provisioning", "ready"}
        and session_has_expired(existing)
    ):
        schedule_session_cleanup(
            background_tasks,
            db,
            existing,
            reason="lease_expired",
        )
    elif existing and existing.status in {
        "termination_requested",
        "cleanup_failed",
        "terminating",
    }:
        background_tasks.add_task(cleanup_session_by_id, existing.id)
    if existing:
        return session_dict(existing)

    capability = TIER_CAPABILITIES[requested]
    lease_minutes = (
        payload.leaseMinutes or 5
        if mode == "interactive"
        else int(capability["minutes"])
    )
    if requested == "free":
        start = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        used = db.scalar(
            select(func.count())
            .select_from(CloudSandboxSession)
            .where(
                CloudSandboxSession.user_id == auth.user.id,
                CloudSandboxSession.sandbox_tier == "free",
                CloudSandboxSession.created_at >= start,
                CloudSandboxSession.status != "failed",
            )
        ) or 0
        if used >= FREE_DAILY_SESSION_LIMIT:
            raise HTTPException(
                429,
                f"Bạn đã dùng hết {FREE_DAILY_SESSION_LIMIT} phiên Free hôm nay",
            )
        now = utcnow()
        lease_expires_at = now + timedelta(minutes=lease_minutes)
        row = CloudSandboxSession(
            user_id=auth.user.id,
            sandbox_tier="free",
            provider="local",
            mode="auto",
            lease_minutes=lease_minutes,
            status="ready",
            remote_url=None,
            ready_at=now,
            lease_expires_at=lease_expires_at,
            expires_at=lease_expires_at,
        )
    else:
        availability = cloud_sandbox_service.availability(requested, mode)
        if not availability["available"]:
            missing = ", ".join(availability["missing"])
            detail = availability["reason"]
            if missing:
                detail = f"{detail}: {missing}"
            raise HTTPException(
                503,
                f"Sandbox {requested.upper()} {mode} chưa được cấu hình hoặc chưa sẵn sàng ({detail})",
            )
        credit_cost = int(capability["creditCost"])
        wallet = wallet_for(db, auth.user.id)
        if wallet.credits < credit_cost:
            raise HTTPException(
                402,
                f"Bạn cần {credit_cost} credit để mở Sandbox {requested.upper()}",
            )
        wallet.credits -= credit_cost
        agent_token = create_session_token()
        now = utcnow()
        # The OS self-destruct deadline includes a bounded provisioning window.
        # Once ready, provision_task replaces the public expiry with ready+lease.
        hard_expires_at = now + timedelta(
            minutes=(
                settings.sandbox_cloud_provision_timeout_minutes + lease_minutes
            )
        )
        row = CloudSandboxSession(
            user_id=auth.user.id,
            sandbox_tier=requested,
            provider="aws",
            mode=mode,
            lease_minutes=lease_minutes,
            agent_token_hash=hashlib.sha256(agent_token.encode("utf-8")).hexdigest(),
            expires_at=hard_expires_at,
        )
    db.add(row)
    db.commit()
    db.refresh(row)
    if requested == "free":
        try:
            await asyncio.to_thread(free_web_sandbox.create, row.id, row.expires_at)
        except Exception as exc:
            row.status = "failed"
            row.error = str(exc)[:1000]
            db.commit()
            raise HTTPException(503, f"Không khởi động được Free Sandbox: {exc}") from exc
    else:
        # Starlette retains and runs this task after the response is sent.
        # A bare asyncio.create_task without a strong reference can be garbage
        # collected while EC2 provisioning is still awaiting network I/O.
        background_tasks.add_task(provision_task, row.id, agent_token)
    return session_dict(row)


@router.get("/sessions/{session_id}/browser")
def free_browser_state(session_id: str, auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict:
    row = require_free_session(db, session_id, auth.user.id)
    try:
        return free_web_sandbox.state(session_id)
    except KeyError:
        # Local browser state is in memory and disappears when uvicorn reloads.
        # Recreate the temporary profile for a still-valid persisted session.
        if row.expires_at <= utcnow():
            raise HTTPException(410, "free_browser_session_expired") from None
        try:
            return free_web_sandbox.create(row.id, row.expires_at)
        except Exception as exc:
            raise HTTPException(503, f"Không khôi phục được Free Sandbox: {exc}") from exc
    except TimeoutError as exc:
        raise HTTPException(410, str(exc)) from exc


def require_free_session(db: DbSession, session_id: str, user_id: str) -> CloudSandboxSession:
    row = db.get(CloudSandboxSession, session_id)
    if row is None or row.user_id != user_id or row.sandbox_tier != "free" or row.status != "ready":
        raise HTTPException(404, "Không tìm thấy Free Sandbox đang chạy")
    return row


@router.post("/sessions/{session_id}/browser/navigate")
def free_browser_navigate(payload: FreeNavigateInput, session_id: str, auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict:
    require_free_session(db, session_id, auth.user.id)
    try:
        return free_web_sandbox.navigate(session_id, payload.url)
    except PermissionError as exc:
        raise HTTPException(403, "URL nội bộ hoặc không công khai đã bị chặn") from exc
    except Exception as exc:
        raise HTTPException(502, f"Không mở được website: {exc}") from exc


@router.post("/sessions/{session_id}/browser/click")
def free_browser_click(payload: FreeClickInput, session_id: str, auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict:
    require_free_session(db, session_id, auth.user.id)
    try:
        return free_web_sandbox.click(session_id, payload.x, payload.y)
    except TimeoutError as exc:
        raise HTTPException(410, "Phiên Free Sandbox đã hết hạn") from exc
    except KeyError as exc:
        raise HTTPException(409, "Trình duyệt Sandbox vừa được khởi động lại; hãy tải lại phiên") from exc
    except Exception as exc:
        raise HTTPException(502, f"Không thực hiện được thao tác click: {exc}") from exc


@router.post("/sessions/{session_id}/browser/key")
def free_browser_key(payload: FreeKeyInput, session_id: str, auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict:
    require_free_session(db, session_id, auth.user.id)
    try:
        return free_web_sandbox.key(session_id, payload.key)
    except ValueError as exc:
        raise HTTPException(400, "Phím không được phép") from exc
    except TimeoutError as exc:
        raise HTTPException(410, "Phiên Free Sandbox đã hết hạn") from exc
    except KeyError as exc:
        raise HTTPException(409, "Trình duyệt Sandbox vừa được khởi động lại; hãy tải lại phiên") from exc
    except Exception as exc:
        raise HTTPException(502, f"Không gửi được phím vào Sandbox: {exc}") from exc


@router.post("/sessions/{session_id}/browser/type")
def free_browser_type(payload: FreeTypeInput, session_id: str, auth: CurrentSession, db: DbSession = Depends(get_db)) -> dict:
    require_free_session(db, session_id, auth.user.id)
    try:
        return free_web_sandbox.type_text(session_id, payload.text)
    except ValueError as exc:
        raise HTTPException(400, "Dữ liệu nhập không hợp lệ") from exc
    except TimeoutError as exc:
        raise HTTPException(410, "Phiên Free Sandbox đã hết hạn") from exc
    except KeyError as exc:
        raise HTTPException(409, "Trình duyệt Sandbox vừa được khởi động lại; hãy tải lại phiên") from exc
    except Exception as exc:
        raise HTTPException(502, f"Không điền được canary vào website: {exc}") from exc


@router.get("/sessions/{session_id}")
async def get_session(
    session_id: str,
    background_tasks: BackgroundTasks,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> dict:
    row = db.get(CloudSandboxSession, session_id)
    if row is None or row.user_id != auth.user.id:
        raise HTTPException(404, "Không tìm thấy phiên")
    if row.status in {"provisioning", "ready"} and session_has_expired(row):
        schedule_session_cleanup(
            background_tasks,
            db,
            row,
            reason="lease_expired",
        )
    elif row.status in {"termination_requested", "cleanup_failed", "terminating"}:
        background_tasks.add_task(cleanup_session_by_id, row.id)
    return session_dict(row)


def require_exe_session(db: DbSession, session_id: str, user_id: str) -> CloudSandboxSession:
    row = db.get(CloudSandboxSession, session_id)
    if row is None or row.user_id != user_id:
        raise HTTPException(404, "Không tìm thấy phiên")
    if not TIER_CAPABILITIES.get(row.sandbox_tier, {}).get("exe"):
        raise HTTPException(403, "Gói hiện tại không có EXE Sandbox")
    if row.status not in {"provisioning", "ready"} or session_has_expired(row):
        raise HTTPException(409, "Phiên EXE Sandbox không còn sẵn sàng")
    return row


@router.post("/sessions/{session_id}/exe")
async def upload_exe_for_cloud_sandbox(
    session_id: str,
    auth: CurrentSession,
    file: UploadFile = File(...),
    consent: bool = Form(False),
    db: DbSession = Depends(get_db),
) -> dict:
    row = require_exe_session(db, session_id, auth.user.id)
    if not consent:
        raise HTTPException(422, "Cần xác nhận gửi mẫu vào Windows Sandbox Cloud")
    if row.sample_status != "none":
        raise HTTPException(
            409,
            "Mỗi phiên EXE chỉ phân tích một file. Hãy kết thúc phiên và tạo phiên PRO mới.",
        )
    if not settings.sandbox_public_base_url:
        raise HTTPException(503, "Sandbox Cloud Agent chưa được cấu hình callback URL")
    try:
        filename = safe_sample_name(file.filename or "sample.exe")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not filename.lower().endswith((".exe", ".msi", ".bat", ".cmd", ".com", ".scr", ".ps1")):
        raise HTTPException(400, "Chỉ chấp nhận tệp thực thi Windows")
    content = await file.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(413, "File vượt giới hạn kích thước")
    if not content:
        raise HTTPException(400, "File rỗng")
    queued_at = utcnow()
    upload_claim = db.execute(
        update(CloudSandboxSession)
        .where(
            CloudSandboxSession.id == row.id,
            CloudSandboxSession.user_id == auth.user.id,
            CloudSandboxSession.status.in_(("provisioning", "ready")),
            CloudSandboxSession.sample_status == "none",
        )
        .values(
            sample_status="uploading",
            sample_report={
                "consent": True,
                "mode": row.mode,
                "phase": "uploading",
                "upload_started_at": queued_at.isoformat(),
            },
        )
    )
    db.commit()
    if upload_claim.rowcount != 1:
        raise HTTPException(
            409,
            "Mỗi phiên EXE chỉ nhận một file; một upload khác đã được chấp nhận",
        )

    try:
        await asyncio.to_thread(remove_session_samples, row.id)
        storage_path, sha256 = await asyncio.to_thread(
            store_sample,
            row.id,
            filename,
            content,
        )
    except Exception as exc:
        await asyncio.to_thread(remove_session_samples, row.id)
        db.execute(
            update(CloudSandboxSession)
            .where(
                CloudSandboxSession.id == row.id,
                CloudSandboxSession.sample_status == "uploading",
            )
            .values(sample_status="none", sample_report={})
        )
        db.commit()
        raise HTTPException(500, "Không lưu được mẫu Sandbox") from exc

    report = {
        "consent": True,
        "mode": row.mode,
        "phase": "queued",
        "queued_at": queued_at.isoformat(),
    }
    queued = db.execute(
        update(CloudSandboxSession)
        .where(
            CloudSandboxSession.id == row.id,
            CloudSandboxSession.status.in_(("provisioning", "ready")),
            CloudSandboxSession.sample_status == "uploading",
        )
        .values(
            sample_filename=filename,
            sample_storage_path=storage_path,
            sample_sha256=sha256,
            sample_size=len(content),
            sample_status="queued",
            sample_report=report,
            sample_uploaded_at=queued_at,
            sample_completed_at=None,
        )
    )
    db.commit()
    if queued.rowcount != 1:
        await asyncio.to_thread(remove_session_samples, row.id)
        db.execute(
            update(CloudSandboxSession)
            .where(
                CloudSandboxSession.id == row.id,
                CloudSandboxSession.sample_status == "uploading",
            )
            .values(
                sample_status="failed",
                sample_report={
                    "consent": True,
                    "mode": row.mode,
                    "phase": "failed",
                    "reason": "session_closed_during_upload",
                },
                sample_completed_at=utcnow(),
            )
        )
        db.commit()
        raise HTTPException(409, "Phiên Sandbox đã đóng trong lúc tải file")
    db.refresh(row)
    return session_dict(row)


def require_agent_session(
    db: DbSession,
    session_id: str,
    token: str | None,
    *,
    allow_report_grace: bool = False,
) -> CloudSandboxSession:
    row = db.get(CloudSandboxSession, session_id)
    if row is None or not verify_agent_token(row.agent_token_hash, token):
        raise HTTPException(401, "Sandbox agent không được xác thực")
    now = utcnow()
    deadline = effective_session_deadline(row)
    if allow_report_grace:
        grace_deadline = deadline + timedelta(
            seconds=max(0, min(settings.sandbox_agent_report_grace_seconds, 30))
        )
        allowed_state = row.status == "ready" or (
            row.status == "termination_requested"
            and row.termination_reason == "lease_expired"
        )
        if not allowed_state or now > grace_deadline:
            raise HTTPException(401, "Cửa sổ gửi báo cáo Sandbox đã đóng")
        return row
    if row.status == "provisioning":
        raise HTTPException(425, "Sandbox chưa ready; agent cần thử lại")
    if row.status != "ready":
        raise HTTPException(409, "Sandbox không còn nhận mẫu")
    if deadline <= now:
        raise HTTPException(410, "Sandbox lease đã hết hạn")
    return row


@router.get("/agent/sessions/{session_id}/bootstrap")
def agent_download_bootstrap(
    session_id: str,
    x_sandbox_agent_token: str | None = Header(default=None),
    db: DbSession = Depends(get_db),
):
    """Deliver the Windows agent without exceeding EC2's 16 KiB UserData limit."""
    row = db.get(CloudSandboxSession, session_id)
    if row is None or not verify_agent_token(row.agent_token_hash, x_sandbox_agent_token):
        raise HTTPException(401, "Sandbox agent không được xác thực")
    if row.status not in {"provisioning", "ready"}:
        raise HTTPException(409, "Sandbox không còn cấp agent")
    if effective_session_deadline(row) <= utcnow():
        raise HTTPException(410, "Sandbox lease đã hết hạn")
    agent_path = (
        Path(__file__).resolve().parents[2]
        / "server"
        / "sandbox-agent"
        / "PrewiseSandboxAgent.ps1"
    )
    if not agent_path.is_file():
        raise HTTPException(503, "Windows Sandbox agent chưa được đóng gói")
    report = dict(row.sample_report or {})
    report["agent_bootstrap_at"] = utcnow().isoformat()
    row.sample_report = report
    db.commit()
    return FileResponse(
        agent_path,
        filename="PrewiseSandboxAgent.ps1",
        media_type="text/plain; charset=utf-8",
    )


@router.get("/agent/sessions/{session_id}/exe")
def agent_download_exe(
    session_id: str,
    x_sandbox_agent_token: str | None = Header(default=None),
    db: DbSession = Depends(get_db),
):
    row = require_agent_session(db, session_id, x_sandbox_agent_token)
    if row.sample_status not in {"queued", "delivered"} or not row.sample_storage_path:
        raise HTTPException(404, "Không có mẫu chờ phân tích")
    path = Path(row.sample_storage_path)
    if not path.is_file():
        raise HTTPException(410, "Mẫu đã hết hạn")
    row.sample_status = "delivered"
    db.commit()
    filename = row.sample_filename or "sample.exe"
    lease_deadline = row.lease_expires_at
    lease_seconds = (
        max(0, int((lease_deadline - utcnow()).total_seconds()))
        if lease_deadline
        else row.lease_minutes * 60
    )
    return FileResponse(
        path,
        filename=filename,
        media_type="application/octet-stream",
        headers={
            "X-Sandbox-Sample-Filename": filename,
            "X-Sandbox-Mode": row.mode,
            "X-Sandbox-Lease-Seconds": str(lease_seconds),
            "X-Sandbox-Auto-Execute": (
                "false" if row.mode == "interactive" else "true"
            ),
        },
    )


@router.post("/agent/sessions/{session_id}/report")
def agent_submit_report(
    session_id: str,
    payload: SandboxAgentReport,
    background_tasks: BackgroundTasks,
    x_sandbox_agent_token: str | None = Header(default=None),
    db: DbSession = Depends(get_db),
) -> dict:
    row = require_agent_session(
        db,
        session_id,
        x_sandbox_agent_token,
        allow_report_grace=True,
    )
    if row.sample_status not in {"queued", "delivered", "staged", "running"}:
        raise HTTPException(409, "Không có mẫu đang chờ báo cáo")
    if payload.mode is not None and payload.mode != row.mode:
        raise HTTPException(409, "Sandbox agent report sai chế độ phiên")
    phase = payload.phase or payload.status
    if payload.phase is not None and payload.phase != payload.status:
        raise HTTPException(422, "status và phase phải đồng nhất")
    transitions = {
        "queued": {"staged", "running", "completed", "failed"},
        "delivered": {"staged", "running", "completed", "failed"},
        "staged": {"staged", "running", "completed", "failed"},
        "running": {"running", "completed", "failed"},
    }
    if phase not in transitions[row.sample_status]:
        raise HTTPException(409, "Chuyển phase Sandbox không hợp lệ")
    row.sample_status = phase
    report = dict(row.sample_report or {})
    report.update(payload.model_dump(mode="json", exclude_none=True))
    report.update(
        {
            "status": phase,
            "phase": phase,
            "mode": row.mode,
            "updated_at": utcnow().isoformat(),
        }
    )
    row.sample_report = report
    row.sample_completed_at = utcnow() if phase in {"completed", "failed"} else None
    db.commit()
    cleanup_scheduled = schedule_completed_auto_cleanup(background_tasks, db, row)
    return {
        "ok": True,
        "mode": row.mode,
        "phase": phase,
        "cleanupScheduled": cleanup_scheduled,
    }


@router.post("/sessions/{session_id}/remote-access")
async def issue_remote_access(
    session_id: str,
    response: Response,
    background_tasks: BackgroundTasks,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> dict:
    """Issue one browser handshake credential for an interactive lease."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    row = db.execute(
        select(CloudSandboxSession)
        .where(
            CloudSandboxSession.id == session_id,
            CloudSandboxSession.user_id == auth.user.id,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Không tìm thấy phiên")
    if row.mode != "interactive":
        raise HTTPException(409, "Auto Sandbox không cung cấp remote desktop")
    if row.status in {"provisioning", "ready"} and session_has_expired(row):
        schedule_session_cleanup(
            background_tasks,
            db,
            row,
            reason="lease_expired",
        )
    if row.status != "ready":
        raise HTTPException(409, f"Interactive Sandbox chưa sẵn sàng: {row.status}")
    broker_availability = cloud_sandbox_service.broker_availability()
    if not broker_availability["available"]:
        raise HTTPException(
            503,
            "Remote broker chưa sẵn sàng "
            f"({broker_availability['reason'] or 'unavailable'})",
        )
    if not row.remote_url:
        raise HTTPException(503, "Remote broker chưa công bố URL phiên")
    if not row.provider_instance_id:
        raise HTTPException(503, "Remote broker chưa gắn phiên với máy ảo")
    if row.lease_expires_at is None:
        raise HTTPException(503, "Interactive Sandbox chưa có lease điều khiển")
    if row.sample_status not in {"staged", "running"}:
        raise HTTPException(
            409,
            "Mẫu chưa được agent đặt an toàn vào Interactive Sandbox",
        )
    if len(settings.sandbox_remote_broker_secret.encode("utf-8")) < 32:
        raise HTTPException(503, "Remote broker authentication chưa được cấu hình")
    if not 15 <= settings.sandbox_remote_access_token_ttl_seconds <= 300:
        raise HTTPException(503, "Remote access token TTL chưa được cấu hình an toàn")

    now = utcnow()
    lease_expires_at = row.lease_expires_at
    token_expires_at = min(
        now + timedelta(seconds=settings.sandbox_remote_access_token_ttl_seconds),
        lease_expires_at,
    )
    if token_expires_at <= now:
        raise HTTPException(410, "Interactive Sandbox đã hết thời gian")
    access_token = create_session_token()
    try:
        connect_url = cloud_sandbox_service.browser_access_url(
            row.remote_url,
            session_id=row.id,
            access_token=access_token,
        )
    except RuntimeError as exc:
        raise HTTPException(503, "Remote broker URL không hợp lệ") from exc
    row.remote_access_token_hash = hashlib.sha256(
        access_token.encode("utf-8")
    ).hexdigest()
    row.remote_access_token_expires_at = token_expires_at
    row.remote_access_token_used_at = None
    db.commit()
    return {
        "sessionId": row.id,
        "mode": row.mode,
        # remoteUrl is kept for current clients; connectUrl makes the handshake
        # semantics explicit for new web/desktop clients.
        "remoteUrl": connect_url,
        "connectUrl": connect_url,
        "accessToken": access_token,
        "tokenExpiresAt": token_expires_at.isoformat(),
        "leaseExpiresAt": lease_expires_at.isoformat(),
        "oneTime": True,
    }


@router.post("/broker/remote-access/consume")
def consume_remote_access(
    payload: ConsumeRemoteAccessInput,
    x_sandbox_broker_secret: str | None = Header(default=None),
    db: DbSession = Depends(get_db),
) -> dict:
    """Atomically consume one token from the trusted remote desktop broker.

    The response intentionally contains no Windows/RDP credentials. The broker
    receives only the already-bound user/session/instance authorization tuple.
    """
    expected_secret = settings.sandbox_remote_broker_secret
    if len(expected_secret.encode("utf-8")) < 32:
        raise HTTPException(503, "Remote broker authentication chưa được cấu hình")
    if not x_sandbox_broker_secret or not secrets.compare_digest(
        x_sandbox_broker_secret,
        expected_secret,
    ):
        raise HTTPException(401, "Remote broker không được xác thực")

    row = db.get(CloudSandboxSession, payload.sessionId)
    if row is None:
        raise HTTPException(401, "Remote access token không hợp lệ")
    now = utcnow()
    token_hash = hashlib.sha256(payload.accessToken.encode("utf-8")).hexdigest()
    consumed = db.execute(
        update(CloudSandboxSession)
        .where(
            CloudSandboxSession.id == payload.sessionId,
            CloudSandboxSession.user_id == row.user_id,
            CloudSandboxSession.mode == "interactive",
            CloudSandboxSession.status == "ready",
            CloudSandboxSession.sample_status.in_(("staged", "running")),
            CloudSandboxSession.provider_instance_id.is_not(None),
            CloudSandboxSession.remote_url.is_not(None),
            CloudSandboxSession.remote_access_token_hash == token_hash,
            CloudSandboxSession.remote_access_token_used_at.is_(None),
            CloudSandboxSession.remote_access_token_expires_at > now,
            CloudSandboxSession.lease_expires_at > now,
        )
        .values(remote_access_token_used_at=now)
    )
    if consumed.rowcount != 1:
        db.rollback()
        raise HTTPException(401, "Remote access token không hợp lệ hoặc đã sử dụng")
    db.commit()
    return {
        "authorized": True,
        "sessionId": row.id,
        "userId": row.user_id,
        "provider": row.provider,
        "providerInstanceId": row.provider_instance_id,
        "leaseExpiresAt": row.lease_expires_at.isoformat(),
    }


@router.delete("/sessions/{session_id}")
async def stop_session(
    session_id: str,
    background_tasks: BackgroundTasks,
    auth: CurrentSession,
    db: DbSession = Depends(get_db),
) -> dict:
    row = db.execute(
        select(CloudSandboxSession)
        .where(
            CloudSandboxSession.id == session_id,
            CloudSandboxSession.user_id == auth.user.id,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Không tìm thấy phiên")
    if row.status in TERMINAL_SESSION_STATES and row.cleanup_completed_at:
        return {"ok": True, "status": row.status, "cleanupPending": False}
    schedule_session_cleanup(
        background_tasks,
        db,
        row,
        reason="user_requested",
    )
    return {
        "ok": True,
        "status": row.status,
        "cleanupPending": True,
    }
