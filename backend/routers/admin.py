"""Admin API routes backed by persistent admin job records."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from typing import Literal

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as DbSession

from backend.config import settings
from backend.db import SessionLocal, get_db
from backend.models import (
    AdminJob,
    AdminJobEvent,
    AssessmentCache,
    ModelVersion,
    PaymentOrder,
    Plan,
    ScanEvent,
    Subscription,
    User,
)
from backend.routers.auth import require_admin
from backend.security_utils import utcnow
from backend.services.ai_context_weight_service import (
    AI_CONTEXT_WEIGHT_ABSOLUTE_MAX_PERCENT,
    get_ai_context_weight_policy,
    get_operational_switches,
    get_url_assessment_cache_enabled,
    set_ai_context_weight_policy,
    set_operational_switches,
    set_url_assessment_cache_enabled,
)
from backend.services.llm_provider_config_service import (
    get_runtime_llm_config,
    get_user_llm_policy,
    safe_config_payload,
    save_runtime_llm_config,
    test_runtime_llm_config,
)
from backend.services.operational_maintenance_service import (
    cleanup_expired_operational_data,
    normalized_scan_history_retention_days,
)
from backend.services.threat_feed_service import (
    REMOTE_FEED_SOURCES,
    configured_feed_specs,
    feed_status,
    sync_configured_feeds,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])

SPECS_DIR = Path(".kiro/specs").resolve()
TRAINING_DATA_DIR = Path("data").resolve()
MODEL_CANDIDATE_DIR = Path(".aisec-data/model-candidates").resolve()

TRAINING_SCRIPTS: dict[str, tuple[Path, list[str], str]] = {
    "text": (
        Path("ai/training/train_real_text_classifier.py").resolve(),
        ["--train", "{data}", "--validation", "{data}", "--test", "{data}"],
        "mdeberta_text.onnx",
    ),
    "prompt": (
        Path("ai/training/train_real_prompt_classifier.py").resolve(),
        ["--train", "{data}", "--validation", "{data}", "--test", "{data}"],
        "protectai_prompt.onnx",
    ),
    "url": (
        Path("ai/training/train_url_lgbm.py").resolve(),
        ["--data", "{data}"],
        "url_lgbm.onnx",
    ),
}


class SpecExecutionRequest(BaseModel):
    specId: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
    mode: Literal["all", "remaining"] = "remaining"


class ModelTrainingRequest(BaseModel):
    dataPath: str
    models: list[Literal["text", "prompt", "url"]] = Field(min_length=1, max_length=1)


class UserStatusRequest(BaseModel):
    status: Literal["active", "suspended"]


class AIContextWeightRequest(BaseModel):
    percent: int = Field(ge=0, le=AI_CONTEXT_WEIGHT_ABSOLUTE_MAX_PERCENT)
    minPercent: int | None = Field(default=None, ge=0, le=AI_CONTEXT_WEIGHT_ABSOLUTE_MAX_PERCENT)
    maxPercent: int | None = Field(default=None, ge=0, le=AI_CONTEXT_WEIGHT_ABSOLUTE_MAX_PERCENT)


class LLMProviderSettingsRequest(BaseModel):
    provider: Literal["auto", "adapter", "local", "endpoint"]
    baseUrl: str = Field(default="", max_length=1000)
    model: str = Field(default="", max_length=300)
    apiKey: str | None = Field(default=None, max_length=2000)
    clearApiKey: bool = False
    allowedProviders: list[Literal["auto", "adapter", "local", "endpoint"]] | None = None
    allowedModels: list[str] | None = Field(default=None, max_length=100)


class URLAssessmentCacheRequest(BaseModel):
    enabled: bool


class OperationalSwitchesRequest(BaseModel):
    threatFeedSchedulerEnabled: bool
    openphishEnabled: bool
    operationalMaintenanceSchedulerEnabled: bool


class ThreatFeedSyncRequest(BaseModel):
    """A bounded, allowlisted subset of configured remote threat feeds."""

    sources: list[str] | None = Field(default=None, max_length=3)

    @field_validator("sources")
    @classmethod
    def validate_sources(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        normalized = [source.strip().lower() for source in value]
        if not normalized or any(source not in REMOTE_FEED_SOURCES for source in normalized):
            raise ValueError("Only configured PhishTank, OpenPhish, or URLhaus feeds may be synced")
        if len(set(normalized)) != len(normalized):
            raise ValueError("Threat-feed sources must be unique")
        return normalized


def _contained_file(base: Path, candidate: Path, *, suffixes: set[str]) -> Path:
    resolved = candidate.resolve()
    if not resolved.is_relative_to(base) or resolved.suffix.lower() not in suffixes:
        raise HTTPException(status_code=400, detail="Invalid file path")
    if not resolved.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return resolved


def _spec_tasks_file(spec_id: str) -> Path:
    return _contained_file(SPECS_DIR, SPECS_DIR / spec_id / "tasks.md", suffixes={".md"})


def _training_data_file(data_path: str) -> Path:
    candidate = Path(data_path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return _contained_file(TRAINING_DATA_DIR, candidate, suffixes={".csv", ".jsonl"})


def _training_unavailable_reason(
    data_path: str,
    models: list[str],
    *,
    prepare_output: bool = False,
) -> str | None:
    """Return a user-safe preflight failure instead of accepting a doomed job."""

    try:
        _training_data_file(data_path)
    except HTTPException as exc:
        if exc.status_code == 404:
            return "Training dataset is not installed in this deployment."
        return str(exc.detail)

    missing_scripts = [
        model_name
        for model_name in models
        if model_name not in TRAINING_SCRIPTS or not TRAINING_SCRIPTS[model_name][0].is_file()
    ]
    if missing_scripts:
        return f"Training executor is unavailable for: {', '.join(missing_scripts)}."

    if prepare_output:
        try:
            MODEL_CANDIDATE_DIR.mkdir(parents=True, exist_ok=True)
        except OSError:
            return "Training output storage is not writable in this deployment."
    write_target = (
        MODEL_CANDIDATE_DIR
        if MODEL_CANDIDATE_DIR.is_dir()
        else MODEL_CANDIDATE_DIR.parent
    )
    if not write_target.is_dir() or not os.access(write_target, os.W_OK):
        return "Training output storage is not writable in this deployment."
    if hasattr(os, "statvfs"):
        try:
            if os.statvfs(write_target).f_flag & getattr(os, "ST_RDONLY", 1):
                return "Training output storage is read-only in this deployment."
        except OSError:
            return "Training output storage is unavailable in this deployment."
    return None


def _training_metrics(stdout: str) -> dict[str, float]:
    """Extract the stable top-level metrics emitted by the training scripts."""

    try:
        payload = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return {}
    raw_metrics = payload.get("metrics", {}) if isinstance(payload, dict) else {}
    if isinstance(raw_metrics, dict) and isinstance(raw_metrics.get("test"), dict):
        raw_metrics = raw_metrics["test"]
    if not isinstance(raw_metrics, dict):
        return {}
    return {
        key: float(raw_metrics[key])
        for key in ("f1", "f1_score", "accuracy")
        if isinstance(raw_metrics.get(key), (int, float))
    }


def _job_payload(job: AdminJob | None, *, spec_id: str | None = None) -> dict:
    if job is None:
        if spec_id is not None:
            return {
                "specId": spec_id,
                "status": "idle",
                "progress": 0,
                "currentTask": None,
                "message": None,
            }
        return {
            "status": "idle",
            "progress": 0,
            "currentModel": None,
            "message": None,
            "results": [],
        }

    if job.job_type == "spec_execution":
        return {
            "jobId": job.id,
            "specId": job.spec_id,
            "status": "running" if job.status == "running" else job.status,
            "currentTask": job.current_step,
            "progress": job.progress,
            "message": job.error if job.status == "failed" else (job.message or job.error),
        }

    return {
        "jobId": job.id,
        "status": "training" if job.status == "running" else job.status,
        "currentModel": job.current_step,
        "progress": job.progress,
        "message": job.error if job.status == "failed" else (job.message or job.error),
        "results": (job.result or {}).get("results", []),
    }


def _update_job(job_id: str, **fields) -> None:
    with SessionLocal() as db:
        job = db.get(AdminJob, job_id)
        if job is None:
            return
        for key, value in fields.items():
            setattr(job, key, value)
        job.updated_at = utcnow()
        db.commit()


def _add_job_event(job_id: str, message: str, level: str = "info", metadata: dict | None = None) -> None:
    with SessionLocal() as db:
        db.add(
            AdminJobEvent(
                job_id=job_id,
                level=level,
                message=message,
                extra_metadata=metadata or {},
            )
        )
        db.commit()


@router.get("/specs")
async def list_specs():
    specs_dir = SPECS_DIR
    if not specs_dir.exists():
        return {
            "specs": [],
            "execution": {
                "enabled": False,
                "reason": "Spec registry is not installed in this deployment.",
            },
        }

    specs = []
    for spec_path in specs_dir.iterdir():
        if not spec_path.is_dir():
            continue
        tasks_file = spec_path / "tasks.md"
        if not tasks_file.exists():
            continue
        try:
            content = tasks_file.read_text(encoding="utf-8")
            total = 0
            completed = 0
            for line in content.splitlines():
                if line.strip().startswith("- ["):
                    total += 1
                    if line.strip().startswith(("- [x]", "- [X]")):
                        completed += 1
            specs.append(
                {
                    "id": spec_path.name,
                    "name": spec_path.name.replace("-", " ").title(),
                    "path": str(spec_path),
                    "tasksTotal": total,
                    "tasksCompleted": completed,
                    "tasksRemaining": total - completed,
                }
            )
        except Exception as exc:
            logger.error("Error parsing spec %s: %s", spec_path, exc)
    return {
        "specs": specs,
        "execution": {
            "enabled": False,
            "reason": "Spec execution is disabled because no real task executor is configured.",
        },
    }


def _display_risk_score(score: float) -> int:
    """Convert the persisted normalized score to the admin UI's 0..100 scale."""

    return round(max(0.0, min(1.0, float(score))) * 100)


@router.get("/overview")
def get_overview(db: DbSession = Depends(get_db)) -> dict:
    """Compact operational snapshot used by the desktop administration console."""
    users_total = db.scalar(select(func.count()).select_from(User)) or 0
    active_users = db.scalar(select(func.count()).select_from(User).where(User.status == "active")) or 0
    scans_total = db.scalar(select(func.count()).select_from(ScanEvent)) or 0
    dangerous_scans = db.scalar(
        select(func.count())
        .select_from(ScanEvent)
        .where(ScanEvent.risk_level.in_(("high", "critical")))
    ) or 0
    avg_latency = db.scalar(select(func.avg(ScanEvent.latency_ms))) or 0
    return {
        "metrics": {"usersTotal": users_total, "activeUsers": active_users, "scansTotal": scans_total,
                    "dangerousScans": dangerous_scans, "averageLatencyMs": round(float(avg_latency))},
        "recentScans": [
            {"id": scan.id, "createdAt": scan.created_at.isoformat(), "modality": scan.modality,
             "riskLevel": scan.risk_level, "score": _display_risk_score(scan.risk_score), "target": scan.normalized_url or scan.input_preview or "Nội dung đã ẩn"}
            for scan in db.execute(select(ScanEvent).order_by(ScanEvent.created_at.desc()).limit(8)).scalars()
        ],
        "recentJobs": [
            {"id": job.id, "type": job.job_type, "status": job.status, "progress": job.progress,
             "message": job.message or job.current_step, "createdAt": job.created_at.isoformat()}
            for job in db.execute(select(AdminJob).order_by(AdminJob.created_at.desc()).limit(6)).scalars()
        ],
        "models": [
            {"id": model.id, "name": model.model_name, "modality": model.modality, "status": model.status,
             "f1": model.f1, "accuracy": model.accuracy, "createdAt": model.created_at.isoformat()}
            for model in db.execute(select(ModelVersion).order_by(ModelVersion.created_at.desc()).limit(8)).scalars()
        ],
    }


@router.get("/finance")
def get_finance_overview(db: DbSession = Depends(get_db)) -> dict:
    """Read-only revenue, order, subscription, and plan snapshot for admins."""

    now = utcnow()
    last_30_days = now - timedelta(days=30)
    last_180_days = now - timedelta(days=180)

    total_revenue = db.scalar(
        select(func.sum(PaymentOrder.amount_vnd)).where(PaymentOrder.status == "paid")
    ) or 0
    revenue_30d = db.scalar(
        select(func.sum(PaymentOrder.amount_vnd)).where(
            PaymentOrder.status == "paid", PaymentOrder.paid_at >= last_30_days
        )
    ) or 0
    pending_amount = db.scalar(
        select(func.sum(PaymentOrder.amount_vnd)).where(
            PaymentOrder.status == "pending",
            (PaymentOrder.expires_at.is_(None) | (PaymentOrder.expires_at > now)),
        )
    ) or 0
    paid_orders = db.scalar(
        select(func.count()).select_from(PaymentOrder).where(PaymentOrder.status == "paid")
    ) or 0
    pending_orders = db.scalar(
        select(func.count()).select_from(PaymentOrder).where(PaymentOrder.status == "pending")
    ) or 0
    active_subscriptions = db.scalar(
        select(func.count()).select_from(Subscription).where(Subscription.status == "active")
    ) or 0

    plan_distribution = {
        str(tier): int(count)
        for tier, count in db.execute(
            select(Subscription.plan_tier, func.count())
            .where(Subscription.status == "active")
            .group_by(Subscription.plan_tier)
        )
    }

    monthly_totals: dict[str, int] = {}
    paid_rows = db.execute(
        select(PaymentOrder.paid_at, PaymentOrder.amount_vnd).where(
            PaymentOrder.status == "paid", PaymentOrder.paid_at >= last_180_days
        )
    ).all()
    for paid_at, amount_vnd in paid_rows:
        if paid_at is None:
            continue
        key = paid_at.strftime("%Y-%m")
        monthly_totals[key] = monthly_totals.get(key, 0) + int(amount_vnd)

    recent_orders = [
        {
            "id": order.id,
            "reference": order.reference,
            "email": email,
            "amountVnd": order.amount_vnd,
            "planTier": order.plan_tier,
            "billingPeriod": order.billing_period,
            "status": order.status,
            "provider": order.provider,
            "paidAt": order.paid_at.isoformat() if order.paid_at else None,
            "createdAt": order.created_at.isoformat(),
        }
        for order, email in db.execute(
            select(PaymentOrder, User.email)
            .join(User, User.id == PaymentOrder.user_id)
            .order_by(PaymentOrder.created_at.desc())
            .limit(12)
        ).all()
    ]

    return {
        "summary": {
            "totalRevenueVnd": int(total_revenue),
            "revenueLast30DaysVnd": int(revenue_30d),
            "pendingAmountVnd": int(pending_amount),
            "paidOrders": int(paid_orders),
            "pendingOrders": int(pending_orders),
            "activeSubscriptions": int(active_subscriptions),
        },
        "planDistribution": plan_distribution,
        "monthlyRevenue": [
            {"month": month, "amountVnd": amount}
            for month, amount in sorted(monthly_totals.items())
        ],
        "plans": [
            {
                "tier": plan.tier,
                "label": plan.label,
                "monthlyPriceVnd": plan.monthly_price_vnd,
                "yearlyPriceVnd": plan.yearly_price_vnd,
            }
            for plan in db.execute(select(Plan).order_by(Plan.monthly_price_vnd)).scalars()
        ],
        "recentOrders": recent_orders,
    }


@router.get("/operational-metrics")
def get_operational_metrics(db: DbSession = Depends(get_db)) -> dict:
    """Low-cardinality scan/core metrics for the admin console and on-call checks."""

    window_start = utcnow() - timedelta(hours=24)
    total_scans = db.scalar(select(func.count()).select_from(ScanEvent)) or 0
    scans_24h = db.scalar(
        select(func.count()).select_from(ScanEvent).where(ScanEvent.created_at >= window_start)
    ) or 0
    blocked_24h = db.scalar(
        select(func.count())
        .select_from(ScanEvent)
        .where(ScanEvent.created_at >= window_start, ScanEvent.decision == "BLOCK")
    ) or 0
    avg_latency_24h = db.scalar(
        select(func.avg(ScanEvent.latency_ms)).where(ScanEvent.created_at >= window_start)
    ) or 0
    last_scan_at = db.scalar(select(func.max(ScanEvent.created_at)))

    def grouped(column) -> dict[str, int]:
        return {
            str(key): int(count)
            for key, count in db.execute(
                select(column, func.count())
                .where(ScanEvent.created_at >= window_start)
                .group_by(column)
            )
        }

    return {
        "windowHours": 24,
        "windowStart": window_start.isoformat(),
        "totalScans": int(total_scans),
        "scansLast24h": int(scans_24h),
        "blockedLast24h": int(blocked_24h),
        "blockRateLast24h": round((float(blocked_24h) / scans_24h) * 100, 2)
        if scans_24h
        else 0.0,
        "averageLatencyMsLast24h": round(float(avg_latency_24h), 2),
        "lastScanAt": last_scan_at.isoformat() if last_scan_at else None,
        "byDecisionLast24h": grouped(ScanEvent.decision),
        "byRiskLevelLast24h": grouped(ScanEvent.risk_level),
        "byModalityLast24h": grouped(ScanEvent.modality),
        "retention": {
            "scanHistoryDays": normalized_scan_history_retention_days(),
            "schedulerEnabled": settings.operational_maintenance_scheduler_enabled,
            "schedulerIntervalMinutes": max(5, settings.operational_maintenance_interval_minutes),
        },
    }


@router.post("/maintenance/cleanup")
def run_operational_cleanup(db: DbSession = Depends(get_db)) -> dict:
    """Run retention cleanup on demand; scheduled cleanup is configured separately."""

    result = cleanup_expired_operational_data(db)
    return {
        "ok": True,
        "retentionDays": normalized_scan_history_retention_days(),
        "deleted": result.as_dict(),
    }


@router.get("/settings/ai-context-weight")
def get_ai_context_weight(db: DbSession = Depends(get_db)) -> dict:
    policy = get_ai_context_weight_policy(db)
    return {
        **policy,
        "absoluteMaxPercent": AI_CONTEXT_WEIGHT_ABSOLUTE_MAX_PERCENT,
        "mode": "shadow" if policy["percent"] == 0 else "weighted",
    }


@router.put("/settings/ai-context-weight")
def update_ai_context_weight(
    payload: AIContextWeightRequest,
    auth=Depends(require_admin),
    db: DbSession = Depends(get_db),
) -> dict:
    current = get_ai_context_weight_policy(db)
    try:
        policy = set_ai_context_weight_policy(
            db,
            percent=payload.percent,
            min_percent=payload.minPercent if payload.minPercent is not None else current["minPercent"],
            max_percent=payload.maxPercent if payload.maxPercent is not None else current["maxPercent"],
            updated_by_user_id=auth.user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        **policy,
        "absoluteMaxPercent": AI_CONTEXT_WEIGHT_ABSOLUTE_MAX_PERCENT,
        "mode": "shadow" if policy["percent"] == 0 else "weighted",
    }


@router.get("/settings/llm-provider")
def get_llm_provider_settings(db: DbSession = Depends(get_db)) -> dict:
    """Return provider-safe configuration; the API key is never returned."""

    try:
        return {**safe_config_payload(get_runtime_llm_config(db)), **get_user_llm_policy(db)}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.put("/settings/llm-provider")
def update_llm_provider_settings(
    payload: LLMProviderSettingsRequest,
    auth=Depends(require_admin),
    db: DbSession = Depends(get_db),
) -> dict:
    try:
        configured = save_runtime_llm_config(
            db,
            provider=payload.provider,
            base_url=payload.baseUrl,
            model=payload.model,
            api_key=payload.apiKey,
            clear_api_key=payload.clearApiKey,
            updated_by_user_id=auth.user.id,
            allowed_user_providers=payload.allowedProviders,
            allowed_user_models=payload.allowedModels,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Services are process-local singletons. Rebuild them so new scans use the
    # saved provider immediately without a backend restart.
    from backend.dependencies import (
        get_adapter_registry,
        get_explanation_service,
        get_inference_service,
    )

    get_explanation_service.cache_clear()
    get_inference_service.cache_clear()
    get_adapter_registry.cache_clear()
    # The demo URL router keeps a module-level reference for model reuse.
    # Replace it as well so the product scan path observes this update now.
    from backend.demo import routes as demo_routes

    demo_routes.inference_service = get_inference_service()
    return {**safe_config_payload(configured), **get_user_llm_policy(db)}


@router.post("/settings/llm-provider/test")
def test_llm_provider_settings(db: DbSession = Depends(get_db)) -> dict:
    try:
        return test_runtime_llm_config(get_runtime_llm_config(db))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Endpoint trả về HTTP {exc.response.status_code}; kiểm tra API key và model.",
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Không kết nối được endpoint: {type(exc).__name__}",
        ) from exc


@router.get("/settings/url-assessment-cache")
def get_url_assessment_cache(db: DbSession = Depends(get_db)) -> dict:
    return {
        "enabled": get_url_assessment_cache_enabled(
            db,
            default=settings.shared_assessment_cache_enabled,
        ),
        "ttlSeconds": settings.shared_assessment_cache_ttl_seconds,
    }


@router.put("/settings/url-assessment-cache")
def update_url_assessment_cache(
    payload: URLAssessmentCacheRequest,
    auth=Depends(require_admin),
    db: DbSession = Depends(get_db),
) -> dict:
    enabled = set_url_assessment_cache_enabled(
        db,
        payload.enabled,
        updated_by_user_id=auth.user.id,
    )
    return {
        "enabled": enabled,
        "ttlSeconds": settings.shared_assessment_cache_ttl_seconds,
    }


@router.delete("/settings/url-assessment-cache")
def purge_url_assessment_cache(db: DbSession = Depends(get_db)) -> dict:
    """Remove every saved URL result without touching unrelated cache entries."""

    result = db.execute(delete(AssessmentCache).where(AssessmentCache.modality == "url"))
    db.commit()
    return {"purged": int(result.rowcount or 0)}


def _operational_switches(db: DbSession) -> dict[str, bool]:
    return get_operational_switches(
        db,
        threat_feed_scheduler_default=settings.threat_feed_scheduler_enabled,
        openphish_default=settings.threat_feed_openphish_enabled,
        maintenance_scheduler_default=settings.operational_maintenance_scheduler_enabled,
    )


@router.get("/settings/operations")
def get_operational_switch_settings(db: DbSession = Depends(get_db)) -> dict:
    return _operational_switches(db)


@router.put("/settings/operations")
def update_operational_switch_settings(
    payload: OperationalSwitchesRequest,
    auth=Depends(require_admin),
    db: DbSession = Depends(get_db),
) -> dict:
    return set_operational_switches(
        db,
        threat_feed_scheduler_enabled=payload.threatFeedSchedulerEnabled,
        openphish_enabled=payload.openphishEnabled,
        operational_maintenance_scheduler_enabled=payload.operationalMaintenanceSchedulerEnabled,
        updated_by_user_id=auth.user.id,
    )


@router.get("/threat-feeds")
def get_threat_feed_status(db: DbSession = Depends(get_db)) -> dict:
    """Return provider-safe state; endpoint URLs and credentials stay private."""
    switches = _operational_switches(db)
    return {
        "schedulerEnabled": switches["threatFeedSchedulerEnabled"],
        "feeds": feed_status(db, openphish_enabled=switches["openphishEnabled"]),
    }


@router.post("/threat-feeds/sync", status_code=202)
def trigger_threat_feed_sync(
    background_tasks: BackgroundTasks,
    payload: ThreatFeedSyncRequest = ThreatFeedSyncRequest(),
    db: DbSession = Depends(get_db),
) -> dict:
    switches = _operational_switches(db)
    configured = {
        spec.source: spec
        for spec in configured_feed_specs(openphish_enabled=switches["openphishEnabled"])
    }
    requested = tuple(payload.sources) if payload.sources is not None else tuple(configured)
    enabled = tuple(source for source in requested if configured[source].enabled)
    if not enabled:
        raise HTTPException(status_code=409, detail="No requested threat-feed source is enabled")
    background_tasks.add_task(
        sync_configured_feeds,
        enabled,
        openphish_enabled=switches["openphishEnabled"],
    )
    return {
        "status": "queued",
        "sources": list(enabled),
        "rateLimitHonored": True,
    }


@router.get("/users")
def list_users(db: DbSession = Depends(get_db)) -> dict:
    users = list(db.execute(select(User).order_by(User.created_at.desc()).limit(100)).scalars())
    subscriptions: dict[str, Subscription] = {}
    for subscription in db.execute(
        select(Subscription).order_by(Subscription.created_at.desc())
    ).scalars():
        subscriptions.setdefault(subscription.user_id, subscription)
    scan_counts = {
        str(user_id): int(count)
        for user_id, count in db.execute(
            select(ScanEvent.user_id, func.count())
            .where(ScanEvent.user_id.is_not(None))
            .group_by(ScanEvent.user_id)
        )
    }
    return {"users": [
        {"id": user.id, "displayName": user.display_name, "email": user.email, "role": user.role,
         "status": user.status, "createdAt": user.created_at.isoformat(),
         "lastLoginAt": user.last_login_at.isoformat() if user.last_login_at else None,
         "currentPlan": subscriptions[user.id].plan_tier if user.id in subscriptions else "free",
         "subscriptionStatus": subscriptions[user.id].status if user.id in subscriptions else None,
         "scansTotal": scan_counts.get(user.id, 0)}
        for user in users
    ]}


@router.patch("/users/{user_id}/status")
def update_user_status(user_id: str, payload: UserStatusRequest, auth=Depends(require_admin), db: DbSession = Depends(get_db)) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy người dùng.")
    if user.id == auth.user.id and payload.status != "active":
        raise HTTPException(status_code=400, detail="Không thể tự khóa tài khoản quản trị đang dùng.")
    user.status = payload.status
    db.commit()
    return {"id": user.id, "status": user.status}


@router.post("/specs/execute")
async def execute_spec_tasks(
    request: SpecExecutionRequest,
):
    _spec_tasks_file(request.specId)
    raise HTTPException(
        status_code=501,
        detail="Spec execution is disabled because no real task executor is configured.",
    )


@router.get("/specs/{spec_id}/status")
async def get_spec_execution_status(spec_id: str, db: DbSession = Depends(get_db)):
    job = db.execute(
        select(AdminJob)
        .where(AdminJob.job_type == "spec_execution", AdminJob.spec_id == spec_id)
        .order_by(AdminJob.created_at.desc())
    ).scalar_one_or_none()
    return {
        **_job_payload(job, spec_id=spec_id),
        "enabled": False,
        "unavailableReason": (
            "Spec execution is disabled because no real task executor is configured."
        ),
    }


@router.post("/models/train")
async def train_models(
    request: ModelTrainingRequest,
    background_tasks: BackgroundTasks,
    db: DbSession = Depends(get_db),
):
    unavailable_reason = _training_unavailable_reason(
        request.dataPath,
        list(request.models),
        prepare_output=True,
    )
    if unavailable_reason:
        raise HTTPException(status_code=503, detail=unavailable_reason)
    data_path = _training_data_file(request.dataPath)

    job = AdminJob(
        job_type="model_training",
        status="running",
        progress=0,
        current_step="Initializing training pipeline",
        message="Initializing training pipeline",
        data_path=str(data_path),
        models=list(request.models),
        result={"results": []},
        started_at=utcnow(),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    background_tasks.add_task(run_model_training, job.id, str(data_path), list(request.models))
    return {"message": "Training started", "dataPath": str(data_path), "jobId": job.id}


@router.get("/models/train/status")
async def get_training_status(db: DbSession = Depends(get_db)):
    job = db.execute(
        select(AdminJob)
        .where(AdminJob.job_type == "model_training")
        .order_by(AdminJob.created_at.desc())
    ).scalar_one_or_none()
    payload = _job_payload(job)
    unavailable_reason = _training_unavailable_reason(
        "data/demo_text_training.csv",
        ["text"],
    )
    return {
        **payload,
        "enabled": unavailable_reason is None,
        "unavailableReason": unavailable_reason,
    }


@router.get("/jobs/{job_id}")
async def get_job(job_id: str, db: DbSession = Depends(get_db)):
    job = db.get(AdminJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return _job_payload(job)


async def run_model_training(job_id: str, data_path: str, models: list[str]) -> None:
    try:
        candidate_dir = MODEL_CANDIDATE_DIR / job_id
        candidate_dir.mkdir(parents=True, exist_ok=True)

        results: list[dict] = []
        total = len(models)
        for idx, model_name in enumerate(models, 1):
            script = TRAINING_SCRIPTS.get(model_name)
            if not script or not script[0].is_file():
                results.append(
                    {
                        "model": model_name,
                        "status": "failed",
                        "error": "Training executor is not installed.",
                    }
                )
                continue
            script_path, script_args_template, artifact_name = script
            script_args = [value.format(data=data_path) for value in script_args_template]

            _update_job(
                job_id,
                status="running",
                progress=int(((idx - 1) / total) * 100),
                current_step=f"Training {model_name} model...",
                message=f"Running training script: {script_path}",
                result={"results": results},
            )
            _add_job_event(job_id, f"Training {model_name}", metadata={"script": script_path})

            try:
                result = await asyncio.to_thread(
                    subprocess.run,
                    [sys.executable, str(script_path), *script_args, "--out", str(candidate_dir)],
                    capture_output=True,
                    text=True,
                    timeout=1800,
                    check=False,
                )
                artifact_path = candidate_dir / artifact_name
                if result.returncode == 0 and artifact_path.is_file() and artifact_path.stat().st_size:
                    metrics = _training_metrics(result.stdout)
                    results.append({"model": model_name, "status": "completed", **metrics})
                    with SessionLocal() as db:
                        db.add(
                            ModelVersion(
                                model_name=model_name,
                                modality="url" if model_name == "url" else "text",
                                status="candidate",
                                artifact_uri=str(candidate_dir),
                                training_dataset_uri=data_path,
                                metrics=metrics,
                                f1=metrics.get("f1_score") or metrics.get("f1"),
                                accuracy=metrics.get("accuracy"),
                                trained_by_job_id=job_id,
                            )
                        )
                        db.commit()
                else:
                    error = result.stderr.strip()[:500]
                    if result.returncode == 0:
                        error = f"Training exited successfully but did not produce {artifact_name}."
                    results.append(
                        {
                            "model": model_name,
                            "status": "failed",
                            "error": error or f"Training process exited with code {result.returncode}.",
                        }
                    )
            except subprocess.TimeoutExpired as exc:
                results.append(
                    {
                        "model": model_name,
                        "status": "failed",
                        "error": f"Training timed out after {exc.timeout} seconds.",
                    }
                )
            except Exception as exc:
                results.append({"model": model_name, "status": "failed", "error": str(exc)})

            model_succeeded = results[-1]["status"] == "completed"
            _update_job(
                job_id,
                progress=int((idx / total) * 100),
                current_step=(
                    f"{model_name} model completed"
                    if model_succeeded
                    else f"{model_name} model failed"
                ),
                message=f"Processed {idx} of {total} models",
                result={"results": results},
            )

        failed_results = [result for result in results if result["status"] != "completed"]
        job_status = "failed" if failed_results else "completed"
        error = "; ".join(
            f"{result['model']}: {result.get('error', 'training failed')}"
            for result in failed_results
        ) or None
        _update_job(
            job_id,
            status=job_status,
            progress=100,
            current_step="Training failed" if failed_results else "All models trained",
            message=(
                f"{len(failed_results)} model training job(s) failed"
                if failed_results
                else f"Successfully trained {len(results)} models"
            ),
            result={"results": results},
            error=error,
            completed_at=utcnow(),
        )
    except Exception as exc:
        logger.error("Model training error: %s", exc)
        _update_job(job_id, status="failed", progress=0, error=str(exc), completed_at=utcnow())
        _add_job_event(job_id, str(exc), level="error")
