"""FastAPI Security Gateway entry point.

Run: uvicorn backend.main:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.db import initialize_database
from backend.middleware import (
    RateLimiterMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from backend.routers import (
    admin,
    agent_security,
    assess,
    auth,
    chat,
    demo,
    feedback,
    gmail,
    health,
    legal,
    legal_admin,
    report_shares,
    sandbox_cloud,
    telemetry,
    waitlist,
)
from backend.services.operational_maintenance_scheduler import run_operational_maintenance_scheduler
from backend.services.threat_feed_scheduler import run_threat_feed_scheduler

logger = logging.getLogger(__name__)


async def recover_cloud_sandbox_lifecycle() -> None:
    try:
        recovered = await sandbox_cloud.reconcile_cloud_sandbox_sessions_after_restart()
        if any(recovered.values()):
            logger.warning("Recovered interrupted Cloud Sandbox lifecycle: %s", recovered)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("Cloud Sandbox restart recovery failed")


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    sandbox_recovery_task = asyncio.create_task(
        recover_cloud_sandbox_lifecycle(),
        name="cloud-sandbox-restart-recovery",
    )
    # The workers are lightweight while disabled and read persistent Admin
    # switches every minute, so turning them on does not need a deployment.
    feed_task = asyncio.create_task(
        run_threat_feed_scheduler(), name="threat-feed-scheduler"
    )
    maintenance_task = asyncio.create_task(
        run_operational_maintenance_scheduler(), name="operational-maintenance-scheduler"
    )
    try:
        yield
    finally:
        if sandbox_recovery_task is not None and not sandbox_recovery_task.done():
            sandbox_recovery_task.cancel()
            with suppress(asyncio.CancelledError):
                await sandbox_recovery_task
        if feed_task is not None:
            feed_task.cancel()
            with suppress(asyncio.CancelledError):
                await feed_task
        if maintenance_task is not None:
            maintenance_task.cancel()
            with suppress(asyncio.CancelledError):
                await maintenance_task


app = FastAPI(
    title="Prewise — Security Gateway",
    version="0.2.0",
    description="Pre-action Risk Core for AI agents, MCP clients, and human-facing apps.",
    lifespan=lifespan,
    docs_url=None if settings.app_env == "production" else "/docs",
    redoc_url=None if settings.app_env == "production" else "/redoc",
    openapi_url=None if settings.app_env == "production" else "/openapi.json",
)


@app.exception_handler(RequestValidationError)
async def log_sandbox_agent_validation_error(request: Request, exc: RequestValidationError):
    """Log schema locations without persisting attacker-controlled telemetry."""
    if request.url.path.startswith("/v1/sandbox-cloud/agent/sessions/"):
        safe_errors = [
            {key: value for key, value in error.items() if key not in {"input", "ctx"}}
            for error in exc.errors()
        ]
        logger.warning("Sandbox agent request validation failed: %s", safe_errors)
    return await request_validation_exception_handler(request, exc)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_origin_regex=r"chrome-extension://.*",
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    allow_private_network=settings.cors_allow_private_network,
)
app.add_middleware(RateLimiterMiddleware, limit_per_min=settings.rate_limit_per_min)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    RequestSizeLimitMiddleware,
    # Multipart boundaries/headers need a small allowance beyond the file cap.
    max_body_bytes=settings.max_upload_bytes + 1024 * 1024,
    paths=(
        "/v1/assess/email-file",
        "/v1/assess/file/",
        "/v1/sandbox-cloud/sessions/",
    ),
)
app.add_middleware(
    RequestSizeLimitMiddleware,
    # Agent evidence is metadata-only and independently bounded by its schema.
    max_body_bytes=512 * 1024,
    paths=("/v1/sandbox-cloud/agent/sessions/",),
)
app.add_middleware(
    RequestSizeLimitMiddleware,
    max_body_bytes=16 * 1024 * 1024,
    exact_paths=("/v1/demo/deepfake/analyze",),
)
app.add_middleware(
    RequestSizeLimitMiddleware,
    max_body_bytes=51 * 1024 * 1024,
    exact_paths=("/v1/demo/deepfake/analyze-video",),
)
app.include_router(health.router)
app.include_router(agent_security.router)
app.include_router(assess.router)
app.include_router(chat.router)
app.include_router(auth.router)
app.include_router(gmail.router)
app.include_router(legal.router)
app.include_router(legal_admin.router)
app.include_router(sandbox_cloud.router)
app.include_router(demo.router)
app.include_router(feedback.router)
app.include_router(report_shares.router)
app.include_router(admin.router)
app.include_router(telemetry.router)
app.include_router(waitlist.router)


@app.get("/")
def root():
    return {
        "name": "Prewise Agent Security Gateway",
        "docs": "/docs" if settings.app_env != "production" else None,
        "health": "/v1/health",
        "agent_security": "/v1/agent/check/*",
        "mcp": "/mcp",
    }
