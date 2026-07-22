"""Health endpoint."""

from __future__ import annotations

import shutil
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from backend.config import settings
from backend.db import check_database
from backend.dependencies import (
    get_adapter_registry,
    get_deepfake_service,
    get_explanation_service,
    get_inference_service,
)
from backend.services.adapter_registry import AdapterRegistry
from backend.services.cloud_sandbox_service import cloud_sandbox_service
from backend.services.deepfake_service import DeepfakeImageService
from backend.services.explanation_service import ExplanationService
from backend.services.gmail_service import gmail_service
from backend.services.inference_service import InferenceService
from backend.services.integration_status_service import integration_status
from backend.services.operational_maintenance_service import (
    normalized_scan_history_retention_days,
)
from backend.services.release_email_service import email_configured
from security.attachment_security import clamav_ready
from shared.schemas import HealthResponse

router = APIRouter(prefix="/v1", tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(
    svc: Annotated[InferenceService, Depends(get_inference_service)],
    expl: Annotated[ExplanationService, Depends(get_explanation_service)],
    deepfake: Annotated[DeepfakeImageService, Depends(get_deepfake_service)],
    adapters: Annotated[AdapterRegistry, Depends(get_adapter_registry)],
):
    model_status = dict(svc.model_status)
    model_status["database"] = {"ready": check_database()}
    model_status["deepfake_image"] = {
        "ready": deepfake.available,
        "model_version": deepfake.model_version,
    }
    model_status["llm"] = {
        "configured": expl.configured,
        "ready": expl.available,
        "model": expl.model,
        "provider": expl.provider,
        "external_data_contract": (
            "harness_and_allowlisted_assessment_context_only"
            if expl.provider == "endpoint"
            else "not_applicable"
        ),
        "last_error": expl.last_error,
    }
    model_status["context_adapters"] = adapters.status()
    clamav_is_ready = clamav_ready(settings.clamav_host, settings.clamav_port)
    model_status["message_security"] = {
        "clamav_configured": bool(settings.clamav_host),
        "clamav_ready": clamav_is_ready,
        "ocr_ready": bool(settings.tesseract_executable or shutil.which("tesseract")),
        "gmail_oauth_configured": gmail_service.configured,
        "attachment_sandbox_enabled": settings.email_attachment_sandbox_enabled,
    }
    model_status["operational_retention"] = {
        "scan_history_retention_days": normalized_scan_history_retention_days(),
        "maintenance_scheduler_enabled": settings.operational_maintenance_scheduler_enabled,
        "maintenance_interval_minutes": max(5, settings.operational_maintenance_interval_minutes),
    }
    model_status["release_notifications"] = {
        "configured": email_configured(),
        "provider": "cloudflare_email_sending",
    }
    model_status["integrations"] = integration_status(
        settings,
        clamav_is_ready=clamav_is_ready,
        cloud_sandbox_is_configured=cloud_sandbox_service.configured(),
    )
    return HealthResponse(
        status="ok",
        models_loaded=svc.models_loaded,
        llm_available=expl.available,
        model_status=model_status,
    )


@router.get("/integrations/status")
def integrations_status():
    """Safe optional-provider preflight; never returns credentials or account IDs."""

    return {
        "integrations": integration_status(
            settings,
            clamav_is_ready=clamav_ready(settings.clamav_host, settings.clamav_port),
            cloud_sandbox_is_configured=cloud_sandbox_service.configured(),
        )
    }


@router.get("/ready")
def readiness(
    svc: Annotated[InferenceService, Depends(get_inference_service)],
    expl: Annotated[ExplanationService, Depends(get_explanation_service)],
    deepfake: Annotated[DeepfakeImageService, Depends(get_deepfake_service)],
    adapters: Annotated[AdapterRegistry, Depends(get_adapter_registry)],
):
    """Deployment readiness; unlike liveness, required engines must be usable."""

    payload = health(svc, expl, deepfake, adapters)
    model_status = payload.model_status
    modalities = model_status.get("modalities_ready", {})
    message_security = model_status.get("message_security", {})
    checks = {
        "database": bool(model_status.get("database", {}).get("ready")),
        "url_model": bool(modalities.get("url")),
        "text_model": bool(modalities.get("text")),
        "prompt_model": bool(modalities.get("prompt")),
        "ocr": bool(message_security.get("ocr_ready")),
        "clamav": not message_security.get("clamav_configured")
        or bool(message_security.get("clamav_ready")),
    }
    ready = all(checks.values())
    return JSONResponse(
        status_code=200 if ready else 503,
        content={
            "status": "ready" if ready else "not_ready",
            "checks": checks,
        },
    )
