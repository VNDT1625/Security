from __future__ import annotations

from datetime import timedelta

from backend.models import CloudSandboxSession
from backend.routers.sandbox_cloud import SandboxAgentReport, session_dict
from backend.security_utils import utcnow


def _session(*, status: str, sample_status: str, report: dict) -> CloudSandboxSession:
    now = utcnow()
    cleanup_complete = status in {"terminated", "expired"}
    return CloudSandboxSession(
        id="output-contract-session",
        user_id="output-contract-user",
        status=status,
        provider="aws",
        sandbox_tier="pro",
        mode="auto",
        lease_minutes=15,
        sample_status=sample_status,
        sample_report=report,
        expires_at=now + timedelta(minutes=15),
        lease_expires_at=now + timedelta(minutes=15),
        cleanup_completed_at=now if cleanup_complete else None,
        terminated_at=now if cleanup_complete else None,
    )


def test_failed_analysis_is_never_presented_like_a_safe_result() -> None:
    row = _session(
        status="terminated",
        sample_status="failed",
        report={
            "verdict": "analysis_failed",
            "analysis": {
                "risk_score": None,
                "confidence": 0.25,
                "evidence_channels": ["process"],
                "missing_channels": ["file", "registry", "network"],
                "risk_signals": [],
            },
            "process_tree": [],
            "file_events": [],
            "registry_events": [],
            "network_events": [],
        },
    )

    analysis = session_dict(row)["sample"]["analysis"]

    assert analysis["outcome"] == "failed"
    assert analysis["riskScore"] is None
    assert analysis["isConclusive"] is False
    assert analysis["safetyClaim"] == "not_established"
    assert analysis["recommendedAction"]["code"] == "retry_compatible_environment"
    assert analysis["cleanup"] == {
        "state": "complete",
        "vmDestroyed": True,
        "remoteAccessRevoked": True,
    }


def test_inconclusive_analysis_exposes_missing_evidence_channels() -> None:
    row = _session(
        status="terminated",
        sample_status="completed",
        report={
            "verdict": "analysis_inconclusive_telemetry_degraded",
            "analysis": {
                "risk_score": 0,
                "confidence": 0.5,
                "evidence_channels": ["process", "file"],
                "missing_channels": ["registry", "network"],
                "risk_signals": [],
            },
            "process_tree": [{"pid": 123}],
            "file_events": [],
            "registry_events": [],
            "network_events": [],
        },
    )

    analysis = session_dict(row)["sample"]["analysis"]
    channels = {item["id"]: item for item in analysis["evidenceChannels"]}

    assert analysis["outcome"] == "inconclusive"
    assert analysis["riskScore"] == 0
    assert analysis["confidence"] == 0.5
    assert analysis["missingChannels"] == ["network", "registry"]
    assert channels["process"]["status"] == "observed"
    assert channels["file"]["status"] == "no_activity"
    assert channels["registry"]["status"] == "unavailable"
    assert channels["network"]["status"] == "unavailable"
    assert analysis["safetyClaim"] == "not_established"


def test_no_obvious_behavior_is_scoped_and_not_a_safe_certification() -> None:
    row = _session(
        status="terminated",
        sample_status="completed",
        report={
            "verdict": "completed_no_obvious_behavior",
            "analysis": {
                "risk_score": 0,
                "confidence": 1.0,
                "evidence_channels": ["process", "file", "registry", "network"],
                "missing_channels": [],
                "risk_signals": [],
            },
            "process_tree": [{"pid": 321}],
            "file_events": [],
            "registry_events": [],
            "network_events": [],
        },
    )

    analysis = session_dict(row)["sample"]["analysis"]

    assert analysis["outcome"] == "no_obvious_behavior"
    assert analysis["isConclusive"] is True
    assert analysis["safetyClaim"] == "no_obvious_behavior_only"
    assert "an toàn" in analysis["recommendedAction"]["label"]


def test_agent_analysis_schema_rejects_overlapping_channel_claims() -> None:
    try:
        SandboxAgentReport.model_validate(
            {
                "status": "completed",
                "analysis": {
                    "risk_score": 0,
                    "confidence": 1,
                    "evidence_channels": ["process"],
                    "missing_channels": ["process"],
                },
            }
        )
    except ValueError as exc:
        assert "available vừa missing" in str(exc)
    else:  # pragma: no cover - a regression would make this branch fail
        raise AssertionError("overlapping channel claims must be rejected")
