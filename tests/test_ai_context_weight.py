import pytest

from backend.models import SystemSetting
from backend.services.ai_context_weight_service import set_ai_context_weight_policy
from backend.services.inference_service import InferenceService
from security.policy_engine import PolicyEngine
from shared.adapter_schemas import AdapterRunStatus, AdapterTask, AdapterTrace
from shared.schemas import AssessResponse, Decision, Modality, RiskCoreTrace, RiskLevel


def _response(core_score: float, ai_signal: float, ai_confidence: float) -> AssessResponse:
    return AssessResponse(
        risk_score=core_score / 100,
        risk_level=RiskLevel.MEDIUM,
        decision=Decision.WARN,
        confidence=0.8,
        modality=Modality.URL,
        risk_core=RiskCoreTrace(
            scoring_version="risk-core-v2-test",
            raw_score=core_score,
            final_score=core_score,
            confidence=80,
            verdict="medium",
        ),
        contextual_analysis=AdapterTrace(
            task=AdapterTask.WEB_CONTEXT,
            adapter_id="test-context",
            status=AdapterRunStatus.COMPLETED,
            risk_signal=ai_signal,
            confidence=ai_confidence,
            scoring_mode="shadow",
        ),
    )


def test_ai_weight_is_confidence_scaled_and_bounded_to_forty_percent() -> None:
    service = InferenceService(policy=PolicyEngine(block=0.85, warn=0.5))
    result = service.apply_url_ai_context_weight(_response(20, 1.0, 0.5), 40)

    # 40% configured × 50% AI confidence = 20% effective AI share.
    assert result.risk_score == 0.36
    assert result.contextual_analysis.scoring_mode == "active"
    assert result.risk_core.ai_context_weight_percent == 40
    assert result.risk_core.ai_context_effective_weight_percent == 20
    assert result.risk_core.ai_context_score == 100
    assert result.risk_core.blended_final_score == 36


def test_ai_weight_cannot_reduce_a_technical_block_below_sixty() -> None:
    service = InferenceService(policy=PolicyEngine(block=0.85, warn=0.5))
    result = service.apply_url_ai_context_weight(_response(80, 0.0, 1.0), 40)

    assert result.risk_score == 0.6
    assert result.decision == Decision.BLOCK


def test_zero_weight_keeps_ai_in_shadow_and_score_unchanged() -> None:
    service = InferenceService(policy=PolicyEngine(block=0.85, warn=0.5))
    result = service.apply_url_ai_context_weight(_response(20, 1.0, 1.0), 0)

    assert result.risk_score == 0.2
    assert result.contextual_analysis.scoring_mode == "shadow"


def test_admin_can_set_dynamic_user_bounds_up_to_one_hundred() -> None:
    class FakeDb:
        def __init__(self):
            self.records = {}

        def get(self, _model, key):
            return self.records.get(key)

        def add(self, value):
            self.records[value.key] = value

        def commit(self):
            return None

    db = FakeDb()
    policy = set_ai_context_weight_policy(
        db,  # type: ignore[arg-type]
        percent=40,
        min_percent=10,
        max_percent=100,
        updated_by_user_id=None,
    )
    assert policy == {"minPercent": 10, "maxPercent": 100, "percent": 40}
    assert all(isinstance(value, SystemSetting) for value in db.records.values())
    with pytest.raises(ValueError, match="min"):
        set_ai_context_weight_policy(
            db,  # type: ignore[arg-type]
            percent=40,
            min_percent=80,
            max_percent=20,
            updated_by_user_id=None,
        )
