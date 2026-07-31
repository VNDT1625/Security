import pytest

from backend.models import SystemSetting
from backend.services.ai_context_weight_service import set_ai_context_weight_policy
from backend.services.inference_service import InferenceService
from shared.schemas import RiskCoreTrace


def test_url_score_has_no_post_policy_ai_blend_path() -> None:
    assert not hasattr(InferenceService, "apply_url_ai_context_weight")
    fields = RiskCoreTrace.model_fields
    assert "blended_final_score" not in fields
    assert "ai_context_weight_percent" not in fields
    assert "ai_context_effective_weight_percent" not in fields
    assert "ai_context_score" not in fields


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
