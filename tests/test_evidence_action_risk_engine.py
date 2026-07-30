from __future__ import annotations

from types import SimpleNamespace

from backend.services.inference_service import InferenceService
from security.risk_core import (
    ActionPolicyDecision,
    ActionRiskInput,
    ActionRiskLevel,
    EvidenceBasedActionRiskEngine,
    EvidenceCategory,
    EvidenceRelationship,
    EvidenceSource,
    LightGBMRiskAdapter,
    SecurityEvidence,
)
from security.risk_core.action_config import default_action_risk_config
from security.risk_core.action_evidence import classify_action, deduplicate_evidence
from security.risk_core.action_explanation import build_action_audit_record
from security.risk_core.action_features import (
    ActionFeatureVector,
    FEATURE_NAMES,
    extract_action_features,
)
from security.risk_core.action_types import SessionRiskResult
from shared.schemas import AgentContext, Decision


def _input(**updates) -> ActionRiskInput:
    data = {
        "action_id": "action-1",
        "action_type": "open_url",
        "target_url": "https://example.test/path",
        "data_types": ("public_data",),
        "user_intent": "Mở trang để đọc thông tin",
        "planned_action": "open url",
        "permission_level": "user",
        "available_assets": (),
        "session_id": None,
        "workflow_id": None,
        "destination_risk_score": 0.0,
        "destination_confidence": 0.9,
    }
    data.update(updates)
    return ActionRiskInput(**data)


def _evidence(
    evidence_id: str,
    category: EvidenceCategory,
    severity: float,
    relationship: EvidenceRelationship,
    *,
    event_id: str = "event-1",
    direct: bool = False,
    metadata: dict | None = None,
) -> SecurityEvidence:
    return SecurityEvidence(
        id=evidence_id,
        category=category,
        event_id=event_id,
        source=EvidenceSource.ACTION_RULE,
        severity=severity,
        reliability=1.0,
        relationship=relationship,
        direct=direct,
        reason_code=evidence_id.upper(),
        summary=evidence_id,
        metadata=metadata or {},
    )


def test_confirmed_credential_exfiltration_sets_critical_floor() -> None:
    result = EvidenceBasedActionRiskEngine().evaluate(
        _input(
            action_type="submit_form",
            data_types=("password",),
            user_intent="Gửi biểu mẫu đăng nhập",
            planned_action="submit form",
            permission_level="denied",
        )
    )
    assert result.direct_floor == 95
    assert result.danger_score is not None and result.danger_score >= 95
    assert result.risk_level is ActionRiskLevel.CRITICAL
    assert result.decision is ActionPolicyDecision.BLOCK


def test_password_word_or_otp_sample_does_not_create_direct_floor() -> None:
    engine = EvidenceBasedActionRiskEngine()
    password_document = engine.evaluate(
        _input(
            action_type="open_file",
            target_url=None,
            data_types=("test_document",),
            user_intent="Đọc tài liệu kiểm thử có chữ password",
            planned_action="open file",
            destination_risk_score=None,
            destination_confidence=None,
        )
    )
    otp_sample = engine.evaluate(
        _input(
            action_id="action-2",
            action_type="copy_data",
            target_url=None,
            data_types=("otp_sample",),
            user_intent="Sao chép dữ liệu kiểm thử OTP giả",
            planned_action="copy data",
            destination_risk_score=None,
            destination_confidence=None,
        )
    )
    assert password_document.direct_floor == 0
    assert otp_sample.direct_floor == 0


def test_confirmed_mass_deletion_floor_cannot_be_lowered_by_model() -> None:
    engine = EvidenceBasedActionRiskEngine(
        lightgbm=LightGBMRiskAdapter(lambda _features: 0.01, model_version="test-low")
    )
    result = engine.evaluate(
        _input(
            action_type="execute_file",
            target_url=None,
            data_types=("confirmed_mass_deletion",),
            user_intent="Chạy tác vụ quản trị",
            planned_action="execute file",
            permission_level="admin",
            destination_risk_score=None,
            destination_confidence=None,
        )
    )
    assert result.direct_floor == 95
    assert result.decision is ActionPolicyDecision.BLOCK
    assert result.ml.risk_probability == 0.01


def test_same_event_is_deduplicated_but_independent_categories_are_preserved() -> None:
    config = default_action_risk_config()
    after, groups = deduplicate_evidence(
        [
            _evidence(
                "password-word",
                EvidenceCategory.CREDENTIAL_ACCESS,
                35,
                EvidenceRelationship.SAME_EVENT,
            ),
            _evidence(
                "password-field",
                EvidenceCategory.CREDENTIAL_ACCESS,
                70,
                EvidenceRelationship.SAME_EVENT,
            ),
            _evidence(
                "external-transfer",
                EvidenceCategory.EXTERNAL_TRANSFER,
                65,
                EvidenceRelationship.INDEPENDENT_RISK,
            ),
            _evidence(
                "bad-destination",
                EvidenceCategory.DESTINATION_REPUTATION,
                80,
                EvidenceRelationship.INDEPENDENT_RISK,
            ),
        ],
        config,
    )
    assert len([item for item in after if item.category == EvidenceCategory.CREDENTIAL_ACCESS]) == 1
    assert {group.category for group in groups} >= {
        EvidenceCategory.CREDENTIAL_ACCESS,
        EvidenceCategory.EXTERNAL_TRANSFER,
        EvidenceCategory.DESTINATION_REPUTATION,
    }


def test_supporting_evidence_bonus_is_bounded() -> None:
    config = default_action_risk_config()
    items = [
        _evidence(
            f"support-{index}",
            EvidenceCategory.BEHAVIORAL_ANOMALY,
            100,
            EvidenceRelationship.SUPPORTING_EVIDENCE,
        )
        for index in range(20)
    ]
    _, groups = deduplicate_evidence(items, config)
    assert len(groups) == 1
    assert groups[0].score <= 100


def test_missing_destination_or_payload_never_allows_sensitive_action() -> None:
    engine = EvidenceBasedActionRiskEngine()
    no_destination = engine.evaluate(
        _input(
            action_type="upload_file",
            target_url=None,
            data_types=("personal_data",),
            user_intent="Tải dữ liệu lên",
            planned_action="upload file",
            destination_risk_score=None,
            destination_confidence=None,
        )
    )
    unknown_payload = engine.evaluate(
        _input(
            action_id="action-2",
            action_type="execute_file",
            target_url=None,
            data_types=(),
            user_intent="Chạy tệp",
            planned_action="execute file",
            permission_level="admin",
            destination_risk_score=None,
            destination_confidence=None,
        )
    )
    assert no_destination.risk_level is ActionRiskLevel.INSUFFICIENT_INFORMATION
    assert no_destination.decision is not ActionPolicyDecision.ALLOW
    assert unknown_payload.risk_level is ActionRiskLevel.INSUFFICIENT_INFORMATION
    assert unknown_payload.decision is not ActionPolicyDecision.ALLOW


def test_lightgbm_fallback_and_weak_signal_escalation() -> None:
    fallback = EvidenceBasedActionRiskEngine().evaluate(_input())
    raised = EvidenceBasedActionRiskEngine(
        lightgbm=LightGBMRiskAdapter(lambda _features: 0.95, model_version="test-high")
    ).evaluate(_input(action_id="action-2"))
    assert fallback.ml.available is False
    assert raised.ml.available is True
    assert raised.decision is ActionPolicyDecision.ASK_CONFIRM


def test_out_of_distribution_input_reduces_model_confidence() -> None:
    adapter = LightGBMRiskAdapter(lambda _features: 0.95, model_version="test")
    config = default_action_risk_config()
    values = {name: None for name in FEATURE_NAMES}
    values["missing_feature_ratio"] = 0.9
    result = adapter.assess(
        ActionFeatureVector("action-features-v1", values, tuple(values)),
        config,
    )
    assert result.out_of_distribution is True
    assert result.model_confidence < 0.3


def test_feature_extraction_preserves_missing_values_instead_of_safe_zero() -> None:
    config = default_action_risk_config()
    value = _input(
        target_url=None,
        data_types=(),
        user_intent=None,
        planned_action=None,
        permission_level=None,
        destination_risk_score=None,
        destination_confidence=None,
    )
    features = extract_action_features(
        value,
        classify_action(value, config),
        [],
        SessionRiskResult(None, 0, 0, 0, False, False, 0),
        ["destination", "payload_classification", "user_intent"],
        config,
    )
    assert features.schema_version == config.feature_schema_version
    assert features.values["destination_trust_score"] is None
    assert features.values["intent_match_score"] is None
    assert features.values["sensitive_data_level"] is None
    assert features.values["has_target"] == 0
    assert features.missing_ratio > 0


def test_session_detects_slow_and_multi_step_exfiltration() -> None:
    engine = EvidenceBasedActionRiskEngine()
    first = engine.evaluate(
        _input(
            action_id="session-1",
            action_type="copy_data",
            target_url=None,
            data_types=("personal_data",),
            user_intent="Sao chép dữ liệu",
            planned_action="copy data",
            session_id="session-a",
            destination_risk_score=None,
            destination_confidence=None,
        )
    )
    assert first.session.multi_step_attack is False
    second = engine.evaluate(
        _input(
            action_id="session-2",
            action_type="upload_file",
            data_types=("personal_data",),
            user_intent="Tải dữ liệu lên",
            planned_action="upload file",
            session_id="session-a",
        )
    )
    third = engine.evaluate(
        _input(
            action_id="session-3",
            action_type="upload_file",
            data_types=("personal_data",),
            user_intent="Tải dữ liệu lên",
            planned_action="upload file",
            session_id="session-a",
        )
    )
    fourth = engine.evaluate(
        _input(
            action_id="session-4",
            action_type="upload_file",
            data_types=("personal_data",),
            user_intent="Tải dữ liệu lên",
            planned_action="upload file",
            session_id="session-a",
        )
    )
    assert second.session.multi_step_attack is True
    assert fourth.session.slow_exfiltration is True
    assert fourth.session.cumulative_risk > third.session.cumulative_risk


def test_approved_workflow_accumulates_less_session_risk() -> None:
    normal = EvidenceBasedActionRiskEngine()
    approved = EvidenceBasedActionRiskEngine()
    normal_result = None
    approved_result = None
    for index in range(3):
        normal_result = normal.evaluate(
            _input(
                action_id=f"n-{index}",
                session_id="normal",
                action_type="upload_file",
                data_types=("personal_data",),
                user_intent="Tải dữ liệu lên",
                planned_action="upload file",
            )
        )
        approved_result = approved.evaluate(
            _input(
                action_id=f"a-{index}",
                session_id="approved",
                workflow_id="w1",
                available_assets=("approved_workflow:w1",),
                action_type="upload_file",
                data_types=("personal_data",),
                user_intent="Tải dữ liệu lên",
                planned_action="upload file",
            )
        )
    assert normal_result is not None and approved_result is not None
    assert approved_result.session.cumulative_risk < normal_result.session.cumulative_risk


def test_audit_record_redacts_sensitive_metadata() -> None:
    result = EvidenceBasedActionRiskEngine().evaluate(
        _input(
            action_type="submit_form",
            data_types=("password",),
            permission_level="denied",
        ),
        extra_evidence=(
            _evidence(
                "secret-metadata",
                EvidenceCategory.CREDENTIAL_ACCESS,
                50,
                EvidenceRelationship.SUPPORTING_EVIDENCE,
                metadata={"password": "real-secret"},
            ),
        ),
    )
    audit = build_action_audit_record(result, workflow_id="workflow-1")
    serialized = str(audit)
    assert "real-secret" not in serialized
    assert "redacted" in serialized


def test_shadow_mode_keeps_legacy_decision_and_records_comparison() -> None:
    service = InferenceService(security_core_mode="shadow")
    result = service.assess_action(
        "copy_data",
        None,
        ["public_data"],
        AgentContext(
            user_intent="Sao chép dữ liệu công khai",
            planned_action="copy data",
            permission_level="user",
            session_id="shadow-session",
        ),
    )
    assert result.security_core is not None
    assert result.security_core["mode"] == "shadow"
    assert result.security_core["legacy_comparison"]["legacy_decision"] in {
        "ALLOW",
        "WARN",
        "ASK_USER_CONFIRMATION",
        "BLOCK",
    }


def test_new_engine_maps_direct_block_to_compatible_public_contract() -> None:
    service = InferenceService(security_core_mode="new_engine")
    result = service.assess_action(
        "execute_file",
        None,
        ["confirmed_mass_deletion"],
        AgentContext(
            user_intent="Chạy tác vụ quản trị",
            planned_action="execute file",
            permission_level="admin",
        ),
    )
    assert result.decision is Decision.BLOCK
    assert result.security_core is not None
    assert result.security_core["direct_floor"] == 95
