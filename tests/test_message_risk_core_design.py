from __future__ import annotations

from ai.adapters.text_adapter import extract_message_urls, preprocess_email
from ai.inference.engine import PredictionResult
from backend.services.inference_service import InferenceService
from security.text_risk_core import (
    MODEL_ONLY_CEILING,
    MODEL_ONLY_WARN_MIN,
    assess_text_risk,
)
from shared.constants import RISK_THRESHOLD_BLOCK, RISK_THRESHOLD_WARN
from shared.schemas import Evidence, Severity


def features(result) -> set[str]:
    return {item.feature or "" for item in result.evidence}


def test_model_only_signal_may_warn_but_never_blocks() -> None:
    """A classifier with no corroborating rule evidence is capped inside WARN.

    The previous contract capped a model-only score at 0.25, below the 0.50 WARN
    threshold, which meant the classifier could not affect the verdict at all.
    On the frozen holdout that cost the deployed email path 81 points of recall
    (0.8% vs 81.8% for the same classifier alone), so the ceiling now sits inside
    the WARN band. The anti-hallucination guarantee that matters is preserved:
    a model alone can never reach BLOCK.
    """
    result = assess_text_risk(
        "Chào anh, lịch họp nội bộ chuyển sang 14h chiều mai.",
        "email",
        {"sender": "Lan <lan@company.vn>", "subject": "Lịch họp dự án"},
        model_score=0.95,
    )
    assert result.score == MODEL_ONLY_CEILING
    assert RISK_THRESHOLD_WARN <= result.score < RISK_THRESHOLD_BLOCK
    # The warning must say plainly that it rests on the model alone.
    assert features(result) == {"model_only_signal"}


def test_low_model_score_alone_stays_allow() -> None:
    result = assess_text_risk(
        "Chào anh, lịch họp nội bộ chuyển sang 14h chiều mai.",
        "email",
        {"sender": "Lan <lan@company.vn>", "subject": "Lịch họp dự án"},
        model_score=0.20,
    )
    assert result.score < RISK_THRESHOLD_WARN
    assert features(result) == {"no_text_signal"}


def test_email_bec_combination_applies_mandatory_floor() -> None:
    result = assess_text_risk(
        "Tôi là giám đốc. Hãy giữ bí mật, thay đổi số tài khoản thanh toán mới "
        "và chuyển khoản gấp hôm nay.",
        "email",
    )
    assert result.score >= 0.85
    assert "E-BEC-02" in features(result)


def test_email_authentication_failure_needs_impersonation_and_action_for_floor() -> None:
    risky = assess_text_risk(
        "Ngân hàng yêu cầu đăng nhập và nhập mật khẩu để thanh toán.",
        "email",
        {"sender": "Ngân hàng <alert@unknown.example>", "dmarc": "fail"},
    )
    technical_only = assess_text_risk(
        "Bản tin kỹ thuật tháng này.",
        "email",
        {"sender": "News <news@example.com>", "dmarc": "fail", "forwarded": True},
    )
    assert risky.score >= 0.85
    assert technical_only.score < 0.40


def test_account_lock_shortlink_email_is_suspicious() -> None:
    result = assess_text_risk(
        "Tài khoản của bạn bị khóa, nhấn vào đây để xác minh ngay: http://bit.ly/xxx",
        "email",
    )
    assert result.score > 0.40
    assert "email_account_takeover_cluster" in features(result)


def test_hidden_html_href_is_preserved_for_url_analysis() -> None:
    raw = '<a href="http://paypa1-login.example/verify">https://paypal.com</a>'
    assert set(extract_message_urls(raw)) == {
        "https://paypal.com",
        "http://paypa1-login.example/verify",
    }
    clean = preprocess_email(raw)
    assert "paypa1-login.example" in clean
    result = assess_text_risk(clean, "email")
    assert "E-WEB-01" in features(result)


def test_legitimate_otp_warning_is_not_treated_as_otp_request() -> None:
    result = assess_text_risk(
        "Mã OTP của bạn là 123456. Tuyệt đối không chia sẻ mã này cho bất kỳ ai. "
        "Ngân hàng không bao giờ yêu cầu OTP.",
        "sms",
    )
    assert result.score < 0.40
    assert "S-CONT-02" not in features(result)


def test_short_legitimate_otp_warning_is_not_treated_as_request() -> None:
    result = assess_text_risk(
        "Mã OTP của bạn là 123456. Không chia sẻ mã này cho bất kỳ ai.",
        "sms",
    )
    assert result.score < 0.40
    assert "S-CONT-02" not in features(result)


def test_conversation_turns_are_included_in_sms_assessment() -> None:
    result = assess_text_risk(
        "",
        "sms",
        {
            "conversation_turns": [
                {"text": "Xin lỗi tôi nhầm số, kết bạn Zalo nhé."},
                {"text": "Tôi có cơ hội đầu tư USDT lợi nhuận cao."},
            ]
        },
    )
    assert result.score >= 0.80
    assert "S-CONV-01" in features(result)


def test_sms_otp_request_applies_mandatory_floor() -> None:
    result = assess_text_risk(
        "Tài khoản bị khóa ngay. Hãy gửi lại mã OTP này cho nhân viên để xác minh.",
        "sms",
    )
    assert result.score >= 0.85
    assert "S-CONT-02" in features(result)


def test_sms_job_task_deposit_applies_mandatory_floor() -> None:
    result = assess_text_risk(
        "Việc online làm nhiệm vụ nhận hoa hồng. Nạp tiền chốt đơn để rút tiền ngay.",
        "sms",
    )
    assert result.score >= 0.85
    assert "S-CONT-04" in features(result)


def test_sms_wrong_number_to_investment_applies_mandatory_floor() -> None:
    result = assess_text_risk(
        "Xin lỗi tôi nhầm số. Kết bạn Zalo trao đổi nhé, tôi có cơ hội đầu tư USDT lợi nhuận cao.",
        "sms",
    )
    assert result.score >= 0.80
    assert "S-CONV-01" in features(result)


def test_unaccented_vietnamese_otp_request_is_detected() -> None:
    result = assess_text_risk(
        "Tai khoan cua ban sap bi khoa. Hay xac minh OTP ngay.",
        "sms",
    )

    assert result.score >= 0.85
    assert "S-CONT-02" in features(result)


def test_unaccented_otp_do_not_share_warning_stays_safe() -> None:
    result = assess_text_risk(
        "Ma OTP 123456 de dang nhap. Tuyet doi khong chia se ma OTP cho bat ky ai.",
        "sms",
    )

    assert result.score < 0.40
    assert "S-CONT-02" not in features(result)


def test_sms_sender_abuse_is_high_evidence_but_not_a_standalone_block() -> None:
    result = assess_text_risk(
        "Chào bạn, đây là một tin nhắn bình thường.",
        "sms",
        {"sender_abuse_confirmed": True},
    )
    assert "S-ID-02" in features(result)
    assert 0.15 <= result.score < 0.60


def test_sms_voip_sender_is_only_a_supporting_signal() -> None:
    result = assess_text_risk(
        "Lịch hẹn của bạn lúc 14 giờ.",
        "sms",
        {"sender_line_type": "voip"},
    )
    assert "S-ID-03" in features(result)
    assert result.score < 0.20


def test_sms_country_mismatch_combines_with_scam_action() -> None:
    result = assess_text_risk(
        "Bưu kiện bị giữ, hãy bấm link và đóng phí ngay: https://ship-fee.example/pay",
        "sms",
        {"sender_country_mismatch": True},
    )
    assert "S-ID-01" in features(result)
    assert "S-CONT-01" in features(result)
    assert result.score >= 0.40


class _StubEngine:
    models_loaded = False
    model_status: dict = {}

    def predict_text(self, text: str, metadata: dict | None = None) -> PredictionResult:
        return PredictionResult(0.08, [], "stub-text")

    def predict_url(self, url: str) -> PredictionResult:
        return PredictionResult(
            0.84,
            [
                Evidence(
                    source="url_adapter",
                    message="Domain giả thương hiệu",
                    severity=Severity.HIGH,
                    feature="brand_domain_mismatch",
                    contribution=0.2,
                )
            ],
            "stub-url",
        )


def test_single_embedded_brand_signal_does_not_inflate_message_to_80() -> None:
    service = InferenceService(engine=_StubEngine())
    response = service.assess_text(
        '<a href="https://danger.example/login">Xem hóa đơn</a>',
        "email",
    )
    assert response.risk_score < 0.65
    assert any(item.source.startswith("embedded_url_1:") for item in response.evidence)


class _CoordinatedURLStubEngine(_StubEngine):
    def predict_url(self, url: str) -> PredictionResult:
        return PredictionResult(
            1.0,
            [
                Evidence(
                    source="url_adapter",
                    message=feature,
                    severity=Severity.HIGH,
                    feature=feature,
                    contribution=0.2,
                )
                for feature in (
                    "brand_domain_mismatch",
                    "deceptive_subdomain",
                    "credential_theft_intent",
                )
            ],
            "stub-url",
        )


def test_coordinated_embedded_url_core_override_protects_message() -> None:
    service = InferenceService(engine=_CoordinatedURLStubEngine())
    response = service.assess_text(
        '<a href="https://paypal.security.example/login">Đăng nhập</a>',
        "email",
    )

    assert response.risk_score >= 0.80


def test_extra_weak_evidence_never_lowers_the_verdict() -> None:
    """The model ceiling must be monotonic in the rule evidence.

    An SMS whose only rule hit was "contains a link" (+0.07) used to cap the
    classifier at 0.17 and return ALLOW, while the identical text *without* the
    link was capped at the model-only ceiling and returned WARN. Finding one more
    suspicious property must never make the message look safer.
    """
    without_link = assess_text_risk(
        "Your parcel is held, pay the fee today", "sms", model_score=0.95
    )
    with_link = assess_text_risk(
        "Your parcel is held, pay the fee at http://bit.ly/x2p", "sms", model_score=0.95
    )
    assert with_link.score >= without_link.score
    assert with_link.score >= RISK_THRESHOLD_WARN


def test_weak_evidence_does_not_promote_a_confident_benign_model() -> None:
    result = assess_text_risk(
        "Your parcel is at http://bit.ly/x2p", "sms", model_score=0.10
    )
    assert result.score < RISK_THRESHOLD_WARN


# --- Cross-mode parity ------------------------------------------------------
# These scenarios used to exist in exactly one modality, so the identical scam
# scored very differently depending on which channel it arrived through.


def test_email_detects_remote_control_app_request() -> None:
    result = assess_text_risk(
        "Kính gửi anh, vui lòng tải ứng dụng AnyDesk để kỹ thuật viên hỗ trợ từ xa.",
        "email",
    )
    assert "E-CONT-remote-app" in features(result)
    assert result.score >= 0.85


def test_email_detects_job_task_deposit_scam() -> None:
    result = assess_text_risk(
        "Việc online làm nhiệm vụ nhận hoa hồng cao. Vui lòng nạp tiền để chốt đơn.",
        "email",
    )
    assert "E-CONT-job-deposit" in features(result)
    assert result.score >= 0.85


def test_email_detects_delivery_fee_scenario() -> None:
    result = assess_text_risk(
        "Bưu kiện của bạn đang bị giữ. Truy cập https://ship-fee.example/pay "
        "và thanh toán phí giao ngay.",
        "email",
    )
    assert "E-CONT-delivery-fee" in features(result)


def test_sms_detects_business_email_compromise_pattern() -> None:
    result = assess_text_risk(
        "Tôi là giám đốc. Thay đổi số tài khoản thanh toán mới và chuyển khoản gấp.",
        "sms",
    )
    assert "S-BEC-01" in features(result)
    assert result.score >= 0.85


def test_chat_transcript_uses_the_conversational_rule_set() -> None:
    """chat/call_transcript used to fall through to the email rules."""
    result = assess_text_risk(
        "Xin lỗi tôi nhầm số. Kết bạn Zalo trao đổi nhé, tôi có cơ hội đầu tư USDT lợi nhuận cao.",
        "chat",
    )
    assert "S-CONV-01" in features(result)
    assert result.score >= 0.80


def test_shortener_lists_are_shared_between_url_and_message_cores() -> None:
    from ai.adapters.url_adapter import SHORTLINK_DOMAINS, analyze_url_signals

    # Previously cutt.ly/rb.gy/shorturl.at were known only to the message core
    # and goo.gl/ow.ly/buff.ly only to the URL core.
    for domain in ("cutt.ly", "rb.gy", "shorturl.at", "goo.gl", "ow.ly", "buff.ly"):
        assert domain in SHORTLINK_DOMAINS
        assert analyze_url_signals(f"https://{domain}/abc123").shortlink is True
    email = assess_text_risk("Xem tại https://cutt.ly/abc123 nhé", "email")
    assert "E-WEB-shortlink" in features(email)


def test_sms_brand_cluster_contribution_is_actually_scored() -> None:
    """The declared 0.16 contribution used to be evidence-only, never added."""
    result = assess_text_risk(
        "Vietcombank thong bao: truy cap https://vcb-verify.example va chuyen khoan ngay.",
        "sms",
    )
    assert "sms_brand_action_cluster" in features(result)
    contributions = sum(item.contribution or 0 for item in result.evidence)
    assert contributions > 0


# --- Model-only calibration gate -------------------------------------------


def test_uncorroborated_low_confidence_model_stays_below_warn() -> None:
    """The deployed text model is miscalibrated on Vietnamese.

    It scores ordinary Vietnamese business messages at 0.44-0.69, so letting any
    score >= 0.50 warn on its own raised a false alarm on half of a benign
    Vietnamese sample. Uncorroborated signals must clear MODEL_ONLY_WARN_MIN
    before they may interrupt the user.
    """
    result = assess_text_risk(
        "Chào anh, lịch họp nội bộ chuyển sang 14h chiều mai.",
        "email",
        {"sender": "Lan <lan@company.vn>", "subject": "Lịch họp dự án"},
        model_score=0.60,
    )
    assert result.score < RISK_THRESHOLD_WARN
    assert "model_only_signal" not in features(result)


def test_uncorroborated_high_confidence_model_may_warn() -> None:
    result = assess_text_risk(
        "Chào anh, lịch họp nội bộ chuyển sang 14h chiều mai.",
        "email",
        {"sender": "Lan <lan@company.vn>", "subject": "Lịch họp dự án"},
        model_score=MODEL_ONLY_WARN_MIN,
    )
    assert RISK_THRESHOLD_WARN <= result.score < RISK_THRESHOLD_BLOCK
    assert "model_only_signal" in features(result)


def test_the_gate_never_weakens_a_rule_backed_verdict() -> None:
    """Deterministic Vietnamese evidence must be unaffected by the model gate."""
    result = assess_text_risk(
        "Tài khoản bị khóa ngay. Hãy gửi lại mã OTP này cho nhân viên để xác minh.",
        "sms",
        model_score=0.10,
    )
    assert result.score >= 0.85
