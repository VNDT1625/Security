"""Robustness lab tests — attacks + evaluation harness."""

from ai.inference.engine import InferenceEngine
from ai.robustness.attacks import ATTACKS, homoglyph_url, leetspeak_vi
from tests.adversarial.run_robustness_eval import evaluate


def test_attacks_registry():
    assert "homoglyph_url" in ATTACKS
    assert homoglyph_url("paypal.com") != "paypal.com"
    assert leetspeak_vi("ngan hang") == "ng4n h4ng"


def test_engine_detects_homoglyph_url_after_attack():
    engine = InferenceEngine()
    adv = homoglyph_url("http://paypal-secure.tk/login")
    assert any(
        item.feature in {"homoglyph", "brand_domain_mismatch", "brand_typosquatting"}
        for item in engine.predict_url(adv).evidence
    )


def test_evaluate_produces_report():
    report = evaluate()
    assert "url_homoglyph" in report
    assert "prompt_base64_wrap" in report
    assert 0.0 <= report["url_homoglyph"]["clean_detection_rate"] <= 1.0


def test_vietnamese_phishing_survives_leetspeak_and_zero_width_attacks():
    report = evaluate()
    assert report["text_leetspeak_vi"]["clean_detection_rate"] == 1.0
    assert report["text_leetspeak_vi"]["adversarial_detection_rate"] == 1.0
    assert report["text_zero_width"]["clean_detected"] is True
    assert report["text_zero_width"]["adversarial_detected"] is True
