"""Hybrid inference tests without downloading large Transformer artifacts."""

import json

import numpy as np
import pytest

from ai.inference.engine import InferenceEngine
from security.text_risk_core import MODEL_ONLY_CEILING
from shared.constants import RISK_THRESHOLD_BLOCK


class _Input:
    def __init__(self, name: str):
        self.name = name


class _TransformerSession:
    def __init__(self, malicious_logit: float):
        self.malicious_logit = malicious_logit
        self.last_feed = None

    def get_inputs(self):
        return [_Input("input_ids"), _Input("attention_mask"), _Input("token_type_ids")]

    def run(self, output_names, feed):
        self.last_feed = feed
        return [np.array([[0.0, self.malicious_logit]], dtype=np.float32)]


class _Tokenizer:
    def __call__(self, text, **kwargs):
        return {
            "input_ids": np.array([[1, 42, 2]], dtype=np.int64),
            "attention_mask": np.array([[1, 1, 1]], dtype=np.int64),
        }


def test_hybrid_score_blends_models_and_floors_on_rules(tmp_path):
    engine = InferenceEngine(model_dir=str(tmp_path))

    # Trained models are averaged by weight; the rule heuristic is not a peer.
    assert engine._hybrid_score(0.9, 0.6, 0.2) == pytest.approx((0.9 * 0.7 + 0.6 * 0.2) / 0.9)
    # With the transformer absent the lightweight model keeps its full say
    # instead of being diluted by a near-zero keyword baseline.
    assert engine._hybrid_score(None, 0.7, 0.05) == pytest.approx(0.7)
    # Rules may still raise the score above what the models produced.
    assert engine._hybrid_score(None, 0.1, 0.8) == pytest.approx(0.8)
    # With no model loaded the heuristic is all there is.
    assert engine._hybrid_score(None, None, 0.8) == pytest.approx(0.8)


def test_url_model_uses_metadata_schema_and_dynamic_context(tmp_path, monkeypatch):
    engine = InferenceEngine(model_dir=str(tmp_path))
    engine.url_session = object()
    engine.model_metadata["url_lgbm.onnx"] = {
        "feature_names": [
            "url_length",
            "dns_available",
            "domain_age_days_normalized",
            "local_feed_hit",
        ]
    }
    captured: list[float] = []

    def fake_run(_session, features):
        captured.extend(features)
        return 0.2

    monkeypatch.setattr(engine, "_run_lgbm", fake_run)

    result = engine.predict_url(
        "https://example.com/login",
        context={
            "dns_available": 1,
            "domain_age_days": 30,
            "local_feed_hit": 1,
        },
    )

    assert result.model_version.startswith("url_lgbm.onnx+enriched-context+")
    assert captured[1] == 1.0
    assert captured[2] == pytest.approx(30 / 3650)
    assert captured[3] == 1.0


def test_url_model_keeps_legacy_vector_when_metadata_has_no_schema(tmp_path, monkeypatch):
    engine = InferenceEngine(model_dir=str(tmp_path))
    engine.url_session = object()
    captured: list[float] = []

    def fake_run(_session, features):
        captured.extend(features)
        return 0.2

    monkeypatch.setattr(engine, "_run_lgbm", fake_run)

    engine.predict_url(
        "https://example.com",
        context={"dns_available": 1, "local_feed_hit": 1},
    )

    assert len(captured) == 15


def test_text_transformer_branch_is_executed_but_cannot_block_alone(tmp_path):
    engine = InferenceEngine(model_dir=str(tmp_path))
    session = _TransformerSession(malicious_logit=3.0)
    engine.text_transformer_session = session
    engine.text_tokenizer = _Tokenizer()

    result = engine.predict_text("Please verify this account request")

    # A model-only verdict is bounded by the message policy: it may warn, but
    # independent sender, URL, attachment or scam-combination evidence is
    # required before the message can reach the BLOCK band.
    assert result.risk_score == pytest.approx(MODEL_ONLY_CEILING)
    assert result.risk_score < RISK_THRESHOLD_BLOCK
    assert result.model_version == "hybrid-text[transformer+rules]"
    assert any(item.source == "text_transformer" for item in result.evidence)
    assert session.last_feed["token_type_ids"].tolist() == [[0, 0, 0]]


def test_weak_text_transformer_metadata_disables_branch(tmp_path):
    (tmp_path / "mdeberta_text_transformer.meta.json").write_text(
        json.dumps({"metrics": {"f1": 0.52}}),
        encoding="utf-8",
    )
    engine = InferenceEngine(model_dir=str(tmp_path))
    engine.text_transformer_session = _TransformerSession(malicious_logit=5.0)
    engine.text_tokenizer = _Tokenizer()

    result = engine.predict_text("Please verify this account request")

    assert "mdeberta_text_transformer.onnx" in engine.disabled_models
    assert "transformer" not in result.model_version
    assert not any(item.source == "text_transformer" for item in result.evidence)


def test_prompt_transformer_branch_is_executed(tmp_path):
    engine = InferenceEngine(model_dir=str(tmp_path))
    session = _TransformerSession(malicious_logit=3.0)
    engine.prompt_transformer_session = session
    engine.prompt_tokenizer = _Tokenizer()

    result = engine.predict_prompt("Translate the following content")

    assert result.risk_score > 0.8
    assert result.model_version == "hybrid-prompt[transformer+rules]"
    assert any(item.source == "prompt_transformer" for item in result.evidence)
    assert session.last_feed is not None
