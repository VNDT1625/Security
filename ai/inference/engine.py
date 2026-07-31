"""Unified Inference Engine (module-specification.md; engineering-backlog TSK-009).

Loads ONNX models when available (URL LightGBM, text mDeBERTa, prompt protectai) and
otherwise falls back to deterministic heuristics so the whole system runs end-to-end
without trained artifacts. Every prediction routes through the same interface, so the
gateway is agnostic to whether real models are loaded.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from importlib import metadata as importlib_metadata
from importlib import util as importlib_util
from typing import Any

from ai.adapters.prompt_adapter import detect_injection
from ai.adapters.text_adapter import chunk_text, normalize_for_detection, preprocess_email
from ai.adapters.url_adapter import (
    CONTEXT_FEATURE_NAMES,
    analyze_url_signals,
    extract_url_features,
    has_homoglyph,
    is_ip_host,
)
from security.prompt_firewall import assess_prompt_firewall
from security.text_risk_core import assess_text_risk
from security.url_risk_core import collect_url_evidence
from shared.constants import HIGH_RISK_TLDS, URGENCY_KEYWORDS_VI
from shared.schemas import Evidence, Severity

try:  # optional heavy dependency
    import onnxruntime as ort  # type: ignore

    _HAS_ORT = True
except Exception:  # pragma: no cover
    _HAS_ORT = False


@dataclass
class PredictionResult:
    risk_score: float
    evidence: list[Evidence] = field(default_factory=list)
    model_version: str = "heuristic-1"
    model_probability: float | None = None


TEXT_TRANSFORMER_MIN_F1 = 0.65


def _clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


class InferenceEngine:
    """Manages model sessions (if present) with heuristic fallback."""

    def __init__(self, model_dir: str = "server/models") -> None:
        self.model_dir = model_dir
        self.load_errors: dict[str, str] = {}
        self.disabled_models: dict[str, str] = {}
        self.model_metadata = {
            name: self._read_metadata(name)
            for name in (
                "url_lgbm.onnx",
                "mdeberta_text.onnx",
                "protectai_prompt.onnx",
                "mdeberta_text_transformer.onnx",
                "protectai_prompt_transformer.onnx",
            )
        }
        self._quality_gate_text_transformer()
        self.url_session = self._maybe_load("url_lgbm.onnx")
        # Stable filenames are the lightweight string-input classifiers.
        self.text_session = self._maybe_load("mdeberta_text.onnx")
        self.prompt_session = self._maybe_load("protectai_prompt.onnx")
        self.text_transformer_session = self._maybe_load("mdeberta_text_transformer.onnx")
        self.prompt_transformer_session = self._maybe_load("protectai_prompt_transformer.onnx")
        self.text_tokenizer = self._maybe_load_tokenizer(
            "mdeberta_text_tokenizer", self.text_transformer_session
        )
        self.prompt_tokenizer = self._maybe_load_tokenizer(
            "protectai_prompt_tokenizer", self.prompt_transformer_session
        )

    @property
    def models_loaded(self) -> bool:
        return bool(
            self.url_session is not None
            and self._text_model_ready()
            and self._prompt_model_ready()
        )

    @property
    def model_status(self) -> dict[str, Any]:
        return {
            "model_dir": self.model_dir,
            "runtime": {
                "onnxruntime_available": _HAS_ORT,
                "onnxruntime_version": self._package_version("onnxruntime"),
                "onnxruntime_providers": ort.get_available_providers() if _HAS_ORT else [],
                "transformers_available": importlib_util.find_spec("transformers") is not None,
                "transformers_version": self._package_version("transformers"),
            },
            "modalities_ready": {
                "url": self.url_session is not None,
                "text": self._text_model_ready(),
                "prompt": self._prompt_model_ready(),
            },
            "models": {
                "url_lgbm": self._session_status("url_lgbm.onnx", self.url_session),
                "text_lightweight": self._session_status("mdeberta_text.onnx", self.text_session),
                "text_transformer": self._session_status(
                    "mdeberta_text_transformer.onnx",
                    self.text_transformer_session,
                    tokenizer_dir="mdeberta_text_tokenizer",
                    tokenizer=self.text_tokenizer,
                    requires_tokenizer=True,
                ),
                "prompt_lightweight": self._session_status(
                    "protectai_prompt.onnx", self.prompt_session
                ),
                "prompt_transformer": self._session_status(
                    "protectai_prompt_transformer.onnx",
                    self.prompt_transformer_session,
                    tokenizer_dir="protectai_prompt_tokenizer",
                    tokenizer=self.prompt_tokenizer,
                    requires_tokenizer=True,
                ),
            },
            "errors": dict(self.load_errors),
            "disabled": dict(self.disabled_models),
        }

    def _read_metadata(self, model_name: str) -> dict[str, Any]:
        path = os.path.join(self.model_dir, model_name.replace(".onnx", ".meta.json"))
        if not os.path.exists(path):
            return {}
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            self.load_errors[f"{model_name}:metadata"] = str(exc)
            return {}

    def _quality_gate_text_transformer(self) -> None:
        name = "mdeberta_text_transformer.onnx"
        metadata = self.model_metadata.get(name, {})
        metrics = metadata.get("metrics") if isinstance(metadata.get("metrics"), dict) else {}
        f1_score = metrics.get("f1")
        if f1_score is None:
            return
        try:
            f1 = float(f1_score)
        except (TypeError, ValueError):
            return
        if f1 < TEXT_TRANSFORMER_MIN_F1:
            self.disabled_models[name] = (
                f"validation_f1={f1:.4f} is below required {TEXT_TRANSFORMER_MIN_F1:.2f}"
            )

    def _package_version(self, package: str) -> str | None:
        try:
            return importlib_metadata.version(package)
        except importlib_metadata.PackageNotFoundError:
            return None

    def _text_model_ready(self) -> bool:
        transformer_ready = (
            self.text_transformer_session is not None
            and self.text_tokenizer is not None
            and "mdeberta_text_transformer.onnx" not in self.disabled_models
        )
        return self.text_session is not None or transformer_ready

    def _prompt_model_ready(self) -> bool:
        return self.prompt_session is not None or (
            self.prompt_transformer_session is not None and self.prompt_tokenizer is not None
        )

    def _session_status(
        self,
        model_name: str,
        session: Any,
        *,
        tokenizer_dir: str | None = None,
        tokenizer: Any = None,
        requires_tokenizer: bool = False,
    ) -> dict[str, Any]:
        model_path = os.path.join(self.model_dir, model_name)
        metadata = self.model_metadata.get(model_name, {})
        metrics = {}
        for key in ("metrics", "test_metrics", "validation_metrics", "metrics_on_synthetic_holdout"):
            value = metadata.get(key)
            if isinstance(value, dict):
                metrics = value
                break
        tokenizer_ready = None if tokenizer_dir is None else tokenizer is not None
        ready = session is not None and (not requires_tokenizer or tokenizer_ready is True)
        status: dict[str, Any] = {
            "ready": ready,
            "exists": os.path.exists(model_path),
            "path": model_path,
            "metadata_present": bool(metadata),
            "metrics": metrics,
            "disabled_reason": self.disabled_models.get(model_name, ""),
            "load_error": self.load_errors.get(model_name, ""),
        }
        if tokenizer_dir is not None:
            tokenizer_path = os.path.join(self.model_dir, tokenizer_dir)
            status["tokenizer"] = {
                "ready": tokenizer_ready,
                "exists": os.path.isdir(tokenizer_path),
                "path": tokenizer_path,
                "load_error": self.load_errors.get(tokenizer_dir, ""),
            }
        return status

    def _metadata_max_length(self, model_name: str, default: int = 256) -> int:
        value = self.model_metadata.get(model_name, {}).get("max_length")
        try:
            max_length = int(value)
        except (TypeError, ValueError):
            return default
        return max(8, min(512, max_length))

    def _maybe_load(self, name: str):
        if name in self.disabled_models:
            return None
        if not _HAS_ORT:
            self.load_errors[name] = "onnxruntime is not installed"
            return None
        path = os.path.join(self.model_dir, name)
        if not os.path.exists(path):
            self.load_errors[name] = "model file is missing"
            return None
        try:  # pragma: no cover - requires real model file
            available = ort.get_available_providers()
            providers = [
                provider
                for provider in ("CUDAExecutionProvider", "CPUExecutionProvider")
                if provider in available
            ]
            return ort.InferenceSession(path, providers=providers)
        except Exception as exc:
            self.load_errors[name] = str(exc)
            return None

    def _maybe_load_tokenizer(self, directory: str, session: Any):
        if session is None:
            return None
        path = os.path.join(self.model_dir, directory)
        if not os.path.isdir(path):
            self.load_errors[directory] = "tokenizer directory is missing"
            return None
        try:  # pragma: no cover - optional large-model runtime
            from transformers import AutoTokenizer

            return AutoTokenizer.from_pretrained(path, local_files_only=True, use_fast=True)
        except Exception as exc:
            self.load_errors[directory] = str(exc)
            return None

    def _hybrid_score(
        self,
        transformer_score: float | None,
        lightweight_score: float | None,
        heuristic_score: float,
    ) -> float:
        """Blend trained models, then let the rule heuristic raise but never lower.

        The heuristic is a crude keyword baseline, not a peer estimator. When it
        was averaged in as a third component, a missing transformer left it
        holding a third of the weight, and on non-Vietnamese text its ~0.05
        baseline dragged confident classifier scores below the warning
        threshold. Treating rules as a floor matches how the prompt path
        (``max(model_prob, firewall.score)``) and the message risk core already
        combine deterministic and learned signals.
        """
        weighted = [
            (transformer_score, 0.70),
            (lightweight_score, 0.20),
        ]
        available = [(score, weight) for score, weight in weighted if score is not None]
        if not available:
            return _clip01(heuristic_score)
        total_weight = sum(weight for _, weight in available)
        ensemble = sum(float(score) * weight for score, weight in available) / total_weight
        return _clip01(max(ensemble, heuristic_score))

    def _hybrid_version(
        self,
        modality: str,
        transformer_score: float | None,
        lightweight_score: float | None,
    ) -> str:
        components = []
        if transformer_score is not None:
            components.append("transformer")
        if lightweight_score is not None:
            components.append("lite")
        components.append("rules")
        return f"hybrid-{modality}[{'+'.join(components)}]"

    # ------------------------------------------------------------------ URL
    def predict_url(
        self,
        url: str,
        context: dict[str, object] | None = None,
    ) -> PredictionResult:
        try:
            legacy_features = extract_url_features(url)
        except Exception as e:
            # Handle invalid URLs gracefully
            return PredictionResult(
                risk_score=0.5,
                evidence=[Evidence(
                    source="url_adapter",
                    message=f"Cannot parse URL properly: {str(e)}",
                    severity=Severity.MEDIUM,
                    feature="parse_error",
                    contribution=0.5
                )],
                model_version="heuristic-url-2-error"
            )

        model_score: float | None = None
        dynamic_context_used = False
        if self.url_session is not None:  # pragma: no cover - needs model
            try:
                metadata = self.model_metadata.get("url_lgbm.onnx", {})
                configured_names = metadata.get("feature_names")
                feature_names = (
                    configured_names
                    if isinstance(configured_names, list) and configured_names
                    else None
                )
                model_features = (
                    extract_url_features(
                        url,
                        feature_names=feature_names,
                        context=context,
                    )
                    if feature_names
                    else legacy_features
                )
                dynamic_context_used = bool(
                    context
                    and feature_names
                    and set(feature_names).intersection(CONTEXT_FEATURE_NAMES)
                )
                model_score = self._run_lgbm(self.url_session, model_features)
            except Exception:
                model_score = None

        observations = collect_url_evidence(url)
        if model_score is not None:
            context_suffix = "+enriched-context" if dynamic_context_used else ""
            version = f"url_lgbm.onnx{context_suffix}+multilayer-url-core-4"
        else:
            version = "multilayer-url-core-4"
        # URL observations are evidence only. The unified Risk Core is the sole
        # scorer and policy engine downstream.
        return PredictionResult(
            0.0,
            observations.evidence,
            version,
            model_probability=model_score,
        )

    def _heuristic_url(self, url: str, features: list[float]) -> float:
        signals = analyze_url_signals(url)
        score = 0.03
        if signals.homoglyph:
            score += 0.35
        if signals.brand_mismatch:
            score += 0.34
        if signals.deceptive_subdomain:
            score += 0.24
        if signals.no_https:
            score += 0.16
        if signals.risky_tld:
            score += 0.18
        if signals.ip_host:
            score += 0.22
        if signals.shortlink:
            score += 0.12
        if signals.at_symbol:
            score += 0.20
        if signals.percent_encoded:
            score += 0.10
        if signals.long_url:
            score += 0.10
        if signals.many_delimiters:
            score += 0.10
        if signals.excessive_dots:
            score += 0.08
        if signals.path_depth >= 4:
            score += 0.07
        if signals.query_param_count >= 4:
            score += 0.08
        if signals.suspicious_keywords:
            score += min(0.24, 0.07 * len(signals.suspicious_keywords))
        if features[9] < 0.34 and not signals.brand_mismatch:
            score += 0.08
        return score

    def _url_evidence(self, url: str, features: list[float]) -> list[Evidence]:
        signals = analyze_url_signals(url)
        ev: list[Evidence] = []
        if signals.brand_mismatch:
            brands = ", ".join(signals.brand_mentions[:3])
            ev.append(Evidence(source="url_adapter",
                               message=(
                                   "URL mentions trusted brand "
                                   f"({brands}) but real domain is "
                                   f"{signals.parts.registrable_domain}"
                               ),
                               severity=Severity.CRITICAL,
                               feature="brand_domain_mismatch",
                               contribution=0.42))
        if signals.deceptive_subdomain:
            ev.append(Evidence(source="url_adapter",
                               message=(
                                   "Brand or official-looking domain appears in subdomain; "
                                   f"real domain is {signals.parts.registrable_domain}"
                               ),
                               severity=Severity.CRITICAL,
                               feature="deceptive_subdomain",
                               contribution=0.38))
        if signals.at_symbol:
            ev.append(Evidence(source="url_adapter",
                               message="URL contains @, which can hide the real destination",
                               severity=Severity.HIGH,
                               feature="at_symbol_in_url",
                               contribution=0.26))
        if signals.shortlink:
            ev.append(Evidence(source="url_adapter",
                               message="URL uses a shortener, hiding the final domain",
                               severity=Severity.MEDIUM,
                               feature="is_shortlink",
                               contribution=0.14))
        if signals.suspicious_keywords:
            keywords = ", ".join(signals.suspicious_keywords[:5])
            ev.append(Evidence(source="url_adapter",
                               message=f"URL contains sensitive keywords: {keywords}",
                               severity=Severity.HIGH
                               if {"otp", "password", "bank"} & set(signals.suspicious_keywords)
                               else Severity.MEDIUM,
                               feature="suspicious_keywords",
                               contribution=min(0.28, 0.08 * len(signals.suspicious_keywords))))
        if signals.many_delimiters or signals.percent_encoded or signals.long_url:
            ev.append(Evidence(source="url_adapter",
                               message="URL structure is obfuscated or unusually complex",
                               severity=Severity.MEDIUM,
                               feature="url_obfuscation",
                               contribution=0.16))
        if signals.excessive_dots:
            ev.append(Evidence(source="url_adapter",
                               message="Host has many dot-separated labels",
                               severity=Severity.MEDIUM,
                               feature="excessive_dots",
                               contribution=0.12))
        if has_homoglyph(url):
            ev.append(Evidence(source="url_adapter",
                               message="Domain giả mạo thương hiệu (homoglyph)",
                               severity=Severity.CRITICAL, feature="homoglyph_score",
                               contribution=0.38))
        if features[8] == 0.0:
            ev.append(Evidence(source="url_adapter", message="Không dùng HTTPS",
                               severity=Severity.MEDIUM, feature="has_https", contribution=0.21))
        if features[3] == 1.0:
            ev.append(Evidence(source="url_adapter", message="TLD rủi ro cao",
                               severity=Severity.MEDIUM, feature="tld_risk_score",
                               contribution=0.17))
        if is_ip_host(url):
            ev.append(Evidence(source="url_adapter", message="Địa chỉ dùng IP thay tên miền",
                               severity=Severity.HIGH, feature="has_ip_address", contribution=0.2))
        if features[14] == 1.0:
            ev.append(Evidence(source="url_adapter", message="Đường dẫn chứa từ khóa nhạy cảm",
                               severity=Severity.LOW, feature="path_keyword", contribution=0.09))
        if not ev:
            ev.append(Evidence(source="url_adapter",
                               message="Không phát hiện dấu hiệu rủi ro rõ rệt",
                               severity=Severity.INFO, contribution=0.02))
        return ev

    def _run_lgbm(self, session, features):  # pragma: no cover - needs model
        import numpy as np

        name = session.get_inputs()[0].name
        out = session.run(None, {name: np.array([features], dtype=np.float32)})
        try:
            return float(out[1][0][1])
        except Exception:
            return float(out[0][0])

    # ------------------------------------------------------------------ text
    def predict_text(self, text: str, metadata: dict | None = None) -> PredictionResult:
        clean = preprocess_email(text, metadata)
        chunks = chunk_text(clean) or [clean]
        heuristic_score = self._heuristic_text(clean)
        lightweight_score: float | None = None
        transformer_score: float | None = None
        if self.text_session is not None:  # pragma: no cover - needs model
            try:
                scores = [self._run_text(c) for c in chunks]
                lightweight_score = max(scores) if scores else None
            except Exception:
                lightweight_score = None
        if (
            self.text_transformer_session is not None
            and self.text_tokenizer is not None
            and "mdeberta_text_transformer.onnx" not in self.disabled_models
        ):
            try:
                scores = [
                    self._run_transformer_binary_classifier(
                        self.text_transformer_session,
                        self.text_tokenizer,
                        chunk,
                        max_length=self._metadata_max_length("mdeberta_text_transformer.onnx"),
                    )
                    for chunk in chunks
                ]
                transformer_score = max(scores) if scores else None
            except Exception:
                transformer_score = None
        score = self._hybrid_score(transformer_score, lightweight_score, heuristic_score)
        # The phishing core contributes independent explainable signals from sender
        # metadata, social-engineering language and embedded URLs.
        core = assess_text_risk(
            clean,
            modality=str((metadata or {}).get("modality", "email")),
            metadata=metadata,
            model_score=score,
            technical_signal=detect_injection(clean)[0] >= 0.5,
        )
        version = self._hybrid_version("text", transformer_score, lightweight_score)
        model_evidence = self._text_evidence(
            clean,
            lightweight_score=lightweight_score,
            transformer_score=transformer_score,
        )
        evidence = [
            *core.evidence,
            *(item for item in model_evidence if item.severity != Severity.INFO),
        ]
        return PredictionResult(core.score, evidence, version)

    def _heuristic_text(self, text: str) -> float:
        lower = normalize_for_detection(text)
        score = 0.05
        kw = [k for k in URGENCY_KEYWORDS_VI if k in lower]
        score += 0.12 * len(kw)
        import re

        links = re.findall(r"(?:https?://|www\.)\S+", text)
        if any(
            link.startswith("http://")
            or any(f".{t}" in link for t in HIGH_RISK_TLDS)
            or has_homoglyph(link)
            for link in links
        ):
            score += 0.24
        if re.search(r"ngân hàng|bank|tài khoản", lower) and re.search(
            r"@(?:gmail|yahoo|outlook|hotmail)\.", lower
        ):
            score += 0.16
        if re.search(r"ngân hàng|bank|tài khoản", lower) and re.search(
            r"khóa|khoá|xác minh|xác nhận|đình chỉ", lower
        ):
            score += 0.18
        inj, _ = detect_injection(text)
        score = max(score, inj * 0.6)
        return score

    def _text_evidence(
        self,
        text: str,
        lightweight_score: float | None = None,
        transformer_score: float | None = None,
    ) -> list[Evidence]:
        ev: list[Evidence] = []
        lower = normalize_for_detection(text)
        kw = [k for k in URGENCY_KEYWORDS_VI if k in lower]
        if kw:
            ev.append(Evidence(source="text_adapter",
                               message=f"Ngôn từ hối thúc/đe dọa ({', '.join(kw[:4])})",
                               severity=Severity.HIGH if len(kw) >= 2 else Severity.MEDIUM,
                               feature="urgency_keywords", contribution=0.12 * len(kw)))
        import re

        if re.findall(r"(?:https?://|www\.)\S+", text):
            ev.append(Evidence(source="text_adapter", message="Chứa liên kết trong nội dung",
                               severity=Severity.MEDIUM, feature="link_present", contribution=0.2))
        inj, patterns = detect_injection(text)
        if inj >= 0.5:
            ev.append(Evidence(source="prompt_adapter",
                               message="Phát hiện chỉ dẫn thao túng (prompt injection) ẩn trong nội dung",
                               severity=Severity.CRITICAL, feature="injection", contribution=inj))
        if transformer_score is not None and transformer_score >= 0.5:
            ev.append(Evidence(source="text_transformer",
                               message="Mô hình ngữ nghĩa nhận thấy kịch bản đáng ngờ; đây là tín hiệu hỗ trợ, không phải xác nhận độc hại.",
                               severity=Severity.MEDIUM,
                               feature="text_transformer_probability",
                               contribution=min(0.10, transformer_score)))
        if lightweight_score is not None and lightweight_score >= 0.5:
            ev.append(Evidence(source="text_model",
                               message="Mô hình văn bản nhận thấy mẫu đáng ngờ; cần đối chiếu với bằng chứng kỹ thuật/nội dung.",
                               severity=Severity.MEDIUM,
                               feature="text_model_probability", contribution=min(0.10, lightweight_score)))
        if not ev:
            ev.append(Evidence(source="text_adapter",
                               message="Không phát hiện dấu hiệu lừa đảo rõ rệt",
                               severity=Severity.INFO, contribution=0.02))
        return ev

    def _run_text(self, chunk: str):  # pragma: no cover - needs model
        return self._run_string_binary_classifier(self.text_session, chunk)

    # ---------------------------------------------------------------- prompt
    def predict_prompt(self, text: str) -> PredictionResult:
        heuristic_prob, patterns = detect_injection(text)
        lightweight_score: float | None = None
        transformer_score: float | None = None
        if self.prompt_session is not None:  # pragma: no cover - needs model
            try:
                lightweight_score = self._run_string_binary_classifier(self.prompt_session, text)
            except Exception:
                lightweight_score = None
        if self.prompt_transformer_session is not None and self.prompt_tokenizer is not None:
            try:
                transformer_score = self._run_transformer_binary_classifier(
                    self.prompt_transformer_session,
                    self.prompt_tokenizer,
                    text,
                    max_length=self._metadata_max_length("protectai_prompt_transformer.onnx"),
                )
            except Exception:
                transformer_score = None
        model_prob = self._hybrid_score(transformer_score, lightweight_score, heuristic_prob)
        firewall = assess_prompt_firewall(text)
        # A deterministic high-confidence family cannot be averaged away by a
        # weak/stale classifier. Conversely the ML ensemble still catches novel
        # semantic attacks not covered by fixed signatures.
        prob = _clip01(max(model_prob, firewall.score))
        version = self._hybrid_version("prompt", transformer_score, lightweight_score)
        ev: list[Evidence] = list(firewall.evidence)
        if transformer_score is not None and transformer_score >= 0.5:
            ev.append(Evidence(source="prompt_transformer",
                               message="ProtectAI Transformer flagged prompt injection",
                               severity=Severity.CRITICAL,
                               feature="prompt_transformer_probability",
                               contribution=transformer_score))
        if lightweight_score is not None and lightweight_score >= 0.5:
            ev.append(Evidence(source="prompt_model",
                               message="Lightweight prompt model flagged injection risk",
                               severity=Severity.CRITICAL,
                               feature="prompt_model_probability",
                               contribution=lightweight_score))
        if heuristic_prob >= 0.5:
            ev.append(Evidence(source="prompt_adapter",
                               message="Phát hiện mẫu tấn công ghi đè chỉ dẫn",
                               severity=Severity.CRITICAL, feature="injection_pattern",
                               contribution=heuristic_prob))
        return PredictionResult(prob, ev, version)

    def _run_transformer_binary_classifier(
        self, session: Any, tokenizer: Any, text: str, max_length: int = 256
    ) -> float:
        """Tokenize text and run a standard sequence-classification ONNX graph."""
        import numpy as np

        encoded = tokenizer(
            text,
            return_tensors="np",
            truncation=True,
            max_length=max_length,
        )
        feed: dict[str, Any] = {}
        for model_input in session.get_inputs():
            if model_input.name in encoded:
                feed[model_input.name] = np.asarray(encoded[model_input.name], dtype=np.int64)
            elif model_input.name == "token_type_ids" and "input_ids" in encoded:
                feed[model_input.name] = np.zeros_like(encoded["input_ids"], dtype=np.int64)
            else:
                raise RuntimeError(f"tokenizer did not produce ONNX input {model_input.name}")
        return self._extract_binary_probability(session.run(None, feed))

    def _run_string_binary_classifier(self, session: Any, text: str) -> float:
        """Run a string-input ONNX binary classifier and return class-1 probability."""
        if session is None:
            raise RuntimeError("model session is not loaded")
        inputs = session.get_inputs()
        if not inputs or "string" not in inputs[0].type:
            raise RuntimeError("only string-input ONNX classifiers are supported here")

        import numpy as np

        raw_outputs = session.run(None, {inputs[0].name: np.array([[text]], dtype=object)})
        return self._extract_binary_probability(raw_outputs)

    def _extract_binary_probability(self, raw_outputs: list[Any]) -> float:
        import numpy as np

        for output in raw_outputs:
            if isinstance(output, list) and output and isinstance(output[0], dict):
                row = output[0]
                if 1 in row:
                    return float(row[1])
                if "1" in row:
                    return float(row["1"])
                continue

            arr = np.asarray(output)
            if arr.size == 0:
                continue
            if arr.dtype.kind in {"i", "u"} and arr.ndim <= 1:
                # Label output, not probability output.
                continue
            if arr.ndim >= 2 and arr.shape[-1] >= 2:
                row = arr.reshape(-1, arr.shape[-1])[0].astype(float)
                if row.min() < 0.0 or row.max() > 1.0 or not np.isclose(row.sum(), 1.0, atol=1e-3):
                    row = np.exp(row - np.max(row))
                    row = row / row.sum()
                return float(row[1])
            if arr.ndim == 1 and arr.size >= 2:
                row = arr.astype(float)
                if row.min() < 0.0 or row.max() > 1.0 or not np.isclose(row.sum(), 1.0, atol=1e-3):
                    row = np.exp(row - np.max(row))
                    row = row / row.sum()
                return float(row[1])
            if arr.size == 1:
                return float(arr.reshape(-1)[0])
        raise RuntimeError("could not read class probability from ONNX outputs")
