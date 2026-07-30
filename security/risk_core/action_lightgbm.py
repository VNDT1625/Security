"""Bounded LightGBM adapter for action risk.

The deployed URL model has a different feature schema and is intentionally not
reused here. Until an action model artifact exists, this adapter reports an
explicit safe fallback instead of inventing a prediction.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from .action_config import ActionRiskConfig
from .action_features import ActionFeatureVector
from .action_types import LightGBMRiskResult


Predictor = Callable[[list[float]], float]


class LightGBMRiskAdapter:
    def __init__(
        self,
        predictor: Predictor | None = None,
        *,
        model_version: str = "unavailable",
    ) -> None:
        self._predictor = predictor
        self.model_version = model_version

    @classmethod
    def from_onnx(cls, path: str | Path | None) -> "LightGBMRiskAdapter":
        if not path:
            return cls()
        model_path = Path(path)
        if not model_path.is_file():
            return cls(model_version="artifact_missing")
        try:
            import numpy as np
            import onnxruntime as ort

            session = ort.InferenceSession(
                str(model_path),
                providers=["CPUExecutionProvider"],
            )
            input_name = session.get_inputs()[0].name

            def predict(values: list[float]) -> float:
                output = session.run(
                    None,
                    {input_name: np.asarray([values], dtype=np.float32)},
                )
                try:
                    probabilities: Any = output[1][0]
                    if isinstance(probabilities, dict):
                        return float(probabilities.get(1, probabilities.get("1", 0.0)))
                    return float(probabilities[1])
                except (IndexError, KeyError, TypeError, ValueError):
                    return float(output[0][0])

            return cls(predict, model_version=model_path.name)
        except (ImportError, OSError, RuntimeError, ValueError):
            return cls(model_version="load_failed")

    def assess(
        self,
        features: ActionFeatureVector,
        config: ActionRiskConfig,
    ) -> LightGBMRiskResult:
        out_of_distribution = features.missing_ratio >= config.ml_ood_missing_ratio
        if self._predictor is None:
            return LightGBMRiskResult(
                available=False,
                out_of_distribution=out_of_distribution,
                model_version=self.model_version,
                error_code=(
                    "artifact_missing"
                    if self.model_version in {"unavailable", "artifact_missing"}
                    else "model_unavailable"
                ),
            )
        try:
            probability = max(
                0.0,
                min(1.0, float(self._predictor(features.numeric_vector()))),
            )
        except (ArithmeticError, RuntimeError, TypeError, ValueError):
            return LightGBMRiskResult(
                available=False,
                out_of_distribution=out_of_distribution,
                model_version=self.model_version,
                error_code="inference_failed",
            )

        separation = abs(probability - 0.5) * 2.0
        model_confidence = separation * (1.0 - min(0.8, features.missing_ratio))
        if out_of_distribution:
            model_confidence *= 0.55
        upward_signal = max(0.0, (probability - 0.5) * 2.0)
        contribution = (
            config.ml_max_contribution * upward_signal * model_confidence
        )
        ranked = sorted(
            (
                (name, abs(float(value)))
                for name, value in features.values.items()
                if value is not None and name != "action_type_code"
            ),
            key=lambda item: (-item[1], item[0]),
        )[:5]
        return LightGBMRiskResult(
            available=True,
            risk_probability=round(probability, 6),
            risk_contribution=round(
                min(config.ml_max_contribution, contribution),
                4,
            ),
            model_confidence=round(model_confidence, 6),
            out_of_distribution=out_of_distribution,
            top_features=tuple(
                {"name": name, "impact": round(value, 6)}
                for name, value in ranked
            ),
            model_version=self.model_version,
        )
