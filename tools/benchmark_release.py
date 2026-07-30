"""Prewise release evaluator — the reproducible benchmark referenced by FINAL_BENCHMARK_2026.

What this closes
----------------
* Blocker 3 - one evaluator, run against the deployed artifacts, persisting JSON,
  confusion matrices and misclassification samples under ``artifacts/benchmarks/``.
* Blocker 4 - an ablation on the same frozen holdout: rules only, ML only,
  ML + rules, and the full Prewise Risk Core + policy.
* Blocker 5 - the full decision path is scored, not only the raw model
  probability, so a high model score that is calibrated back to ALLOW shows up
  as a measured regression instead of hiding.
* Blocker 6 (partly) - latency is reported as p50/p95/p99 per arm on declared
  hardware rather than as a single best-case number.

Ablation arms
-------------
URL
  ``rules_only``      deterministic URL Risk Core with no ML input
  ``ml_only``         raw LightGBM ONNX probability, thresholded
  ``ml_plus_rules``   URL Risk Core with the ML score fused in
  ``full_offline``    Risk Core v2 criteria + override rules + Policy Engine v2,
                      running the offline evidence set (no network enrichment).
                      This is exactly what the product computes when DNS and
                      threat-intelligence feeds are unavailable, so it is a
                      *lower bound* on deployed quality.
  ``full_enriched``   the real ``InferenceService.assess_url`` including DNS,
                      domain and threat-feed enrichment. Network bound, so it
                      runs on a subsample (``--enriched-sample``).

email / sms
  ``rules_only``      deterministic text Risk Core with no ML input
  ``ml_only``         raw text-classifier probability, thresholded
  ``full_offline``    the deployed message path (ML fused into the text Risk
                      Core, plus embedded-URL analysis and the policy engine)

prompt
  ``rules_only``      deterministic prompt firewall signatures
  ``ml_only``         raw prompt-injection classifier probability
  ``full_offline``    the deployed ``predict_prompt`` fusion + policy

Usage
-----
    python -m tools.benchmark_release                     # every arm, offline
    python -m tools.benchmark_release --modes url         # one modality
    python -m tools.benchmark_release --enriched-sample 150
    python -m tools.benchmark_release --limit 200         # fast smoke run
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

HOLDOUT_DIR = REPO_ROOT / "benchmarks" / "prewise_holdout" / "v1"
OUTPUT_DIR = REPO_ROOT / "artifacts" / "benchmarks"

# A Prewise verdict is an action, not a probability. Everything at WARN or above
# counts as "flagged" for the confusion matrix, because that is the point at
# which the product visibly interrupts the user.
FLAGGING_DECISIONS = {"warn", "require_review", "soft_block", "hard_block"}
DEFAULT_ML_THRESHOLD = 0.5
# Risk Core scores are 0..100; 20 is the WARN boundary in PolicyEngineV2.
CORE_FLAG_THRESHOLD = 0.20


def _log(message: str) -> None:
    print(f"[benchmark] {message}", flush=True)


# --------------------------------------------------------------------- metrics
@dataclass
class ArmScore:
    arm: str
    mode: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    errors: int = 0
    misclassified: list[dict[str, Any]] = field(default_factory=list)

    def observe(
        self,
        *,
        truth: int,
        flagged: bool,
        latency_ms: float,
        sample: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        self.latencies_ms.append(latency_ms)
        if truth == 1 and flagged:
            self.tp += 1
        elif truth == 1 and not flagged:
            self.fn += 1
            self._record(sample, "false_negative", detail)
        elif truth == 0 and flagged:
            self.fp += 1
            self._record(sample, "false_positive", detail)
        else:
            self.tn += 1

    def _record(self, sample: str, kind: str, detail: dict[str, Any] | None) -> None:
        if len(self.misclassified) >= 40:
            return
        self.misclassified.append(
            {"kind": kind, "sample": sample[:300], **(detail or {})}
        )

    def summary(self) -> dict[str, Any]:
        total = self.tp + self.fp + self.tn + self.fn
        accuracy = (self.tp + self.tn) / total if total else 0.0
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0
        recall = self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        fpr = self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0
        fnr = self.fn / (self.fn + self.tp) if (self.fn + self.tp) else 0.0
        latencies = sorted(self.latencies_ms)

        def pct(p: float) -> float:
            if not latencies:
                return 0.0
            index = min(len(latencies) - 1, max(0, int(round(p * (len(latencies) - 1)))))
            return round(latencies[index], 3)

        return {
            "arm": self.arm,
            "mode": self.mode,
            "rows_scored": total,
            "errors": self.errors,
            "confusion_matrix": {
                "true_positive": self.tp,
                "false_positive": self.fp,
                "true_negative": self.tn,
                "false_negative": self.fn,
            },
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "latency_ms": {
                "p50": pct(0.50),
                "p95": pct(0.95),
                "p99": pct(0.99),
                "mean": round(statistics.fmean(latencies), 3) if latencies else 0.0,
                "max": round(latencies[-1], 3) if latencies else 0.0,
            },
        }


# ------------------------------------------------------------------- scoring fns
class Scorers:
    """Lazily constructed so ``--modes`` only pays for what it uses."""

    def __init__(self) -> None:
        self._engine = None
        self._service = None

    @property
    def engine(self):
        if self._engine is None:
            from ai.inference.engine import InferenceEngine
            from backend.config import settings

            self._engine = InferenceEngine(model_dir=settings.model_dir)
            status = self._engine.model_status["modalities_ready"]
            _log(f"inference engine ready: {status}")
        return self._engine

    @property
    def service(self):
        if self._service is None:
            from backend.services.inference_service import InferenceService

            self._service = InferenceService(engine=self.engine)
        return self._service

    # ------------------------------------------------------------------- URL
    def url_rules_only(self, url: str) -> tuple[bool, dict[str, Any]]:
        from security.url_risk_core import assess_url

        result = assess_url(url, model_score=None)
        return result.score >= CORE_FLAG_THRESHOLD, {"score": round(result.score, 4)}

    def url_ml_only(self, url: str) -> tuple[bool, dict[str, Any]]:
        probability = self._url_model_probability(url)
        if probability is None:
            raise RuntimeError("URL model is not loaded; ml_only arm cannot be scored")
        return probability >= DEFAULT_ML_THRESHOLD, {"probability": round(probability, 4)}

    def url_ml_plus_rules(self, url: str) -> tuple[bool, dict[str, Any]]:
        from security.url_risk_core import assess_url

        probability = self._url_model_probability(url)
        result = assess_url(url, model_score=probability)
        return result.score >= CORE_FLAG_THRESHOLD, {
            "score": round(result.score, 4),
            "model": None if probability is None else round(probability, 4),
        }

    def _url_model_probability(self, url: str) -> float | None:
        engine = self.engine
        if engine.url_session is None:
            return None
        from ai.adapters.url_adapter import extract_url_features

        metadata = engine.model_metadata.get("url_lgbm.onnx", {})
        names = metadata.get("feature_names")
        features = (
            extract_url_features(url, feature_names=names)
            if isinstance(names, list) and names
            else extract_url_features(url)
        )
        try:
            return float(engine._run_lgbm(engine.url_session, features))
        except Exception:
            return None

    def url_full_offline(self, url: str) -> tuple[bool, dict[str, Any]]:
        """Risk Core v2 + Policy Engine v2 on the offline evidence set."""
        from security.risk_core import PolicyEngineV2, default_config
        from security.risk_core import assess as assess_risk_v2
        from security.risk_core.detectors import (
            ScanObservations,
            add_offline_url_findings,
            build_criteria_evidence,
        )
        from security.risk_core.url_overrides import URL_OVERRIDE_RULES

        prediction = self.engine.predict_url(url)
        observations = ScanObservations(url)
        add_offline_url_findings(observations, prediction.evidence)
        config = default_config()
        risk = assess_risk_v2(
            build_criteria_evidence(observations, config),
            config=config,
            override_rules=URL_OVERRIDE_RULES,
        )
        policy = PolicyEngineV2().decide(risk)
        decision = policy.decision.value
        return decision in FLAGGING_DECISIONS, {
            "risk_score": round(risk.risk_score, 2),
            "decision": decision,
            "confidence": round(risk.confidence_score, 2),
        }

    def url_full_enriched(self, url: str) -> tuple[bool, dict[str, Any]]:
        response = self.service.assess_url(url, context="", context_ai_mode="off")
        decision = response.decision.value.lower()
        flagged = decision in {"warn", "block", "ask_user_confirmation"}
        return flagged, {
            "risk_score": round(response.risk_score, 4),
            "decision": response.decision.value,
            "level": response.risk_level.value,
        }

    # ------------------------------------------------------------------ text
    def _text_rules_only(self, text: str, modality: str) -> tuple[bool, dict[str, Any]]:
        from security.text_risk_core import assess_text_risk

        result = assess_text_risk(text, modality=modality, metadata={"modality": modality})
        return result.score >= CORE_FLAG_THRESHOLD, {"score": round(result.score, 4)}

    def _text_ml_only(self, text: str) -> tuple[bool, dict[str, Any]]:
        engine = self.engine
        if engine.text_session is None:
            raise RuntimeError("text model is not loaded; ml_only arm cannot be scored")
        from ai.adapters.text_adapter import chunk_text, preprocess_email

        clean = preprocess_email(text, None)
        chunks = chunk_text(clean) or [clean]
        probability = max(engine._run_text(chunk) for chunk in chunks)
        return probability >= DEFAULT_ML_THRESHOLD, {"probability": round(probability, 4)}

    def _text_full_offline(self, text: str, modality: str) -> tuple[bool, dict[str, Any]]:
        response = self.service.assess_text(
            text,
            modality=modality,
            metadata={"modality": modality, "analysis_depth": "quick"},
            context_ai_mode="off",
        )
        decision = response.decision.value.lower()
        flagged = decision in {"warn", "block", "ask_user_confirmation"}
        return flagged, {
            "risk_score": round(response.risk_score, 4),
            "decision": response.decision.value,
        }

    # ---------------------------------------------------------------- prompt
    def prompt_rules_only(self, text: str) -> tuple[bool, dict[str, Any]]:
        from security.prompt_firewall import assess_prompt_firewall

        result = assess_prompt_firewall(text)
        return result.score >= DEFAULT_ML_THRESHOLD, {"score": round(result.score, 4)}

    def prompt_ml_only(self, text: str) -> tuple[bool, dict[str, Any]]:
        engine = self.engine
        if engine.prompt_session is None:
            raise RuntimeError("prompt model is not loaded; ml_only arm cannot be scored")
        probability = engine._run_string_binary_classifier(engine.prompt_session, text)
        return probability >= DEFAULT_ML_THRESHOLD, {"probability": round(probability, 4)}

    def prompt_full_offline(self, text: str) -> tuple[bool, dict[str, Any]]:
        prediction = self.engine.predict_prompt(text)
        return prediction.risk_score >= DEFAULT_ML_THRESHOLD, {
            "risk_score": round(prediction.risk_score, 4)
        }


# ------------------------------------------------------------------- execution
def _load_rows(filename: str) -> list[dict[str, str]]:
    import csv

    path = HOLDOUT_DIR / filename
    if not path.exists():
        raise SystemExit(
            f"missing holdout file {path}. Run: python -m tools.build_holdout"
        )
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _run_arm(
    arm: str,
    mode: str,
    rows: list[dict[str, str]],
    payload_key: str,
    scorer: Callable[[str], tuple[bool, dict[str, Any]]],
) -> ArmScore:
    score = ArmScore(arm=arm, mode=mode)
    total = len(rows)
    for index, row in enumerate(rows, start=1):
        payload = row[payload_key]
        truth = int(row["label"])
        started = time.perf_counter()
        try:
            flagged, detail = scorer(payload)
        except Exception as exc:  # a scorer that cannot run must not fake a result
            score.errors += 1
            if score.errors <= 3:
                _log(f"  {arm}/{mode}: error on row {index}: {type(exc).__name__}: {exc}")
            if score.errors > max(10, total // 20):
                raise SystemExit(
                    f"arm {arm}/{mode} failed on more than 5% of rows; refusing to "
                    f"publish a partial result ({score.errors} errors)"
                ) from exc
            continue
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        score.observe(
            truth=truth,
            flagged=flagged,
            latency_ms=elapsed_ms,
            sample=payload,
            detail=detail,
        )
        if index % 500 == 0:
            _log(f"  {arm}/{mode}: {index}/{total}")
    return score


MODE_SPECS: dict[str, dict[str, Any]] = {
    "url": {"file": "url_holdout.csv", "payload": "url"},
    "email": {"file": "email_holdout.csv", "payload": "text"},
    "sms": {"file": "sms_holdout.csv", "payload": "text"},
    "prompt": {"file": "prompt_holdout.csv", "payload": "text"},
}


def build_plan(scorers: Scorers, mode: str) -> list[tuple[str, Callable[[str], tuple[bool, dict[str, Any]]]]]:
    if mode == "url":
        return [
            ("rules_only", scorers.url_rules_only),
            ("ml_only", scorers.url_ml_only),
            ("ml_plus_rules", scorers.url_ml_plus_rules),
            ("full_offline", scorers.url_full_offline),
        ]
    if mode in {"email", "sms"}:
        return [
            ("rules_only", lambda text, m=mode: scorers._text_rules_only(text, m)),
            ("ml_only", scorers._text_ml_only),
            ("full_offline", lambda text, m=mode: scorers._text_full_offline(text, m)),
        ]
    if mode == "prompt":
        return [
            ("rules_only", scorers.prompt_rules_only),
            ("ml_only", scorers.prompt_ml_only),
            ("full_offline", scorers.prompt_full_offline),
        ]
    raise ValueError(mode)


def _environment() -> dict[str, Any]:
    import os

    info: dict[str, Any] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count(),
    }
    try:
        import onnxruntime

        info["onnxruntime"] = onnxruntime.__version__
        info["onnxruntime_providers"] = onnxruntime.get_available_providers()
    except Exception:
        info["onnxruntime"] = None
    return info


def _artifact_hashes() -> dict[str, str]:
    import hashlib

    from backend.config import settings

    hashes: dict[str, str] = {}
    model_dir = Path(settings.model_dir)
    for name in ("url_lgbm.onnx", "mdeberta_text.onnx", "protectai_prompt.onnx"):
        path = model_dir / name
        if not path.exists():
            hashes[name] = "MISSING"
            continue
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        hashes[name] = digest.hexdigest()
    return hashes


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Prewise release benchmark")
    parser.add_argument(
        "--modes", nargs="*", choices=sorted(MODE_SPECS), default=sorted(MODE_SPECS)
    )
    parser.add_argument("--limit", type=int, default=0, help="cap rows per mode (0 = all)")
    parser.add_argument(
        "--enriched-sample",
        type=int,
        default=0,
        help="rows for the network-bound full_enriched URL arm (0 = skip)",
    )
    parser.add_argument("--out", default=str(OUTPUT_DIR), help="output directory")
    args = parser.parse_args()

    manifest_path = HOLDOUT_DIR / "manifest.json"
    if not manifest_path.exists():
        raise SystemExit("no frozen holdout; run: python -m tools.build_holdout")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)

    scorers = Scorers()
    report: dict[str, Any] = {
        "benchmark": "prewise-release",
        "holdout": {
            "name": manifest["name"],
            "version": manifest["version"],
            "protocol": manifest["protocol"],
            "arms": {
                entry["arm"]: {
                    "sha256": entry["sha256"],
                    "rows": entry["rows"],
                    "class_counts": entry["class_counts"],
                    "evaluation_source": entry["evaluation_source"],
                    "overlap_risk": entry["overlap_risk"],
                }
                for entry in manifest["arms"]
            },
        },
        "artifact_sha256": _artifact_hashes(),
        "environment": _environment(),
        "flagging_rule": (
            "A row counts as flagged when the product would visibly interrupt the "
            "user, i.e. decision in WARN / REQUIRE_REVIEW / SOFT_BLOCK / HARD_BLOCK "
            "for policy arms, or probability >= 0.5 for raw-model arms."
        ),
        "results": {},
        "row_limit_applied": args.limit or None,
    }

    for mode in args.modes:
        spec = MODE_SPECS[mode]
        rows = _load_rows(spec["file"])
        if args.limit:
            rows = rows[: args.limit]
        _log(f"=== {mode}: {len(rows)} rows ===")
        mode_results = []
        for arm_name, scorer in build_plan(scorers, mode):
            _log(f"running {mode}/{arm_name} ...")
            started = time.perf_counter()
            score = _run_arm(mode, arm_name, rows, spec["payload"], scorer)
            summary = score.summary()
            summary["wall_seconds"] = round(time.perf_counter() - started, 2)
            mode_results.append(summary)
            _log(
                f"  -> acc={summary['accuracy']:.4f} f1={summary['f1']:.4f} "
                f"fpr={summary['false_positive_rate']:.4f} p95={summary['latency_ms']['p95']}ms"
            )
            (output_dir / f"misclassified_{mode}_{arm_name}.json").write_text(
                json.dumps(score.misclassified, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        report["results"][mode] = mode_results

    if args.enriched_sample and "url" in args.modes:
        rows = _load_rows(MODE_SPECS["url"]["file"])[: args.enriched_sample]
        _log(f"=== url/full_enriched (network bound): {len(rows)} rows ===")
        started = time.perf_counter()
        score = _run_arm("url", "full_enriched", rows, "url", scorers.url_full_enriched)
        summary = score.summary()
        summary["wall_seconds"] = round(time.perf_counter() - started, 2)
        summary["note"] = (
            "Network-bound arm on a subsample. Latency here includes live DNS, WHOIS "
            "and threat-feed lookups and is NOT comparable to the offline arms."
        )
        report["results"].setdefault("url", []).append(summary)
        (output_dir / "misclassified_url_full_enriched.json").write_text(
            json.dumps(score.misclassified, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    report_path = output_dir / "release-benchmark.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    _log(f"wrote {report_path}")

    markdown = render_markdown(report)
    markdown_path = output_dir / "release-benchmark.md"
    markdown_path.write_text(markdown, encoding="utf-8")
    _log(f"wrote {markdown_path}")
    return 0


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Prewise release benchmark (machine generated)",
        "",
        f"Holdout: `{report['holdout']['name']}` `{report['holdout']['version']}`",
        "",
        "## Frozen holdout",
        "",
        "| Arm | Rows | Benign | Malicious | Source | Overlap risk | SHA-256 |",
        "|---|---:|---:|---:|---|---|---|",
    ]
    for arm, entry in report["holdout"]["arms"].items():
        lines.append(
            f"| {arm} | {entry['rows']} | {entry['class_counts']['benign']} | "
            f"{entry['class_counts']['malicious']} | {entry['evaluation_source']} | "
            f"{entry['overlap_risk']} | `{entry['sha256'][:16]}...` |"
        )
    lines += ["", "## Deployed artifact hashes", "", "| Artifact | SHA-256 |", "|---|---|"]
    for name, digest in report["artifact_sha256"].items():
        lines.append(f"| `{name}` | `{digest}` |")

    lines += ["", "## Ablation results", ""]
    for mode, arms in report["results"].items():
        lines += [
            f"### {mode}",
            "",
            "| Arm | Acc | Precision | Recall | F1 | FPR | FNR | TP | FP | TN | FN | p50 ms | p95 ms | p99 ms |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for arm in arms:
            matrix = arm["confusion_matrix"]
            latency = arm["latency_ms"]
            lines.append(
                f"| {arm['mode']} | {arm['accuracy']:.4f} | {arm['precision']:.4f} | "
                f"{arm['recall']:.4f} | {arm['f1']:.4f} | {arm['false_positive_rate']:.4f} | "
                f"{arm['false_negative_rate']:.4f} | {matrix['true_positive']} | "
                f"{matrix['false_positive']} | {matrix['true_negative']} | "
                f"{matrix['false_negative']} | {latency['p50']} | {latency['p95']} | "
                f"{latency['p99']} |"
            )
        lines.append("")
    lines += [
        "## Environment",
        "",
        "```json",
        json.dumps(report["environment"], indent=2),
        "```",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
