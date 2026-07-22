"""Versioned, dependency-light benchmark harness for local Legal RAG engines."""

from __future__ import annotations

import hashlib
import inspect
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    query: str
    relevance: dict[str, int] = field(default_factory=dict)
    split: str = "canary"
    slice: str = "single_provision"
    context: dict[str, str] = field(default_factory=dict)
    exact_citation: bool = False
    expected_abstention: bool = False
    notes: str = ""
    annotation: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> BenchmarkCase:
        relevance = value.get("relevance", {})
        if isinstance(relevance, list):
            relevance = {str(chunk_id): 1 for chunk_id in relevance}
        if not isinstance(relevance, Mapping):
            raise ValueError("relevance must be an object or list")
        normalized = {str(key): int(grade) for key, grade in relevance.items()}
        if any(grade <= 0 for grade in normalized.values()):
            raise ValueError("relevance grades must be positive integers")
        case_id = str(value.get("case_id") or value.get("id") or "").strip()
        query = str(value.get("query") or "").strip()
        if not case_id or not query:
            raise ValueError("each case requires case_id and query")
        expected_abstention = bool(value.get("expected_abstention", False))
        if not normalized and not expected_abstention:
            raise ValueError(f"{case_id}: a retrieval case requires relevance labels")
        return cls(
            case_id=case_id,
            query=query,
            relevance=normalized,
            split=str(value.get("split", "canary")),
            slice=str(value.get("slice", "single_provision")),
            context={str(k): str(v) for k, v in dict(value.get("context", {})).items()},
            exact_citation=bool(value.get("exact_citation", False)),
            expected_abstention=expected_abstention,
            notes=str(value.get("notes", "")),
            annotation=dict(value.get("annotation", {})),
        )


@dataclass(frozen=True)
class GateConfig:
    min_recall: float = 0.98
    min_mrr: float = 0.80
    min_ndcg: float = 0.85
    min_abstention: float = 0.99
    min_exact_citation: float = 1.0
    max_regression: float = 0.02
    max_p95_latency_ms: float = 2_000.0

    def __post_init__(self) -> None:
        for name in (
            "min_recall",
            "min_mrr",
            "min_ndcg",
            "min_abstention",
            "min_exact_citation",
        ):
            value = float(getattr(self, name))
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        if self.max_regression < 0:
            raise ValueError("max_regression must be non-negative")
        if self.max_p95_latency_ms <= 0:
            raise ValueError("max_p95_latency_ms must be positive")

    def model_dump(self) -> dict[str, float]:
        return {
            name: float(getattr(self, name))
            for name in (
                "min_recall",
                "min_mrr",
                "min_ndcg",
                "min_abstention",
                "min_exact_citation",
                "max_regression",
                "max_p95_latency_ms",
            )
        }


def load_cases(path: str | Path, *, split: str | None = None) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    with Path(path).open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                case = BenchmarkCase.from_mapping(json.loads(line))
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid benchmark row {line_number}: {exc}") from exc
            if split is None or case.split == split:
                cases.append(case)
    if not cases:
        raise ValueError("benchmark contains no selected cases")
    if len({case.case_id for case in cases}) != len(cases):
        raise ValueError("benchmark case_id values must be unique")
    return cases


def _percentile(values: Sequence[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] * (upper - position) + ordered[upper] * (position - lower)


def _dcg(grades: Sequence[int]) -> float:
    return sum((2**grade - 1) / math.log2(rank + 2) for rank, grade in enumerate(grades))


def score_ranking(case: BenchmarkCase, ranking: Sequence[str], *, k: int) -> dict[str, Any]:
    cutoff = list(ranking[:k])
    relevant = set(case.relevance)
    found = [chunk_id for chunk_id in cutoff if chunk_id in relevant]
    first_rank = next((rank for rank, item in enumerate(cutoff, start=1) if item in relevant), None)
    ideal = sorted(case.relevance.values(), reverse=True)[:k]
    observed = [case.relevance.get(item, 0) for item in cutoff]
    ideal_dcg = _dcg(ideal)
    abstained = not ranking
    return {
        "recall_at_k": len(set(found)) / len(relevant) if relevant else 0.0,
        "hit_at_k": float(bool(found)),
        "reciprocal_rank": 1.0 / first_rank if first_rank else 0.0,
        "ndcg_at_k": _dcg(observed) / ideal_dcg if ideal_dcg else 0.0,
        "first_relevant_rank": first_rank,
        "exact_top1": (
            float(bool(cutoff) and cutoff[0] in relevant) if case.exact_citation else None
        ),
        "abstention_correct": (float(abstained) if case.expected_abstention else None),
    }


def calculate_metrics(per_case: Sequence[Mapping[str, Any]], *, k: int) -> dict[str, Any]:
    retrieval = [row for row in per_case if not row.get("expected_abstention")]
    exact = [row for row in retrieval if row.get("exact_citation")]
    abstention = [row for row in per_case if row.get("expected_abstention")]
    latencies = [float(row.get("latency_ms", 0.0)) for row in per_case]

    def mean(metric: str, rows: Sequence[Mapping[str, Any]]) -> float:
        values = [float(row[metric]) for row in rows if row.get(metric) is not None]
        return statistics.fmean(values) if values else 0.0

    return {
        "case_count": len(per_case),
        "retrieval_case_count": len(retrieval),
        "abstention_case_count": len(abstention),
        f"candidate_recall_at_{k}": round(mean("recall_at_k", retrieval), 6),
        f"hit_rate_at_{k}": round(mean("hit_at_k", retrieval), 6),
        f"mrr_at_{k}": round(mean("reciprocal_rank", retrieval), 6),
        f"ndcg_at_{k}": round(mean("ndcg_at_k", retrieval), 6),
        "exact_citation_top1_accuracy": round(mean("exact_top1", exact), 6),
        "abstention_accuracy": round(mean("abstention_correct", abstention), 6),
        "latency_ms": {
            "p50": round(_percentile(latencies, 0.50), 3),
            "p95": round(_percentile(latencies, 0.95), 3),
            "p99": round(_percentile(latencies, 0.99), 3),
            "mean": round(statistics.fmean(latencies), 3) if latencies else 0.0,
        },
    }


def reviewed_dataset_status(cases: Sequence[BenchmarkCase]) -> dict[str, Any]:
    """Return deterministic eligibility; never infer legal review from gold labels."""

    reasons: list[str] = []
    if not cases:
        reasons.append("dataset_empty")
    for case in cases:
        annotation = case.annotation
        annotators = annotation.get("annotator_ids", [])
        if annotation.get("status") != "adjudicated":
            reasons.append(f"{case.case_id}:not_adjudicated")
        if not isinstance(annotators, list) or len(set(map(str, annotators))) < 2:
            reasons.append(f"{case.case_id}:two_annotators_required")
        if not str(annotation.get("legal_reviewer_id", "")).strip():
            reasons.append(f"{case.case_id}:legal_reviewer_required")
        if not str(annotation.get("reviewed_at", "")).strip():
            reasons.append(f"{case.case_id}:reviewed_at_required")
    return {
        "production_eligible": not reasons,
        "reason_codes": reasons,
    }


def load_metrics(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read baseline metrics: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("baseline metrics must be a JSON object")
    return dict(payload)


def evaluate_release_gate(
    candidate: Mapping[str, Any],
    baseline: Mapping[str, Any],
    *,
    top_k: int,
    config: GateConfig,
    dataset_status: Mapping[str, Any],
    baseline_path: str = "",
    baseline_sha256: str = "",
) -> dict[str, Any]:
    """Evaluate absolute, regression, latency, and review gates."""

    checks: list[dict[str, Any]] = []

    def add_check(
        name: str,
        *,
        actual: Any,
        comparator: str,
        threshold: Any,
        passed: bool,
        baseline_value: Any = None,
    ) -> None:
        check = {
            "name": name,
            "actual": actual,
            "comparator": comparator,
            "threshold": threshold,
            "passed": bool(passed),
        }
        if baseline_value is not None:
            check["baseline"] = baseline_value
        checks.append(check)

    production_eligible = bool(dataset_status.get("production_eligible", False))
    add_check(
        "reviewed_dataset_required",
        actual=production_eligible,
        comparator="==",
        threshold=True,
        passed=production_eligible,
    )
    for count_key in ("case_count", "retrieval_case_count", "abstention_case_count"):
        actual = candidate.get(count_key)
        expected = baseline.get(count_key)
        add_check(
            f"baseline_compatible:{count_key}",
            actual=actual,
            comparator="==",
            threshold=expected,
            passed=actual is not None and expected is not None and actual == expected,
            baseline_value=expected,
        )

    quality = {
        f"candidate_recall_at_{top_k}": config.min_recall,
        f"mrr_at_{top_k}": config.min_mrr,
        f"ndcg_at_{top_k}": config.min_ndcg,
        "abstention_accuracy": config.min_abstention,
        "exact_citation_top1_accuracy": config.min_exact_citation,
    }
    for metric, minimum in quality.items():
        candidate_value = candidate.get(metric)
        baseline_value = baseline.get(metric)
        is_number = isinstance(candidate_value, (int, float))
        add_check(
            f"minimum:{metric}",
            actual=candidate_value,
            comparator=">=",
            threshold=minimum,
            passed=is_number and float(candidate_value) >= minimum,
        )
        baseline_is_number = isinstance(baseline_value, (int, float))
        regression_floor = (
            float(baseline_value) - config.max_regression if baseline_is_number else None
        )
        add_check(
            f"regression:{metric}",
            actual=candidate_value,
            comparator=">= baseline - max_regression",
            threshold=regression_floor,
            passed=(
                is_number
                and baseline_is_number
                and float(candidate_value) >= float(regression_floor)
            ),
            baseline_value=baseline_value,
        )

    latency = candidate.get("latency_ms", {})
    latency_map = latency if isinstance(latency, Mapping) else {}
    p95 = latency_map.get("p95")
    add_check(
        "maximum:latency_ms.p95",
        actual=p95,
        comparator="<=",
        threshold=config.max_p95_latency_ms,
        passed=isinstance(p95, (int, float)) and float(p95) <= config.max_p95_latency_ms,
    )
    passed = all(check["passed"] for check in checks)
    return {
        "schema_version": 1,
        "evaluated": True,
        "passed": passed,
        "production_eligible": production_eligible,
        "dataset_review": dict(dataset_status),
        "baseline": {
            "path": baseline_path,
            "sha256": baseline_sha256,
        },
        "config": config.model_dump(),
        "checks": checks,
        "failed_checks": [check["name"] for check in checks if not check["passed"]],
    }


def bootstrap_confidence_intervals(
    per_case: Sequence[Mapping[str, Any]], *, k: int, seed: int, samples: int = 1000
) -> dict[str, list[float]]:
    retrieval = [row for row in per_case if not row.get("expected_abstention")]
    if not retrieval or samples <= 0:
        return {}
    rng = random.Random(seed)
    names = ("recall_at_k", "reciprocal_rank", "ndcg_at_k")
    distributions = {name: [] for name in names}
    for _ in range(samples):
        sample = [rng.choice(retrieval) for _ in retrieval]
        for name in names:
            distributions[name].append(statistics.fmean(float(row[name]) for row in sample))
    aliases = {
        "recall_at_k": f"candidate_recall_at_{k}",
        "reciprocal_rank": f"mrr_at_{k}",
        "ndcg_at_k": f"ndcg_at_{k}",
    }
    return {
        aliases[name]: [
            round(_percentile(values, 0.025), 6),
            round(_percentile(values, 0.975), 6),
        ]
        for name, values in distributions.items()
    }


class RetrieverAdapter:
    """Feature-detect new and legacy LocalLegalRAG-compatible APIs."""

    def __init__(self, engine: Any, *, mode: str = "auto") -> None:
        if mode not in {"auto", "retrieve", "query", "legacy"}:
            raise ValueError("mode must be auto, retrieve, query, or legacy")
        self.engine = engine
        self.mode = mode
        self.method_name = self._select_method()

    def _select_method(self) -> str:
        preferences = {
            "auto": ("retrieve", "query", "legacy_search", "legacy_query"),
            "retrieve": ("retrieve",),
            "query": ("query",),
            "legacy": ("legacy_search", "legacy_query", "query"),
        }[self.mode]
        for name in preferences:
            if callable(getattr(self.engine, name, None)):
                return name
        raise TypeError(f"engine has none of the supported methods: {', '.join(preferences)}")

    @staticmethod
    def _payload_references(payload: Any) -> tuple[Sequence[Any], str, dict[str, Any]]:
        reason = ""
        trace: dict[str, Any] = {}
        if payload is None:
            return (), reason, trace
        if isinstance(payload, Mapping):
            references = payload.get("references", payload.get("results", ()))
            reason = str(payload.get("insufficient_reason", payload.get("reason", "")))
            raw_trace = payload.get("trace", {})
        elif hasattr(payload, "references"):
            references = payload.references
            reason = str(getattr(payload, "insufficient_reason", ""))
            raw_trace = getattr(payload, "trace", {})
        else:
            references = payload
            raw_trace = {}
        if hasattr(raw_trace, "model_dump"):
            raw_trace = raw_trace.model_dump()
        elif hasattr(raw_trace, "__dict__"):
            raw_trace = vars(raw_trace)
        if isinstance(raw_trace, Mapping):
            trace = dict(raw_trace)
        return references or (), reason, trace

    def search(self, case: BenchmarkCase, *, top_k: int) -> dict[str, Any]:
        method = getattr(self.engine, self.method_name)
        signature = inspect.signature(method)
        kwargs: dict[str, Any] = {}
        if "top_k" in signature.parameters:
            kwargs["top_k"] = top_k
        if "context" in signature.parameters:
            kwargs["context"] = case.context
        started = time.perf_counter()
        payload = method(case.query, **kwargs)
        latency_ms = (time.perf_counter() - started) * 1000
        references, reason, trace = self._payload_references(payload)
        ranking: list[str] = []
        items: list[dict[str, Any]] = []
        for reference in references:
            if isinstance(reference, Mapping):
                item = dict(reference)
            elif hasattr(reference, "model_dump"):
                item = dict(reference.model_dump())
            elif hasattr(reference, "__dict__"):
                item = dict(vars(reference))
            else:
                continue
            chunk_id = str(item.get("chunk_id", ""))
            if not chunk_id or chunk_id in ranking:
                continue
            ranking.append(chunk_id)
            items.append(
                {
                    "chunk_id": chunk_id,
                    "document_id": str(item.get("document_id", "")),
                    "document_number": str(item.get("document_number", "")),
                    "section": str(item.get("section", "")),
                    "retrieval_score": item.get("retrieval_score"),
                    "relevance_score": item.get("relevance_score"),
                    "channels": item.get("channels", []),
                }
            )
        return {
            "ranking": ranking[:top_k],
            "references": items[:top_k],
            "latency_ms": round(latency_ms, 3),
            "insufficient_reason": reason,
            "trace": trace,
        }


class BenchmarkHarness:
    def __init__(
        self,
        engine: Any,
        cases: Sequence[BenchmarkCase],
        *,
        mode: str = "auto",
        top_k: int = 10,
        seed: int = 20260722,
        bootstrap_samples: int = 1000,
    ) -> None:
        self.adapter = RetrieverAdapter(engine, mode=mode)
        self.cases = list(cases)
        self.top_k = max(1, int(top_k))
        self.seed = int(seed)
        self.bootstrap_samples = max(0, int(bootstrap_samples))

    def run(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for case in self.cases:
            result = self.adapter.search(case, top_k=self.top_k)
            scores = score_ranking(case, result["ranking"], k=self.top_k)
            rows.append(
                {
                    "case_id": case.case_id,
                    "query": case.query,
                    "split": case.split,
                    "slice": case.slice,
                    "expected_abstention": case.expected_abstention,
                    "exact_citation": case.exact_citation,
                    "gold_relevance": case.relevance,
                    **result,
                    **scores,
                }
            )
        metrics = calculate_metrics(rows, k=self.top_k)
        metrics["confidence_intervals_95"] = bootstrap_confidence_intervals(
            rows, k=self.top_k, seed=self.seed, samples=self.bootstrap_samples
        )
        metrics["by_slice"] = self._by_slice(rows)
        return rows, metrics

    def _by_slice(self, rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for name in sorted({str(row["slice"]) for row in rows}):
            output[name] = calculate_metrics(
                [row for row in rows if row["slice"] == name], k=self.top_k
            )
        return output


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git_state(root: Path) -> dict[str, Any]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=root,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        return {"commit": commit, "dirty": dirty}
    except (OSError, subprocess.SubprocessError):
        return {"commit": "unknown", "dirty": None}


def build_manifest(
    *,
    root: Path,
    dataset_path: Path,
    db_path: Path,
    adapter: RetrieverAdapter,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    engine = adapter.engine
    snapshot: dict[str, Any] = {}
    for owner in (engine, getattr(engine, "retriever", None), getattr(engine, "_retriever", None)):
        candidate = getattr(getattr(owner, "health", None), "snapshot", None)
        if candidate is not None:
            if hasattr(candidate, "model_dump"):
                snapshot = dict(candidate.model_dump())
            elif hasattr(candidate, "__dict__"):
                snapshot = dict(vars(candidate))
            break
    config_json = json.dumps(dict(config), ensure_ascii=False, sort_keys=True).encode("utf-8")
    return {
        "schema_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "git": _git_state(root),
        "corpus": {
            "path": str(db_path.resolve()),
            "sha256": sha256_file(db_path) if db_path.is_file() else "missing",
            **snapshot,
        },
        "benchmark": {
            "path": str(dataset_path.resolve()),
            "sha256": sha256_file(dataset_path),
        },
        "engine": {
            "class": f"{type(engine).__module__}.{type(engine).__qualname__}",
            "api": adapter.method_name,
        },
        "config": dict(config),
        "config_sha256": hashlib.sha256(config_json).hexdigest(),
        "runtime": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
        },
    }


def write_outputs(
    output_dir: str | Path,
    *,
    manifest: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    metrics: Mapping[str, Any],
    gate_report: Mapping[str, Any] | None = None,
) -> Path:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    def dump_json(name: str, payload: Any) -> None:
        (destination / name).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    dump_json("run-manifest.json", manifest)
    dump_json("metrics.json", metrics)
    dump_json(
        "gate-report.json",
        gate_report
        or {
            "schema_version": 1,
            "evaluated": False,
            "passed": None,
            "reason": "baseline_not_configured",
        },
    )
    with (destination / "per-case.jsonl").open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n")
    failures = [
        row
        for row in rows
        if (not row.get("expected_abstention") and not row.get("hit_at_k"))
        or (row.get("expected_abstention") and not row.get("abstention_correct"))
    ]
    with (destination / "failures.jsonl").open("w", encoding="utf-8") as stream:
        for row in failures:
            stream.write(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n")
    k = next((key.rsplit("_", 1)[-1] for key in metrics if key.startswith("mrr_at_")), "k")
    report = (
        "# Legal RAG benchmark report\n\n"
        f"- Engine API: `{manifest['engine']['api']}`\n"
        f"- Cases: {metrics['case_count']}\n"
        f"- Candidate Recall@{k}: {metrics.get('candidate_recall_at_' + k, 0):.3f}\n"
        f"- Hit Rate@{k}: {metrics.get('hit_rate_at_' + k, 0):.3f}\n"
        f"- MRR@{k}: {metrics.get('mrr_at_' + k, 0):.3f}\n"
        f"- nDCG@{k}: {metrics.get('ndcg_at_' + k, 0):.3f}\n"
        f"- Exact citation Top-1: {metrics['exact_citation_top1_accuracy']:.3f}\n"
        f"- Abstention accuracy: {metrics['abstention_accuracy']:.3f}\n"
        f"- Latency p50/p95: {metrics['latency_ms']['p50']:.1f}/{metrics['latency_ms']['p95']:.1f} ms\n"
        f"- Failed cases: {len(failures)}\n"
    )
    (destination / "report.md").write_text(report, encoding="utf-8")
    return destination
