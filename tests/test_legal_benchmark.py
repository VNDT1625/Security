from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from benchmarks.legal_rag.harness import (
    BenchmarkCase,
    BenchmarkHarness,
    GateConfig,
    RetrieverAdapter,
    evaluate_release_gate,
    load_cases,
    reviewed_dataset_status,
    score_ranking,
    write_outputs,
)


@dataclass
class _Reference:
    chunk_id: str

    def model_dump(self) -> dict[str, str]:
        return {"chunk_id": self.chunk_id}


class _QueryEngine:
    def query(self, question: str, *, top_k: int = 4):
        return (_Reference("gold"), _Reference("other"))[:top_k]


class _RetrieveResult:
    def __init__(self) -> None:
        self.references = (_Reference("candidate"), _Reference("gold"))
        self.insufficient_reason = ""
        self.trace = {"mode": "hybrid"}


class _HybridEngine(_QueryEngine):
    def retrieve(self, question: str, *, context=None, top_k: int = 8):
        assert context == {"as_of_date": "2026-07-22"}
        return _RetrieveResult()

    def legacy_query(self, question: str, *, top_k: int = 8):
        return (_Reference("legacy"),)[:top_k]


def _case(**overrides) -> BenchmarkCase:
    values = {
        "case_id": "case-1",
        "query": "question",
        "relevance": {"gold": 3, "secondary": 1},
        "context": {"as_of_date": "2026-07-22"},
    }
    values.update(overrides)
    return BenchmarkCase(**values)


def test_adapter_feature_detects_candidate_and_legacy_apis() -> None:
    hybrid = RetrieverAdapter(_HybridEngine(), mode="auto")
    baseline = RetrieverAdapter(_HybridEngine(), mode="legacy")

    assert hybrid.method_name == "retrieve"
    assert hybrid.search(_case(), top_k=10)["ranking"] == ["candidate", "gold"]
    assert baseline.method_name == "legacy_query"
    assert baseline.search(_case(), top_k=1)["ranking"] == ["legacy"]


def test_graded_ranking_metrics_are_deterministic() -> None:
    case = _case(exact_citation=True)
    scores = score_ranking(case, ["other", "gold", "secondary"], k=3)

    assert scores["recall_at_k"] == 1.0
    assert scores["reciprocal_rank"] == 0.5
    assert scores["exact_top1"] == 0.0
    assert 0.0 < scores["ndcg_at_k"] < 1.0


def test_harness_aggregates_and_writes_reproducible_artifacts(tmp_path: Path) -> None:
    rows, metrics = BenchmarkHarness(
        _QueryEngine(), [_case()], mode="query", top_k=2, bootstrap_samples=20
    ).run()
    assert metrics["candidate_recall_at_2"] == 0.5
    assert metrics["mrr_at_2"] == 1.0
    assert "candidate_recall_at_2" in metrics["confidence_intervals_95"]

    output = write_outputs(
        tmp_path,
        manifest={"engine": {"api": "query"}},
        rows=rows,
        metrics=metrics,
        gate_report={"schema_version": 1, "evaluated": True, "passed": True},
    )
    assert (output / "run-manifest.json").is_file()
    assert (output / "per-case.jsonl").is_file()
    assert (output / "metrics.json").is_file()
    assert (output / "report.md").is_file()
    assert (output / "failures.jsonl").is_file()
    assert json.loads((output / "gate-report.json").read_text())["passed"] is True


def _gate_metrics(
    *,
    recall: float = 0.96,
    mrr: float = 0.90,
    ndcg: float = 0.91,
    abstention: float = 1.0,
    exact: float = 1.0,
    p95: float = 250.0,
) -> dict:
    return {
        "case_count": 100,
        "retrieval_case_count": 80,
        "abstention_case_count": 20,
        "candidate_recall_at_10": recall,
        "mrr_at_10": mrr,
        "ndcg_at_10": ndcg,
        "abstention_accuracy": abstention,
        "exact_citation_top1_accuracy": exact,
        "latency_ms": {"p95": p95},
    }


def test_release_gate_enforces_absolute_regression_latency_and_review() -> None:
    config = GateConfig(
        min_recall=0.90,
        min_mrr=0.80,
        min_ndcg=0.85,
        min_abstention=0.99,
        min_exact_citation=1.0,
        max_regression=0.02,
        max_p95_latency_ms=500,
    )
    baseline = _gate_metrics(recall=0.97, mrr=0.91, ndcg=0.92)
    passing = evaluate_release_gate(
        _gate_metrics(recall=0.96, mrr=0.90, ndcg=0.91),
        baseline,
        top_k=10,
        config=config,
        dataset_status={"production_eligible": True, "reason_codes": []},
    )
    assert passing["passed"] is True
    assert passing["failed_checks"] == []

    failing = evaluate_release_gate(
        _gate_metrics(recall=0.80, p95=900),
        baseline,
        top_k=10,
        config=config,
        dataset_status={
            "production_eligible": False,
            "reason_codes": ["not_adjudicated"],
        },
    )
    assert failing["passed"] is False
    assert "reviewed_dataset_required" in failing["failed_checks"]
    assert "minimum:candidate_recall_at_10" in failing["failed_checks"]
    assert "regression:candidate_recall_at_10" in failing["failed_checks"]
    assert "maximum:latency_ms.p95" in failing["failed_checks"]


def test_public_canary_is_explicitly_not_production_eligible() -> None:
    root = Path(__file__).resolve().parents[1]
    cases = load_cases(root / "benchmarks" / "legal_rag" / "v1" / "canary.jsonl")

    status = reviewed_dataset_status(cases)

    assert status["production_eligible"] is False
    assert any("not_adjudicated" in reason for reason in status["reason_codes"])


def test_reviewer_template_contains_no_fabricated_gold() -> None:
    root = Path(__file__).resolve().parents[1]
    template = root / "benchmarks" / "legal_rag" / "v1" / "reviewer-dataset.template.jsonl"
    row = json.loads(template.read_text(encoding="utf-8").strip())

    assert row["relevance"] == {}
    assert row["annotation"]["status"] == "draft"
    with pytest.raises(ValueError, match="requires relevance"):
        load_cases(template)


def test_cli_release_gate_returns_nonzero_for_nonreviewed_canary(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    db_path = root / "data" / "legal_rag" / "rag.sqlite3"
    if not db_path.is_file():
        pytest.skip("local legal corpus is not installed")
    baseline = _gate_metrics()
    baseline.update(
        {"case_count": 10, "retrieval_case_count": 8, "abstention_case_count": 2}
    )
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    output = tmp_path / "run"

    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "benchmark_legal_rag.py"),
            "--db",
            str(db_path),
            "--baseline-metrics",
            str(baseline_path),
            "--bootstrap-samples",
            "0",
            "--output",
            str(output),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 2, result.stdout + result.stderr
    report = json.loads((output / "gate-report.json").read_text(encoding="utf-8"))
    assert report["evaluated"] is True
    assert report["passed"] is False
    assert "reviewed_dataset_required" in report["failed_checks"]


def test_canary_has_unique_real_corpus_ids() -> None:
    root = Path(__file__).resolve().parents[1]
    dataset = root / "benchmarks" / "legal_rag" / "v1" / "canary.jsonl"
    cases = load_cases(dataset)
    assert len(cases) >= 8

    db_path = root / "data" / "legal_rag" / "rag.sqlite3"
    if not db_path.is_file():
        pytest.skip("local legal corpus is not installed")
    gold_ids = sorted({chunk_id for case in cases for chunk_id in case.relevance})
    with sqlite3.connect(db_path) as connection:
        placeholders = ",".join("?" for _ in gold_ids)
        found = {
            row[0]
            for row in connection.execute(
                f"SELECT chunk_id FROM chunks WHERE chunk_id IN ({placeholders})", gold_ids
            )
        }
    assert found == set(gold_ids)


def test_loader_rejects_unlabelled_non_abstention_case(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text(json.dumps({"case_id": "x", "query": "q"}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="requires relevance"):
        load_cases(path)
