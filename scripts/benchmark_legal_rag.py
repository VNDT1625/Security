"""Run the versioned Legal RAG retrieval benchmark."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.legal_rag.harness import (  # noqa: E402
    BenchmarkHarness,
    GateConfig,
    build_manifest,
    evaluate_release_gate,
    load_cases,
    load_metrics,
    reviewed_dataset_status,
    sha256_file,
    write_outputs,
)
from security.legal_rag import LocalLegalRAG  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=ROOT / "benchmarks" / "legal_rag" / "v1" / "canary.jsonl",
    )
    parser.add_argument("--db", type=Path, default=ROOT / "data" / "legal_rag" / "rag.sqlite3")
    parser.add_argument("--split", default=None)
    parser.add_argument("--mode", choices=("auto", "retrieve", "query", "legacy"), default="auto")
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20260722)
    parser.add_argument("--bootstrap-samples", type=int, default=1000)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--baseline-metrics",
        type=Path,
        default=None,
        help="Frozen metrics.json from the same reviewed dataset and top-k.",
    )
    parser.add_argument("--min-recall", type=float, default=0.98)
    parser.add_argument("--min-mrr", type=float, default=0.80)
    parser.add_argument("--min-ndcg", type=float, default=0.85)
    parser.add_argument("--min-abstention", type=float, default=0.99)
    parser.add_argument("--min-exact-citation", type=float, default=1.0)
    parser.add_argument("--max-regression", type=float, default=0.02)
    parser.add_argument("--max-p95-latency-ms", type=float, default=2_000.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cases = load_cases(args.dataset, split=args.split)
    engine = LocalLegalRAG(args.db, top_k=min(8, max(1, args.top_k)))
    harness = BenchmarkHarness(
        engine,
        cases,
        mode=args.mode,
        top_k=args.top_k,
        seed=args.seed,
        bootstrap_samples=args.bootstrap_samples,
    )
    rows, metrics = harness.run()
    gate_config = GateConfig(
        min_recall=args.min_recall,
        min_mrr=args.min_mrr,
        min_ndcg=args.min_ndcg,
        min_abstention=args.min_abstention,
        min_exact_citation=args.min_exact_citation,
        max_regression=args.max_regression,
        max_p95_latency_ms=args.max_p95_latency_ms,
    )
    dataset_status = reviewed_dataset_status(cases)
    gate_report: dict[str, object]
    if args.baseline_metrics is not None:
        baseline = load_metrics(args.baseline_metrics)
        gate_report = evaluate_release_gate(
            metrics,
            baseline,
            top_k=args.top_k,
            config=gate_config,
            dataset_status=dataset_status,
            baseline_path=str(args.baseline_metrics.resolve()),
            baseline_sha256=sha256_file(args.baseline_metrics),
        )
    else:
        gate_report = {
            "schema_version": 1,
            "evaluated": False,
            "passed": None,
            "reason": "baseline_not_configured",
            "production_eligible": dataset_status["production_eligible"],
            "dataset_review": dataset_status,
        }
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + f"-{harness.adapter.method_name}"
    output = args.output or ROOT / "outputs" / "legal-rag-benchmark" / run_id
    config = {
        "mode": args.mode,
        "selected_api": harness.adapter.method_name,
        "top_k": args.top_k,
        "seed": args.seed,
        "bootstrap_samples": args.bootstrap_samples,
        "split": args.split,
        "baseline_metrics": (
            str(args.baseline_metrics.resolve()) if args.baseline_metrics else None
        ),
        "gate": gate_config.model_dump(),
    }
    manifest = build_manifest(
        root=ROOT,
        dataset_path=args.dataset,
        db_path=args.db,
        adapter=harness.adapter,
        config=config,
    )
    write_outputs(
        output,
        manifest=manifest,
        rows=rows,
        metrics=metrics,
        gate_report=gate_report,
    )
    print(f"Legal RAG benchmark: {output}")
    print(
        f"Recall@{args.top_k}={metrics[f'candidate_recall_at_{args.top_k}']:.3f} "
        f"MRR@{args.top_k}={metrics[f'mrr_at_{args.top_k}']:.3f} "
        f"nDCG@{args.top_k}={metrics[f'ndcg_at_{args.top_k}']:.3f}"
    )
    if gate_report.get("evaluated"):
        print("Release gate: " + ("PASS" if gate_report.get("passed") else "FAIL"))
        return 0 if gate_report.get("passed") else 2
    print("Release gate: NOT EVALUATED (no frozen baseline supplied)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
