"""Run the structured action-risk fixture.

This is an engineering smoke benchmark, not a product accuracy claim.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.risk_core import ActionRiskInput, EvidenceBasedActionRiskEngine
from security.risk_core.action_benchmark import (
    ActionBenchmarkObservation,
    benchmark_action_risk,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fixture",
        default="tests/fixtures/action_risk/structured_cases.json",
    )
    args = parser.parse_args()
    cases = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
    engine = EvidenceBasedActionRiskEngine()
    observations = []
    for index, case in enumerate(cases):
        payload = case["input"]
        started = time.perf_counter()
        result = engine.evaluate(
            ActionRiskInput(
                action_id=str(case.get("id") or index),
                action_type=payload["action_type"],
                target_url=payload.get("target_url"),
                data_types=tuple(payload.get("data_types", [])),
                user_intent=payload.get("user_intent"),
                planned_action=payload.get("planned_action"),
                permission_level=payload.get("permission_level"),
                available_assets=tuple(payload.get("available_assets", [])),
                session_id=payload.get("session_id"),
                workflow_id=payload.get("workflow_id"),
                destination_risk_score=payload.get("destination_risk_score"),
                destination_confidence=payload.get("destination_confidence"),
            )
        )
        observations.append(
            ActionBenchmarkObservation(
                expected_dangerous=bool(case["expected_dangerous"]),
                expected_critical=bool(case["expected_critical"]),
                score=result.danger_score or result.composite_score,
                confidence=result.confidence,
                decision=result.decision.value,
                latency_ms=(time.perf_counter() - started) * 1000,
                unknown=result.risk_level.value == "insufficient_information",
            )
        )
    print(json.dumps(benchmark_action_risk(observations), indent=2))
    print("fixture_only=true")


if __name__ == "__main__":
    main()
