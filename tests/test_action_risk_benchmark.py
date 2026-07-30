from security.risk_core.action_benchmark import (
    ActionBenchmarkObservation,
    benchmark_action_risk,
)


def test_action_benchmark_reports_security_focused_metrics() -> None:
    result = benchmark_action_risk(
        [
            ActionBenchmarkObservation(True, True, 95, 90, "block", 5),
            ActionBenchmarkObservation(True, False, 70, 80, "ask_confirm", 7),
            ActionBenchmarkObservation(False, False, 10, 85, "allow", 3),
            ActionBenchmarkObservation(False, False, 20, 30, "ask_confirm", 4, unknown=True),
        ]
    )
    assert result["critical_recall"] == 1
    assert result["dangerous_recall"] == 1
    assert result["false_positive_rate"] == 0
    assert result["pr_auc"] is not None
    assert result["roc_auc"] is not None
    assert result["unknown_rate"] == 0.25
