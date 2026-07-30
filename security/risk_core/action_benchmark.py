"""Dataset-agnostic metrics for the action risk engine.

Structured fixtures can exercise this module, but their output must not be
presented as production accuracy without an independently labelled holdout.
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import mean


@dataclass(frozen=True)
class ActionBenchmarkObservation:
    expected_dangerous: bool
    expected_critical: bool
    score: float
    confidence: float
    decision: str
    latency_ms: float
    legacy_decision: str | None = None
    unknown: bool = False


def _roc_auc(labels: list[int], scores: list[float]) -> float | None:
    positive = [score for label, score in zip(labels, scores) if label == 1]
    negative = [score for label, score in zip(labels, scores) if label == 0]
    if not positive or not negative:
        return None
    wins = sum(
        1.0 if pos > neg else 0.5 if pos == neg else 0.0
        for pos in positive
        for neg in negative
    )
    return wins / (len(positive) * len(negative))


def _pr_auc(labels: list[int], scores: list[float]) -> float | None:
    positives = sum(labels)
    if not positives:
        return None
    ranked = sorted(zip(scores, labels), key=lambda item: -item[0])
    previous_recall = 0.0
    area = 0.0
    true_positive = 0
    for rank, (_, label) in enumerate(ranked, start=1):
        true_positive += label
        recall = true_positive / positives
        precision = true_positive / rank
        area += precision * (recall - previous_recall)
        previous_recall = recall
    return area


def _calibration_error(labels: list[int], scores: list[float], bins: int = 10) -> float:
    total = max(1, len(labels))
    error = 0.0
    for index in range(bins):
        lower = index / bins
        upper = (index + 1) / bins
        members = [
            (label, score / 100.0)
            for label, score in zip(labels, scores)
            if lower <= score / 100.0 < upper
            or (index == bins - 1 and score / 100.0 == 1.0)
        ]
        if not members:
            continue
        observed = mean(label for label, _ in members)
        predicted = mean(score for _, score in members)
        error += len(members) / total * abs(observed - predicted)
    return error


def benchmark_action_risk(
    observations: list[ActionBenchmarkObservation],
    *,
    dangerous_threshold: float = 60.0,
) -> dict[str, float | int | None]:
    labels = [int(item.expected_dangerous) for item in observations]
    scores = [item.score for item in observations]
    predicted = [int(score >= dangerous_threshold) for score in scores]
    tp = sum(actual and guess for actual, guess in zip(labels, predicted))
    tn = sum(not actual and not guess for actual, guess in zip(labels, predicted))
    fp = sum(not actual and guess for actual, guess in zip(labels, predicted))
    fn = sum(actual and not guess for actual, guess in zip(labels, predicted))
    critical_total = sum(item.expected_critical for item in observations)
    critical_hits = sum(
        item.expected_critical and item.score >= 85
        for item in observations
    )
    latencies = sorted(item.latency_ms for item in observations)
    p95_index = max(0, min(len(latencies) - 1, int(len(latencies) * 0.95) - 1))
    disagreements = sum(
        bool(item.legacy_decision)
        and item.legacy_decision != item.decision
        for item in observations
    )
    confirmations = sum(
        item.decision in {"ask_confirm", "sandbox", "temporary_block"}
        for item in observations
    )
    return {
        "samples": len(observations),
        "critical_recall": critical_hits / critical_total if critical_total else None,
        "dangerous_recall": tp / (tp + fn) if tp + fn else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "false_negative_rate": fn / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "pr_auc": _pr_auc(labels, scores),
        "roc_auc": _roc_auc(labels, scores),
        "calibration_error": _calibration_error(labels, scores) if observations else None,
        "average_latency_ms": mean(latencies) if latencies else None,
        "p95_latency_ms": latencies[p95_index] if latencies else None,
        "rule_model_disagreement_rate": disagreements / len(observations)
        if observations
        else None,
        "unknown_rate": sum(item.unknown for item in observations) / len(observations)
        if observations
        else None,
        "confirmation_rate": confirmations / len(observations)
        if observations
        else None,
    }
