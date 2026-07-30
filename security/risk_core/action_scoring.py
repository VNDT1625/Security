"""Direct floors, bounded composite score and independent confidence."""

from __future__ import annotations

from collections import defaultdict

from .action_config import ActionRiskConfig
from .action_types import (
    DirectEvidenceResult,
    EvidenceGroup,
    LightGBMRiskResult,
    SecurityEvidence,
    SessionRiskResult,
)


def _soft_or(scores: list[float]) -> float:
    remainder = 1.0
    for score in scores:
        remainder *= 1.0 - max(0.0, min(100.0, score)) / 100.0
    return 100.0 * (1.0 - remainder)


def evaluate_direct_evidence(
    evidence: list[SecurityEvidence],
    config: ActionRiskConfig,
) -> DirectEvidenceResult:
    matches: list[tuple[float, str, str]] = []
    for item in evidence:
        kind = str(item.metadata.get("direct_kind", ""))
        confirmed = item.metadata.get("confirmed") is True
        floor = config.direct_floors.get(kind)
        if (
            item.direct
            and confirmed
            and floor is not None
            and item.reliability >= 0.90
        ):
            matches.append((floor, kind, item.id))
    if not matches:
        return DirectEvidenceResult(0.0)
    matches.sort(key=lambda value: (-value[0], value[1], value[2]))
    return DirectEvidenceResult(
        floor=matches[0][0],
        kinds=tuple(sorted({item[1] for item in matches})),
        evidence_ids=tuple(sorted({item[2] for item in matches})),
    )


def score_composite(
    groups: list[EvidenceGroup],
    config: ActionRiskConfig,
    *,
    ml: LightGBMRiskResult | None = None,
    session: SessionRiskResult | None = None,
) -> tuple[float, dict[str, float]]:
    """Aggregate independent categories nonlinearly after event deduplication."""
    by_category: dict[str, list[float]] = defaultdict(list)
    category_kind = {}
    for group in groups:
        by_category[group.category.value].append(group.score)
        category_kind[group.category.value] = group.category
    category_scores = {
        name: _soft_or(values)
        for name, values in sorted(by_category.items())
    }
    weighted = [
        score * config.category_weights[category_kind[name]]
        for name, score in category_scores.items()
    ]
    rule_score = _soft_or(weighted)
    additions: list[float] = [rule_score]
    if ml and ml.available and ml.risk_contribution > 0:
        additions.append(min(config.ml_max_contribution, ml.risk_contribution))
    if session and session.contribution > 0:
        additions.append(min(config.session_max_contribution, session.contribution))
    return round(_soft_or(additions), 4), {
        name: round(score, 4) for name, score in category_scores.items()
    }


def compute_action_confidence(
    evidence: list[SecurityEvidence],
    groups: list[EvidenceGroup],
    *,
    missing_fields: list[str],
    total_expected_fields: int,
    ml: LightGBMRiskResult,
    direct: DirectEvidenceResult,
) -> float:
    """Compute confidence separately; it never scales the danger score."""
    completeness = max(
        0.0,
        1.0 - len(set(missing_fields)) / max(1, total_expected_fields),
    )
    sources = {item.source.value for item in evidence if item.reliability > 0}
    source_diversity = min(1.0, len(sources) / 3.0)
    reliability = (
        sum(item.reliability for item in evidence) / len(evidence)
        if evidence
        else 0.0
    )
    independent_categories = len({group.category for group in groups})
    independence = min(1.0, independent_categories / 4.0)
    if ml.available and ml.risk_probability is not None:
        rule_direction = max((group.score for group in groups), default=0.0) / 100.0
        model_direction = ml.risk_probability
        agreement = 1.0 - min(1.0, abs(rule_direction - model_direction))
    else:
        # Absence of an optional model is explicit, not a clean signal.
        agreement = 0.50
    ood_factor = 0.55 if ml.out_of_distribution else 1.0
    score = 100.0 * (
        0.38 * completeness
        + 0.25 * reliability
        + 0.17 * source_diversity
        + 0.12 * independence
        + 0.08 * agreement
    ) * ood_factor
    if direct.floor > 0:
        score = max(score, 70.0)
    return round(max(0.0, min(100.0, score)), 4)
