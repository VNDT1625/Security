"""URL orchestration through the shared evidence-based risk pipeline."""

from __future__ import annotations

from .action_config import ActionRiskConfig, default_action_risk_config
from .action_lightgbm import LightGBMRiskAdapter
from .config import RiskConfig, default_config
from .confidence import compute_confidence
from .evidence import resolve_evidence
from .overrides import OverrideRule, evaluate_overrides
from .scoring import score_external, score_internal
from .types import EvidenceV2, RiskResultV2
from .unified_url_evidence import evaluate_url_evidence


def _level(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "dangerous"
    if score >= 35:
        return "suspicious"
    return "low"


def assess(
    evidence: list[EvidenceV2],
    *,
    config: RiskConfig | None = None,
    override_rules: tuple[OverrideRule, ...] = (),
    action_config: ActionRiskConfig | None = None,
    lightgbm: LightGBMRiskAdapter | None = None,
) -> RiskResultV2:
    """Assess URL evidence without a second weighted scoring core.

    ``score_internal`` and ``score_external`` below only preserve the old trace
    fields for clients that display the 50 criteria.  The returned risk score is
    solely the shared direct-floor/composite pipeline.
    """
    cfg = config or default_config()
    cfg.validate()
    resolved, conflicts = resolve_evidence(evidence)
    shared = evaluate_url_evidence(
        resolved,
        action_config=action_config or default_action_risk_config(),
        lightgbm=lightgbm,
        criterion_max_weights={item.criterion_id: item.max_weight for item in cfg.criteria},
    )

    # Compatibility projection; never use these values for final risk.
    internal, criteria, internal_items = score_internal(resolved, cfg)
    external, awards = score_external(resolved, cfg, {item.evidence_id for item in internal_items})
    legacy_confidence = compute_confidence(criteria, resolved)

    overrides, effective = evaluate_overrides(resolved, override_rules)
    score = max(
        shared.direct.floor,
        shared.composite_score,
        effective.floor if effective else 0.0,
    )
    confidence = shared.confidence
    band = "high" if confidence >= 70 else "medium" if confidence >= 40 else "low"
    unavailable = [item.criterion_id for item in criteria if item.status.value == "unavailable"]
    not_checked = [item.criterion_id for item in criteria if item.status.value == "not_checked"]
    reasoning = [
        "All URL criteria were normalized into the shared evidence pipeline.",
        f"Deduplicated composite evidence contributed {shared.composite_score:.2f}/100.",
    ]
    if shared.direct.floor:
        reasoning.append(f"Confirmed direct evidence applied floor {shared.direct.floor:.2f}.")
    if effective:
        reasoning.append(f"Override {effective.rule_id} applied floor {effective.floor:.2f}.")

    category_scores = {
        category.value: round(
            max(item.score for item in shared.groups if item.category == category), 4
        )
        for category in {item.category for item in shared.groups}
    }
    return RiskResultV2(
        base_risk_score=shared.composite_score,
        risk_score=score,
        risk_level=_level(score),
        confidence_score=confidence,
        confidence_band=band,
        internal_score=internal,
        external_corroboration_score=external,
        # Existing clients still receive their old coverage components.  They do
        # not influence the new score or direct-evidence policy.
        coverage=legacy_confidence.coverage,
        agreement=legacy_confidence.agreement,
        freshness=legacy_confidence.freshness,
        criteria=criteria,
        evidence=resolved,
        external_sources=awards,
        overrides=overrides,
        effective_override=effective,
        conflicts=conflicts,
        rules_version=cfg.rules_version,
        weights_version=cfg.weights_version,
        unavailable_checks=unavailable,
        not_checked_checks=not_checked,
        reasoning=reasoning,
        direct_floor=shared.direct.floor,
        composite_score=shared.composite_score,
        rule_score=shared.rule_score,
        ml_contribution=shared.ml.risk_contribution,
        ml_model_version=shared.ml.model_version,
        missing_fields=shared.missing_fields,
        unified_evidence_groups=category_scores,
        deduplicated_evidence_count=len(shared.after_dedup),
        reason_codes=sorted(
            {item.reason_code for item in shared.after_dedup if item.reason_code}
        ),
    )
