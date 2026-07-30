"""Two-phase deterministic Risk Core v2 orchestration."""

from __future__ import annotations

from .confidence import compute_confidence
from .config import DANGEROUS_CRITERION_IDS, RiskConfig, default_config
from .evidence import resolve_evidence
from .overrides import OverrideRule, evaluate_overrides
from .scoring import score_external, score_internal
from .types import CriterionStatus, EvidenceV2, OverrideResult, RiskResultV2

# Only direct, independently actionable hazards may force an immediate danger
# floor. Contextual or circumstantial criteria remain additive and can still be
# escalated by the explicit multi-signal rules in ``url_overrides.py``.
_IMMEDIATE_DANGER_FINDINGS = frozenset(
    {
        "public_malicious_listing",
        "credential_exfiltration",
        "credential_form_with_external_destination",
        "sensitive_form_with_external_destination",
        "untrusted_sensitive_form_destination",
        "credential_field_with_deception_or_exfiltration",
        "cross_origin_form_action",
        "external_form_action",
        "canary_exfiltration_blocked",
        "private_network_request_blocked",
        "websocket_request_blocked",
        "disguised_executable_download",
        "malicious_javascript_behavior",
    }
)


def _level(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "dangerous"
    if score >= 40:
        return "suspicious"
    if score >= 20:
        return "caution"
    return "low"


def assess(
    evidence: list[EvidenceV2],
    *,
    config: RiskConfig | None = None,
    override_rules: tuple[OverrideRule, ...] = (),
) -> RiskResultV2:
    cfg = config or default_config()
    cfg.validate()
    resolved, conflicts = resolve_evidence(evidence)
    internal, criteria, internal_items = score_internal(resolved, cfg)
    external, awards = score_external(resolved, cfg, {e.evidence_id for e in internal_items})
    base = min(100.0, internal + external)
    overrides, effective = evaluate_overrides(resolved, override_rules)
    immediate_evidence_ids = {
        item.evidence_id
        for item in internal_items
        if item.criterion_id in DANGEROUS_CRITERION_IDS
        and item.status == CriterionStatus.MALICIOUS
        and item.evidence_quality >= 0.75
        and item.adjusted_score > 0
        and item.finding_type in _IMMEDIATE_DANGER_FINDINGS
        and not item.source_id.startswith("web_context:")
    }
    dangerous = sorted(
        (
            item
            for item in criteria
            if item.criterion_id in DANGEROUS_CRITERION_IDS
            and item.status == CriterionStatus.MALICIOUS
            and item.evidence_quality >= 0.75
            and item.adjusted_score > 0
            and bool(immediate_evidence_ids.intersection(item.evidence_ids))
        ),
        key=lambda item: item.criterion_id,
    )
    if dangerous:
        immediate = OverrideResult(
            rule_id="high-confidence-dangerous-criterion-v1",
            floor=60.0,
            minimum_decision="soft_block",
            matched_evidence_ids=tuple(
                sorted(
                    {
                        evidence_id
                        for item in dangerous
                        for evidence_id in item.evidence_ids
                        if evidence_id in immediate_evidence_ids
                    }
                )
            ),
            reason=(
                "At least one high-confidence access-hazard criterion was malicious: "
                + ", ".join(str(item.criterion_id) for item in dangerous)
                + "."
            ),
        )
        overrides.append(immediate)
        overrides.sort(
            key=lambda item: (-item.floor, -len(item.matched_evidence_ids), item.rule_id)
        )
        effective = overrides[0]
    score = max(base, effective.floor if effective else 0.0)
    confidence = compute_confidence(criteria, resolved)
    band = "high" if confidence.score >= 70 else "medium" if confidence.score >= 40 else "low"
    unavailable = [c.criterion_id for c in criteria if c.status.value == "unavailable"]
    not_checked = [c.criterion_id for c in criteria if c.status.value == "not_checked"]
    reasoning = [
        f"Internal evidence contributed {internal:.2f}/80.",
        f"External corroboration contributed {external:.2f}/20.",
    ]
    if effective:
        reasoning.append(f"Override {effective.rule_id} applied floor {effective.floor:.2f}.")
    return RiskResultV2(
        base_risk_score=base,
        risk_score=score,
        risk_level=_level(score),
        confidence_score=confidence.score,
        confidence_band=band,
        internal_score=internal,
        external_corroboration_score=external,
        coverage=confidence.coverage,
        agreement=confidence.agreement,
        freshness=confidence.freshness,
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
    )
