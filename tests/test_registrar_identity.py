from types import SimpleNamespace

from security.risk_core import CriterionStatus, default_config
from security.risk_core.detectors import (
    ScanObservations,
    add_domain_intelligence,
    build_criteria_evidence,
)
from security.risk_core.registrar_identity import assess_registrar_identity


def test_missing_registrar_is_unavailable_not_risky() -> None:
    result = assess_registrar_identity([None, "", None])
    assert result.status == "unavailable"


def test_single_public_registrar_completes_check() -> None:
    result = assess_registrar_identity(["NameCheap, Inc.", None])
    assert result.status == "clean"
    assert result.names == ("NameCheap, Inc.",)


def test_format_variants_are_same_registrar() -> None:
    result = assess_registrar_identity(["NameCheap, Inc.", "NAMECHEAP INC"])
    assert result.status == "clean"


def test_independent_registrar_conflict_is_detected() -> None:
    result = assess_registrar_identity(["NameCheap, Inc.", "Cloudflare Registrar, LLC"])
    assert result.status == "conflict"
    assert len(result.names) == 2


def _domain_intelligence(**overrides):
    values = {
        "available": True,
        "registration_available": True,
        "age_days": 900,
        "expiry_days": 900,
        "certificate_age_days": 300,
        "registrant": None,
        "registrar": "NameCheap, Inc.",
        "registrar_candidates": ("NameCheap, Inc.", "NAMECHEAP INC"),
        "listed": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_criterion_4_uses_real_cross_source_registrar_result() -> None:
    observations = ScanObservations("https://example.test")
    add_domain_intelligence(observations, _domain_intelligence())

    by_id = {
        item.criterion_id: item
        for item in build_criteria_evidence(observations, default_config())
    }
    assert by_id[4].status == CriterionStatus.CLEAN


def test_criterion_4_reports_cross_source_conflict() -> None:
    observations = ScanObservations("https://example.test")
    add_domain_intelligence(
        observations,
        _domain_intelligence(
            registrar_candidates=("NameCheap, Inc.", "Cloudflare Registrar, LLC")
        ),
    )

    by_id = {
        item.criterion_id: item
        for item in build_criteria_evidence(observations, default_config())
    }
    assert by_id[4].status == CriterionStatus.MALICIOUS
    assert by_id[4].finding_type == "registrar_identity_conflict"
