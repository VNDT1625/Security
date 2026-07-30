from security.risk_core import (
    CriterionStatus,
    ScanObservations,
    build_criteria_evidence,
    default_config,
)
from security.risk_core.detectors import add_structured_snapshot
from security.risk_core.owner_identity import assess_owner_identity


def test_redacted_whois_is_not_risk():
    result = assess_owner_identity(
        "REDACTED FOR PRIVACY",
        structured_legal_names=["Acme Technology Company Limited"],
    )

    assert result.status == "not_applicable"
    assert result.conflict is False
    assert result.public_registrant is None
    assert result.as_risk_snapshot()["domain_owner"]["status"] == "not_applicable"


def test_privacy_proxy_is_not_treated_as_owner_conflict():
    result = assess_owner_identity(
        "Domains By Proxy, LLC",
        page_legal_names=["Acme Technology Company Limited"],
    )

    assert result.status == "not_applicable"
    assert result.evidence[0].severity == 0


def test_missing_website_legal_identity_is_not_reported_clean():
    result = assess_owner_identity("Acme Technology Company Limited")

    assert result.status == "not_checked"
    assert result.confidence == 0


def test_matching_public_owner_handles_accents_and_legal_suffixes():
    result = assess_owner_identity(
        "CÔNG TY TNHH CÔNG NGHỆ ÁNH DƯƠNG",
        structured_legal_names=["Cong ty Cong nghe Anh Duong Ltd."],
    )

    assert result.status == "clean"
    assert result.matched_legal_name == "Cong ty Cong nghe Anh Duong Ltd."
    assert result.confidence == 0.9


def test_matching_owner_recognizes_organization_acronym():
    result = assess_owner_identity(
        "International Business Machines Corporation",
        structured_legal_names=["IBM Corp."],
    )

    assert result.status == "clean"


def test_public_organizational_owner_conflict_emits_integrable_evidence():
    result = assess_owner_identity(
        "Northwind Trading Company Limited",
        page_legal_names=["Contoso Retail Corporation"],
        structured_legal_names=["Contoso Retail Ltd."],
    )

    assert result.status == "suspicious"
    assert result.conflict is True
    assert result.confidence == 0.88
    assert result.evidence[0].finding_type == "owner_identity_conflict"
    assert result.evidence[0].severity == 0.65
    snapshot = result.as_risk_snapshot()["domain_owner"]
    assert snapshot["status"] == "suspicious"
    assert snapshot["source"] == "cross_source_identity"
    assert snapshot["metadata"]["comparison"] == "normalized_legal_identity_mismatch"


def test_incompatible_page_identities_make_comparison_inconclusive():
    result = assess_owner_identity(
        "Northwind Trading Company Limited",
        page_legal_names=[
            "Contoso Retail Corporation",
            "Fabrikam Manufacturing Limited",
        ],
    )

    assert result.status == "not_checked"
    assert result.conflict is False


def test_one_matching_and_one_incompatible_page_identity_is_inconclusive():
    result = assess_owner_identity(
        "Northwind Trading Company Limited",
        page_legal_names=[
            "Northwind Trading Ltd.",
            "Fabrikam Manufacturing Limited",
        ],
    )

    assert result.status == "not_checked"


def test_individual_registrant_is_not_accused_of_business_identity_conflict():
    result = assess_owner_identity(
        "Nguyen Thanh Dat",
        structured_legal_names=["Contoso Retail Corporation"],
    )

    assert result.status == "not_checked"
    assert result.conflict is False


def test_conflict_snapshot_is_consumed_by_risk_core():
    result = assess_owner_identity(
        "Northwind Trading Company Limited",
        structured_legal_names=["Contoso Retail Corporation"],
    )
    observations = ScanObservations("https://contoso.example")

    add_structured_snapshot(observations, result.as_risk_snapshot())
    by_id = {
        item.criterion_id: item
        for item in build_criteria_evidence(observations, default_config())
    }

    assert by_id[3].status == CriterionStatus.SUSPICIOUS
    assert by_id[3].evidence_quality == 0.88
