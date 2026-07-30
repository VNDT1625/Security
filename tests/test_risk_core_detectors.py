from security.risk_core import (
    CriterionStatus,
    ScanObservations,
    add_structured_observations,
    build_criteria_evidence,
    default_config,
    mark_context_applicability,
)
from security.risk_core.detectors import add_offline_url_findings
from security.url_risk_core import assess_url


def test_structured_registry_can_activate_every_adapter_driven_criterion():
    obs = ScanObservations("https://example.test")
    # Keys are the explicit adapter contract; this verifies no declared detector is dead code.
    values = {
        "domain_lifecycle_abnormal": True,
        "owner_identity_conflict": True,
        "registrar_abuse_rate_high": True,
        "tls_configuration_abnormal": True,
        "certificate_invalid": True,
        "domain_reputation_low": True,
        "ip_reputation_low": True,
        "server_location_conflict": True,
        "malicious_hosting_density": True,
        "brand_content_impersonation": True,
        "contact_information_invalid": True,
        "business_email_mismatch": True,
        "business_address_invalid": True,
        "legal_identity_conflict": True,
        "privacy_policy_missing": True,
        "terms_refund_missing": True,
        "content_identity_conflict": True,
        "price_outlier": True,
        "coercive_content": True,
        "sensitive_data_request": True,
        "untrusted_sensitive_form": True,
        "irreversible_payment_risk": True,
        "payee_identity_mismatch": True,
        "unnecessary_browser_permission": True,
        "dangerous_download": True,
        "malicious_javascript_behavior": True,
        "risky_third_party_script": True,
        "deceptive_popup": True,
        "malvertising_behavior": True,
        "impersonating_copied_content": True,
        "forged_image_asset": True,
        "social_identity_conflict": True,
        "historical_abuse": True,
        "abrupt_content_repurpose": True,
        "abnormal_dns_churn": True,
        "email_security_conflict": True,
        "brand_metadata_mismatch": True,
        "support_channel_invalid": True,
        "verified_user_complaints": True,
        "review_manipulation": True,
    }
    add_structured_observations(obs, values)
    evidence = build_criteria_evidence(obs, default_config())
    active = {item.criterion_id for item in evidence if item.status in {
        CriterionStatus.SUSPICIOUS, CriterionStatus.MALICIOUS
    }}
    assert active == set(range(1, 50)) - {1, 5, 6, 7, 8, 11, 16, 17, 18}


def test_explicit_false_is_clean_but_absent_is_not_checked():
    obs = ScanObservations("https://example.test")
    add_structured_observations(obs, {"domain_lifecycle_abnormal": False})
    by_id = {item.criterion_id: item for item in build_criteria_evidence(obs, default_config())}
    assert by_id[2].status == CriterionStatus.CLEAN
    assert by_id[3].status == CriterionStatus.NOT_CHECKED


def test_applicability_requires_explicit_context_evidence():
    obs = ScanObservations("https://example.test")
    mark_context_applicability(obs, commercial=False, uses_business_email=False)
    by_id = {item.criterion_id: item for item in build_criteria_evidence(obs, default_config())}
    for cid in (20, 21, 22, 23, 24, 25, 45, 47):
        assert by_id[cid].status == CriterionStatus.NOT_APPLICABLE
        assert by_id[cid].applicability_evidence_ids


def test_new_offline_download_and_shared_platform_signals_reach_v2_criteria():
    url = "https://microsoft-login.pages.dev/account/verify/CV.pdf.exe"
    obs = ScanObservations(url)
    add_offline_url_findings(obs, assess_url(url).evidence)
    evidence = build_criteria_evidence(obs, default_config())
    active = {
        item.criterion_id
        for item in evidence
        if item.status in {CriterionStatus.SUSPICIOUS, CriterionStatus.MALICIOUS}
    }

    # A deceptive pages.dev tenant is a subdomain/identity signal. Criterion 15
    # is reserved for reverse-IP evidence about other malicious hosted domains.
    assert {5, 7, 29, 34}.issubset(active)
    assert 15 not in active
