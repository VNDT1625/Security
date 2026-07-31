from security.url_risk_core import collect_url_evidence


def test_multilayer_core_blocks_brand_subdomain_and_credential_lure():
    result = collect_url_evidence("https://facebook.com.security-login-check.xyz/verify?otp=1")

    assert result.requires_deep_analysis is True
    assert {item.feature for item in result.evidence} >= {
        "brand_domain_mismatch", "deceptive_subdomain", "credential_theft_intent",
    }


def test_multilayer_core_marks_shortlink_for_sandbox():
    result = collect_url_evidence("https://bit.ly/account-verify")

    assert result.requires_deep_analysis is True
    assert any(item.feature == "is_shortlink" for item in result.evidence)


def test_multilayer_core_keeps_benign_domain_low_risk():
    result = collect_url_evidence("https://github.com/openai")

    assert result.requires_deep_analysis is False


def test_credential_lure_score_is_monotonic():
    two_terms = collect_url_evidence("https://example.test/login/verify")
    three_terms = collect_url_evidence("https://example.test/login/verify/account")

    assert len(three_terms.evidence) >= len(two_terms.evidence)
    assert any(item.feature == "credential_lure_cluster" for item in three_terms.evidence)


def test_disguised_executable_is_high_risk_and_requires_sandbox():
    result = collect_url_evidence("https://files.example.test/CV-Nguyen.pdf.exe")

    assert result.requires_deep_analysis is True
    assert {item.feature for item in result.evidence} >= {
        "dangerous_download",
        "disguised_executable_download",
    }


def test_shared_hosting_only_scores_when_lure_context_exists():
    benign = collect_url_evidence("https://legitimate-project.pages.dev/docs")
    phishing = collect_url_evidence("https://microsoft-login.pages.dev/account/verify")

    assert not any(item.feature == "shared_hosting_abuse_context" for item in benign.evidence)
    assert any(item.feature == "shared_hosting_abuse_context" for item in phishing.evidence)
