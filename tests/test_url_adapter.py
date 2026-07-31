"""URL adapter unit tests (test-plan.md §2.1)."""

import pytest

from ai.adapters.url_adapter import (
    FEATURE_NAMES,
    analyze_url_signals,
    extract_enriched_url_features,
    extract_url_feature_map,
    extract_url_features,
    has_homoglyph,
    is_ip_host,
    parse_url_parts,
)
from security.url_risk_core import collect_url_evidence


def test_extract_features_valid_url():
    f = extract_url_features("https://github.com/user/repo")
    assert len(f) == 15
    assert f[8] == 1.0  # has_https


def test_enriched_feature_vector_has_shared_54_plus_schema():
    values = extract_enriched_url_features(
        "https://paypal.example.test/login?redirect=https%3A%2F%2Fpaypal.com",
        context={
            "dns_available": 1,
            "dns_resolves": 1,
            "domain_age_days": 5,
            "tls_available": 1,
            "tls_present": 1,
            "redirect_available": 1,
            "redirect_count": 2,
            "local_feed_checked": 1,
        },
    )
    feature_map = extract_url_feature_map("http://192.168.1.1/login")

    assert len(FEATURE_NAMES) >= 54
    assert len(values) == len(FEATURE_NAMES)
    assert values[FEATURE_NAMES.index("brand_mismatch")] == 1.0
    assert values[FEATURE_NAMES.index("dns_available")] == 1.0
    assert feature_map["has_ip_address"] == 1.0


def test_extract_features_malformed_url():
    with pytest.raises(ValueError):
        extract_url_features("")


def test_homoglyph_detection():
    assert has_homoglyph("http://vietc0mbank-secure.xyz/login") is True
    assert has_homoglyph("https://github.com") is False


def test_ip_based_url():
    assert is_ip_host("http://192.168.1.1/login") is True
    f = extract_url_features("http://192.168.1.1/login")
    assert f[4] == 1.0


def test_risky_tld():
    f = extract_url_features("http://phish.xyz/login")
    assert f[3] == 1.0
    assert f[14] == 1.0  # suspicious keyword 'login'


def test_parse_real_domain_with_vietnamese_public_suffix():
    parts = parse_url_parts("https://vietcombank.com.vn/login")
    assert parts.domain_label == "vietcombank"
    assert parts.registrable_domain == "vietcombank.com.vn"


@pytest.mark.parametrize(
    ("url", "domain_label", "registrable_domain"),
    [
        ("https://auth.paypal.co.uk/login", "paypal", "paypal.co.uk"),
        (
            "https://paypal-login.github.io/verify",
            "paypal-login",
            "paypal-login.github.io",
        ),
        ("https://shop.example.com.au", "example", "example.com.au"),
    ],
)
def test_parse_registrable_domain_with_multi_part_and_tenant_suffixes(
    url, domain_label, registrable_domain
):
    parts = parse_url_parts(url)

    assert parts.domain_label == domain_label
    assert parts.registrable_domain == registrable_domain


def test_deceptive_brand_in_subdomain():
    signals = analyze_url_signals("https://facebook.com.security-login-check.xyz/verify")
    assert signals.parts.registrable_domain == "security-login-check.xyz"
    assert signals.brand_mentions == ("facebook",)
    assert signals.brand_mismatch is True
    assert signals.brand_in_subdomain is True
    assert signals.deceptive_subdomain is True
    assert set(("security", "login", "verify")).issubset(signals.suspicious_keywords)


@pytest.mark.parametrize(
    "url",
    [
        "https://login.paypal.com/account",
        "https://support.vietcombank.com.vn/",
        "https://account.microsoftonline.com/",
        "https://apple.com/",
    ],
)
def test_official_brand_domains_are_not_mismatches(url):
    signals = analyze_url_signals(url)

    assert signals.brand_mismatch is False


@pytest.mark.parametrize(
    "url",
    [
        "https://pineapple.com/",
        "https://googleapis.com/",
        "https://amazonaws.com/",
        "https://münchen.de/",
    ],
)
def test_unrelated_substrings_and_legitimate_idn_are_not_brand_spoofs(url):
    signals = analyze_url_signals(url)

    assert signals.brand_mismatch is False
    assert signals.homoglyph is False


@pytest.mark.parametrize(
    "url",
    [
        "https://xn--l-7sba6dbr.com/login",
        "https://xn--ggle-55da.com/verify",
        "https://vietc0mbank-secure.xyz/login",
    ],
)
def test_unicode_punycode_and_digit_homoglyphs_trigger_brand_spoof(url):
    signals = analyze_url_signals(url)

    assert signals.brand_mismatch is True
    assert signals.homoglyph is True


def test_typo_brand_on_wrong_domain_is_detected():
    result = collect_url_evidence("https://paypa.com/login")

    assert any(item.feature == "brand_typosquatting" for item in result.evidence)


def test_disguised_executable_and_archive_lure_signals():
    executable = analyze_url_signals("https://files.example.test/CV-Nguyen.pdf.exe")
    archive = analyze_url_signals("https://files.example.test/invoice.pdf.zip")

    assert executable.dangerous_download is True
    assert executable.disguised_download is True
    assert archive.archive_lure is True


def test_shared_hosting_is_context_not_a_verdict():
    signals = analyze_url_signals("https://legitimate-project.pages.dev/docs")

    assert signals.shared_hosting is True
    assert signals.brand_mismatch is False
    assert signals.suspicious_keywords == ()
