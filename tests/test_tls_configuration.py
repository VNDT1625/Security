from security.risk_core.tls_configuration import (
    TLSConfigurationState,
    evaluate_tls_configuration,
)
from security.risk_core.types import CriterionStatus


def test_modern_negotiated_tls_is_clean():
    result = evaluate_tls_configuration(
        facts={
            "url": "https://example.com/",
            "tls": {
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_128_GCM_SHA256",
            },
        }
    )

    assert result.state is TLSConfigurationState.HEALTHY
    assert result.status is CriterionStatus.CLEAN
    assert result.checked is True
    assert result.is_risk is False


def test_obsolete_enabled_protocol_is_suspicious_even_when_tls13_is_available():
    result = evaluate_tls_configuration(
        facts={"url": "https://example.com/"},
        tls={
            "enabled_protocols": ["TLSv1.0", "TLSv1.2", "TLSv1.3"],
            "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
        },
    )

    assert result.state is TLSConfigurationState.ABNORMAL
    assert result.status is CriterionStatus.SUSPICIOUS
    assert "obsolete_protocol:TLSv1.0" in result.issues
    assert result.evidence_quality == 1.0


def test_ssl3_is_a_high_severity_configuration_finding():
    result = evaluate_tls_configuration(tls={"protocol": "SSLv3"})

    assert result.status is CriterionStatus.SUSPICIOUS
    assert result.severity == 1.0


def test_known_broken_cipher_is_reported_conservatively():
    result = evaluate_tls_configuration(
        tls={
            "protocol": "TLSv1.2",
            "cipher": ("ECDHE-RSA-RC4-SHA", "TLSv1.2", 128),
        }
    )

    assert result.status is CriterionStatus.SUSPICIOUS
    assert result.severity == 0.9
    assert result.ciphers == ("ECDHE-RSA-RC4-SHA",)
    assert "rc4_cipher:ECDHE-RSA-RC4-SHA" in result.issues


def test_modern_aes_cipher_is_not_mistaken_for_single_des():
    result = evaluate_tls_configuration(
        tls={"protocol": "TLSv1.2", "cipher": "ECDHE-RSA-AES128-GCM-SHA256"}
    )

    assert result.status is CriterionStatus.CLEAN
    assert result.issues == ()


def test_insecure_tls_features_are_configuration_findings():
    result = evaluate_tls_configuration(
        tls={
            "protocol": "TLSv1.2",
            "compression_enabled": True,
            "secure_renegotiation": False,
        }
    )

    assert result.status is CriterionStatus.SUSPICIOUS
    assert result.issues == (
        "tls_compression_enabled",
        "secure_renegotiation_disabled",
    )


def test_secure_renegotiation_flag_is_not_applied_to_tls13_only():
    result = evaluate_tls_configuration(
        tls={"protocol": "TLSv1.3", "secure_renegotiation": False}
    )

    assert result.status is CriterionStatus.CLEAN
    assert result.issues == ()


def test_new_certificate_alone_is_not_a_risk_or_a_clean_configuration_result():
    result = evaluate_tls_configuration(
        facts={"url": "https://new.example/"},
        tls={
            "certificate_age_days": 1,
            "issued_at": "2026-07-30T00:00:00Z",
            "issuer": "Example CA",
            "expires_at": "2026-10-30T00:00:00Z",
        },
    )

    assert result.state is TLSConfigurationState.UNAVAILABLE
    assert result.status is CriterionStatus.UNAVAILABLE
    assert result.is_risk is False


def test_missing_configuration_facts_are_unavailable_not_clean():
    result = evaluate_tls_configuration(
        facts={"url": "https://example.com/", "tls": {}},
        unavailable_reason="TLS probe did not return configuration facts.",
    )

    assert result.status is CriterionStatus.UNAVAILABLE
    assert result.summary == "TLS probe did not return configuration facts."


def test_plain_http_is_not_applicable_because_criterion_8_owns_it():
    result = evaluate_tls_configuration(
        facts={"final_url": "http://example.com/", "tls": {}}
    )

    assert result.state is TLSConfigurationState.NOT_APPLICABLE
    assert result.status is CriterionStatus.NOT_APPLICABLE
    assert result.checked is False


def test_explicit_tls_argument_takes_precedence_over_nested_facts():
    result = evaluate_tls_configuration(
        facts={
            "url": "https://example.com/",
            "tls": {"protocol": "TLSv1.0"},
        },
        tls={"protocol": "TLSv1.3"},
    )

    assert result.status is CriterionStatus.CLEAN
    assert result.protocols == ("TLSv1.3",)
