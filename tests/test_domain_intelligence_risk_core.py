from datetime import UTC, datetime

from security.domain_intelligence import DomainIntelligence, DomainIntelligenceService
from security.risk_core import CriterionStatus, default_config
from security.risk_core.detectors import (
    ScanObservations,
    add_domain_intelligence,
    build_criteria_evidence,
)


def _intel(**overrides):
    values = dict(
        domain="example.test", age_days=20, created_at="2026-01-01",
        registrar="Example Registrar", reputation_status="not_listed",
        reputation_source="urlscan.io", listed=False, score=0.2,
        reasons=(), available=True, expiry_days=10, certificate_age_days=3,
        registration_available=True,
    )
    values.update(overrides)
    return DomainIntelligence(**values)


def test_domain_registration_does_not_guess_tls_configuration():
    obs = ScanObservations("https://example.test")
    add_domain_intelligence(obs, _intel())
    by_id = {e.criterion_id: e for e in build_criteria_evidence(obs, default_config())}
    assert by_id[1].status == CriterionStatus.MALICIOUS
    assert by_id[2].status == CriterionStatus.SUSPICIOUS
    assert by_id[9].status == CriterionStatus.NOT_CHECKED
    assert by_id[3].status == CriterionStatus.NOT_APPLICABLE


def test_missing_expiry_is_not_reported_clean():
    obs = ScanObservations("https://example.test")
    add_domain_intelligence(obs, _intel(expiry_days=None, certificate_age_days=None))
    by_id = {e.criterion_id: e for e in build_criteria_evidence(obs, default_config())}
    assert by_id[2].status == CriterionStatus.UNAVAILABLE
    assert by_id[9].status == CriterionStatus.NOT_CHECKED


def test_certificate_age_is_not_used_as_domain_registration_age(monkeypatch):
    service = DomainIntelligenceService(cache_ttl_seconds=0)
    monkeypatch.setattr(
        service,
        "_query_registration",
        lambda _domain: (None, "whois unavailable", None, "fallback unavailable", None, "rdap unavailable"),
    )
    monkeypatch.setattr(
        service,
        "_query_certificates",
        lambda _domain: ([{"not_before": "2026-01-01T00:00:00Z"}], None),
    )
    monkeypatch.setattr(service, "_query_reputation", lambda _domain: ({"results": []}, None))

    result = service.inspect("example.vn", "https://example.vn")

    assert result.registration_available is False
    assert result.age_days is None
    assert result.created_at is None
    assert result.certificate_age_days == (datetime.now(UTC) - datetime(2026, 1, 1, tzinfo=UTC)).days


def test_registration_unavailable_does_not_emit_clean_domain_age_status():
    obs = ScanObservations("https://example.vn")
    add_domain_intelligence(
        obs,
        _intel(
            age_days=None,
            created_at=None,
            registration_available=False,
            registration_error="WHOIS providers unavailable",
        ),
    )
    by_id = {e.criterion_id: e for e in build_criteria_evidence(obs, default_config())}

    assert by_id[1].status == CriterionStatus.UNAVAILABLE
    assert by_id[1].severity == 0


def test_whoisxml_creation_date_drives_domain_age():
    data = {"registryData": {"createdDateNormalized": "2026-01-01T00:00:00Z"}}
    age_days, created_at = DomainIntelligenceService._whoisxml_age(data)

    assert age_days == (datetime.now(UTC) - datetime(2026, 1, 1, tzinfo=UTC)).days
    assert created_at == "2026-01-01T00:00:00Z"


def test_rdap_expiration_parser():
    rdap = {"events": [{"eventAction": "expiration", "eventDate": "2099-01-01T00:00:00Z"}]}
    assert DomainIntelligenceService._expiry_days(None, None, rdap) > 1000
    assert DomainIntelligenceService._expiry_date(None, None, rdap) == "2099-01-01T00:00:00Z"


def test_rdap_public_registration_fields():
    rdap = {
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Nguyễn Thành Đạt"]]],
            }
        ],
        "nameservers": [
            {"ldhName": "NS-A1.TENTEN.VN."},
            {"ldhName": "ns-a2.tenten.vn"},
        ],
    }
    assert DomainIntelligenceService._rdap_entity_name(rdap, "registrant") == "Nguyễn Thành Đạt"
    assert DomainIntelligenceService._registration_nameservers(None, None, rdap) == (
        "ns-a1.tenten.vn",
        "ns-a2.tenten.vn",
    )


def test_rdap_redacted_registrant_is_not_presented_as_owner():
    rdap = {
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]],
            }
        ]
    }
    assert DomainIntelligenceService._rdap_entity_name(rdap, "registrant") is None


def test_rdap_public_registrant_phone_is_extracted_without_guessing():
    rdap = {
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["tel", {"type": "voice"}, "uri", "tel:+84901234567"]],
                ],
            }
        ]
    }
    assert DomainIntelligenceService._rdap_entity_phone(rdap, "registrant") == "+84901234567"
