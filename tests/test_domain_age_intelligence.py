from datetime import UTC, datetime, timedelta

from security.domain_intelligence import DomainIntelligenceService


def test_registration_falls_back_when_whoisxml_record_has_no_creation_date(monkeypatch):
    service = DomainIntelligenceService()
    calls: list[str] = []

    monkeypatch.setattr(
        service,
        "_query_whoisxml",
        lambda _domain: ({"registrarName": "Partial Registrar"}, None),
    )

    def ip2whois(_domain):
        calls.append("ip2whois")
        return {"create_date": "2020-01-02T00:00:00Z"}, None

    def rdap(_domain):
        calls.append("rdap")
        return None, "must not be queried"

    monkeypatch.setattr(service, "_query_ip2whois", ip2whois)
    monkeypatch.setattr(service, "_query_rdap", rdap)

    whoisxml, whoisxml_error, whois, _, rdap_result, _ = service._query_registration(
        "example.com"
    )

    assert whoisxml == {"registrarName": "Partial Registrar"}
    assert whoisxml_error == "WhoisXML thiếu ngày đăng ký hợp lệ"
    assert whois == {"create_date": "2020-01-02T00:00:00Z"}
    assert rdap_result is None
    assert calls == ["ip2whois"]


def test_registration_falls_back_to_rdap_until_creation_date_is_available(monkeypatch):
    service = DomainIntelligenceService()
    monkeypatch.setattr(
        service,
        "_query_whoisxml",
        lambda _domain: ({"createdDate": "not-a-date"}, None),
    )
    monkeypatch.setattr(
        service,
        "_query_ip2whois",
        lambda _domain: ({"registrar": "Partial IP2WHOIS"}, None),
    )
    monkeypatch.setattr(
        service,
        "_query_rdap",
        lambda _domain: (
            {
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": "2021-02-03T00:00:00Z",
                    }
                ]
            },
            None,
        ),
    )

    registration = service._query_registration("example.com")
    age_days, created_at, source = service._registration_age(
        registration[0], registration[2], registration[4]
    )

    assert age_days == (
        datetime.now(UTC) - datetime(2021, 2, 3, tzinfo=UTC)
    ).days
    assert created_at == "2021-02-03T00:00:00Z"
    assert source == "RDAP"


def test_invalid_primary_date_does_not_hide_valid_secondary_date():
    age_days, created_at = DomainIntelligenceService._whoisxml_age(
        {
            "registryData": {"createdDateNormalized": "invalid"},
            "createdDate": "2022-03-04T00:00:00Z",
        }
    )

    assert age_days == (
        datetime.now(UTC) - datetime(2022, 3, 4, tzinfo=UTC)
    ).days
    assert created_at == "2022-03-04T00:00:00Z"


def test_rdap_skips_invalid_registration_event_and_uses_next_valid_event():
    age_days, created_at = DomainIntelligenceService._domain_age(
        {
            "events": [
                {"eventAction": "registration", "eventDate": "invalid"},
                {
                    "eventAction": "Registration",
                    "eventDate": "2023-04-05T00:00:00Z",
                },
            ]
        }
    )

    assert age_days == (
        datetime.now(UTC) - datetime(2023, 4, 5, tzinfo=UTC)
    ).days
    assert created_at == "2023-04-05T00:00:00Z"


def test_future_creation_date_is_unavailable_instead_of_zero_days_old():
    future = (datetime.now(UTC) + timedelta(days=30)).isoformat()

    assert DomainIntelligenceService._whoisxml_age(
        {"createdDateNormalized": future}
    ) == (None, None)
    assert DomainIntelligenceService._ip2whois_age(
        {"create_date": future}
    ) == (None, None)
    assert DomainIntelligenceService._domain_age(
        {
            "events": [
                {"eventAction": "registration", "eventDate": future},
            ]
        }
    ) == (None, None)


def test_no_provider_creation_date_stays_explicitly_unavailable(monkeypatch):
    service = DomainIntelligenceService(cache_ttl_seconds=0)
    monkeypatch.setattr(
        service,
        "_query_registration",
        lambda _domain: (
            {"registrarName": "Partial record"},
            "WhoisXML thiếu ngày đăng ký hợp lệ",
            None,
            "IP2WHOIS_API_KEY chưa cấu hình",
            {"events": []},
            "RDAP thiếu ngày đăng ký hợp lệ",
        ),
    )
    monkeypatch.setattr(service, "_query_certificates", lambda _domain: ([], None))
    monkeypatch.setattr(
        service, "_query_reputation", lambda _domain: ({"results": []}, None)
    )

    result = service.inspect("example.com", "https://example.com")

    assert result.age_days is None
    assert result.created_at is None
    assert result.registration_available is True
    assert result.registration_error == (
        "WhoisXML thiếu ngày đăng ký hợp lệ; "
        "IP2WHOIS_API_KEY chưa cấu hình; "
        "RDAP thiếu ngày đăng ký hợp lệ"
    )
