"""Live domain-age and public reputation intelligence for URL assessment.

Only fixed, HTTPS intelligence providers are contacted. Results are cached to avoid
repeated third-party requests and failures degrade to an explicit unavailable state.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urljoin

import httpx

from backend.config import settings


@dataclass(frozen=True)
class DomainIntelligence:
    domain: str
    age_days: int | None
    created_at: str | None
    registrar: str | None
    reputation_status: str
    reputation_source: str
    listed: bool | None
    score: float
    reasons: tuple[str, ...]
    available: bool
    registrar_candidates: tuple[str, ...] = ()
    expiry_days: int | None = None
    certificate_age_days: int | None = None
    expires_at: str | None = None
    updated_at: str | None = None
    registrant: str | None = None
    registrant_phone: str | None = None
    registration_nameservers: tuple[str, ...] = ()
    registration_statuses: tuple[str, ...] = ()
    registration_source: str = "RDAP"
    registration_available: bool = False
    registration_error: str | None = None
    reputation_ips: tuple[str, ...] = ()
    malicious_ips: tuple[str, ...] = ()
    malicious_observations: int = 0
    shared_hosting_available: bool = False
    shared_malicious_domains: tuple[str, ...] = ()
    shared_malicious_observations: int = 0


class DomainIntelligenceService:
    """Query RDAP for age and URLhaus for public malicious-URL reputation."""

    def __init__(self, timeout_seconds: float = 4.0, cache_ttl_seconds: int = 3600) -> None:
        self.timeout_seconds = timeout_seconds
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[tuple[str, str], tuple[float, DomainIntelligence]] = {}
        self._lock = threading.Lock()
        self._rdap_bootstrap: tuple[float, dict[str, str]] | None = None
        self._rdap_lock = threading.Lock()

    def inspect(self, domain: str, url: str) -> DomainIntelligence:
        key = (domain.lower(), url)
        with self._lock:
            cached = self._cache.get(key)
            if cached and time.monotonic() - cached[0] < self.cache_ttl_seconds:
                return cached[1]

        # Registration, certificate transparency, and reputation are independent
        # network sources. Query them concurrently so a quick scan is bounded by
        # the slowest provider rather than the sum of all provider timeouts.
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="domain-intel") as pool:
            registration_future = pool.submit(self._query_registration, domain)
            certificate_future = pool.submit(self._query_certificates, domain)
            reputation_future = pool.submit(self._query_reputation, domain)
            (
                whoisxml,
                whoisxml_error,
                whois,
                whois_error,
                rdap,
                rdap_error,
            ) = registration_future.result()
            certificates, certificate_error = certificate_future.result()
            reputation, reputation_error = reputation_future.result()
        age_days, created_at, registration_date_source = self._registration_age(
            whoisxml, whois, rdap
        )
        registration_created_at = created_at
        registrar_candidates = tuple(
            dict.fromkeys(
                value
                for value in (
                    self._whoisxml_registrar(whoisxml),
                    self._ip2whois_registrar(whois),
                    self._registrar(rdap),
                )
                if value
            )
        )
        registrar = registrar_candidates[0] if registrar_candidates else None
        expiry_days = self._expiry_days(whoisxml, whois, rdap)
        expires_at = self._expiry_date(whoisxml, whois, rdap)
        updated_at = self._updated_date(whoisxml, whois, rdap)
        registrant = (
            self._whoisxml_registrant(whoisxml)
            or self._ip2whois_registrant(whois)
            or self._rdap_entity_name(rdap, "registrant")
        )
        registrant_phone = (
            self._whoisxml_registrant_phone(whoisxml)
            or self._ip2whois_registrant_phone(whois)
            or self._rdap_entity_phone(rdap, "registrant")
        )
        registration_nameservers = self._registration_nameservers(whoisxml, whois, rdap)
        registration_statuses = tuple(
            str(value) for value in ((rdap or {}).get("status") or []) if value
        )
        registration_source = registration_date_source or (
            "WhoisXML API" if whoisxml else "IP2WHOIS" if whois else "RDAP"
        )
        registration_errors = [
            error for error in (whoisxml_error, whois_error, rdap_error) if error
        ]
        certificate_age_days, _ = self._certificate_age(certificates)
        listed = self._reputation_listed(reputation)
        reputation_ips = self._reputation_ips(reputation)
        malicious_ips = self._reputation_ips(reputation, malicious_only=True)
        malicious_observations = self._malicious_observation_count(reputation)
        shared_hosting_available = bool(
            isinstance(reputation, dict)
            and reputation.get("shared_hosting_available") is True
        )
        shared_malicious_domains = tuple(
            str(value)
            for value in (
                reputation.get("shared_malicious_domains", [])
                if isinstance(reputation, dict)
                else []
            )
            if value
        )
        shared_malicious_observations = int(
            reputation.get("shared_malicious_observations", 0)
            if isinstance(reputation, dict)
            else 0
        )
        reasons: list[str] = []
        score = 0.0
        if age_days is not None:
            if age_days < 30:
                score += 0.20
                reasons.append(f"Domain mới đăng ký {age_days} ngày (<30 ngày).")
            elif age_days < 90:
                score += 0.12
                reasons.append(f"Domain mới đăng ký {age_days} ngày (<90 ngày).")
            elif age_days < 180:
                score += 0.06
                reasons.append(f"Domain còn mới: {age_days} ngày (<180 ngày).")
        if listed:
            score += 0.45
            reasons.append("Nguồn urlscan.io có kết quả đánh dấu độc hại cho domain.")
        if not reasons and (whoisxml or whois or rdap or certificates or reputation):
            reasons.append("Không phát hiện domain mới hoặc kết quả độc hại trong nguồn công khai đã truy vấn.")
        errors = [error for error in (whoisxml_error, whois_error, rdap_error, certificate_error, reputation_error) if error]
        if errors and not (whoisxml or whois or rdap or certificates or reputation):
            reasons.append("Không thể truy vấn nguồn intelligence: " + "; ".join(errors))

        result = DomainIntelligence(
            domain=domain,
            age_days=age_days,
            created_at=registration_created_at,
            registrar=registrar,
            registrar_candidates=registrar_candidates,
            reputation_status="listed" if listed else "not_listed" if listed is False else "unavailable",
            reputation_source="urlscan.io",
            listed=listed,
            score=min(1.0, score),
            reasons=tuple(reasons),
            available=bool(whoisxml or whois or rdap or certificates or reputation),
            expiry_days=expiry_days,
            certificate_age_days=certificate_age_days,
            expires_at=expires_at,
            updated_at=updated_at,
            registrant=registrant,
            registrant_phone=registrant_phone,
            registration_nameservers=registration_nameservers,
            registration_statuses=registration_statuses,
            registration_source=registration_source,
            registration_available=bool(whoisxml or whois or rdap),
            registration_error="; ".join(registration_errors) or None,
            reputation_ips=reputation_ips,
            malicious_ips=malicious_ips,
            malicious_observations=malicious_observations,
            shared_hosting_available=shared_hosting_available,
            shared_malicious_domains=shared_malicious_domains,
            shared_malicious_observations=shared_malicious_observations,
        )
        with self._lock:
            self._cache[key] = (time.monotonic(), result)
        return result

    def _query_registration(
        self, domain: str
    ) -> tuple[
        dict[str, Any] | None,
        str | None,
        dict[str, Any] | None,
        str | None,
        dict[str, Any] | None,
        str | None,
    ]:
        whoisxml, whoisxml_error = self._query_whoisxml(domain)
        whoisxml_age, _ = self._whoisxml_age(whoisxml)
        if whoisxml is not None and whoisxml_age is None and not whoisxml_error:
            whoisxml_error = "WhoisXML thiếu ngày đăng ký hợp lệ"

        # A provider returning a WHOIS record does not guarantee that it returned
        # a usable creation date. Keep falling back until criterion 1 has real
        # registration-date evidence instead of treating a partial record as clean.
        whois, whois_error = (
            (None, None) if whoisxml_age is not None else self._query_ip2whois(domain)
        )
        whois_age, _ = self._ip2whois_age(whois)
        if whois is not None and whois_age is None and not whois_error:
            whois_error = "IP2WHOIS thiếu ngày đăng ký hợp lệ"

        rdap, rdap_error = (
            (None, None)
            if whoisxml_age is not None or whois_age is not None
            else self._query_rdap(domain)
        )
        rdap_age, _ = self._domain_age(rdap)
        if rdap is not None and rdap_age is None and not rdap_error:
            rdap_error = "RDAP thiếu ngày đăng ký hợp lệ"
        return whoisxml, whoisxml_error, whois, whois_error, rdap, rdap_error

    def _query_whoisxml(self, domain: str) -> tuple[dict[str, Any] | None, str | None]:
        if not settings.whoisxml_api_key:
            return None, "WHOISXML_API_KEY chưa cấu hình"
        try:
            response = httpx.post(
                "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                json={
                    "domainName": domain,
                    "apiKey": settings.whoisxml_api_key,
                    "outputFormat": "JSON",
                },
                timeout=self.timeout_seconds,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            if response.status_code != 200:
                return None, f"WhoisXML HTTP {response.status_code}"
            data = response.json()
            if data.get("ErrorMessage"):
                return None, f"WhoisXML {data['ErrorMessage']}"
            record = data.get("WhoisRecord")
            return (record, None) if record else (None, "WhoisXML thiếu WhoisRecord")
        except Exception as exc:
            return None, f"WhoisXML {type(exc).__name__}"

    @classmethod
    def _whoisxml_age(cls, data: dict[str, Any] | None) -> tuple[int | None, str | None]:
        if not data:
            return None, None
        registry = data.get("registryData") or {}
        for raw in (
            registry.get("createdDateNormalized"),
            registry.get("createdDate"),
            data.get("createdDateNormalized"),
            data.get("createdDate"),
        ):
            result = cls._age_from_created(raw)
            if result[0] is not None:
                return result
        return None, None

    @staticmethod
    def _whoisxml_registrar(data: dict[str, Any] | None) -> str | None:
        if not data:
            return None
        registry = data.get("registryData") or {}
        value = registry.get("registrarName") or data.get("registrarName")
        return str(value) if value else None

    @classmethod
    def _whoisxml_registrant(cls, data: dict[str, Any] | None) -> str | None:
        if not data:
            return None
        registry = data.get("registryData") or {}
        for record in (registry.get("registrant"), data.get("registrant")):
            value = cls._contact_name(record)
            if value:
                return value
        return None

    @classmethod
    def _whoisxml_registrant_phone(cls, data: dict[str, Any] | None) -> str | None:
        if not data:
            return None
        registry = data.get("registryData") or {}
        for record in (registry.get("registrant"), data.get("registrant")):
            value = cls._contact_phone(record)
            if value:
                return value
        return None

    def _query_ip2whois(self, domain: str) -> tuple[dict[str, Any] | None, str | None]:
        if not settings.ip2whois_api_key:
            return None, "IP2WHOIS_API_KEY chưa cấu hình"
        try:
            response = httpx.get(
                "https://api.ip2whois.com/v2",
                params={"key": settings.ip2whois_api_key, "domain": domain, "format": "json"},
                timeout=self.timeout_seconds,
                headers={"Accept": "application/json", "User-Agent": "Prewise/0.2"},
            )
            data = response.json()
            error = data.get("error")
            if isinstance(error, dict):
                return None, f"IP2WHOIS {error.get('error_message') or error.get('error_code') or 'unknown error'}"
            if error or data.get("error_code"):
                return None, f"IP2WHOIS {data.get('error_message') or error or data.get('error_code')}"
            if response.status_code != 200:
                return None, f"IP2WHOIS HTTP {response.status_code}"
            return data, None
        except Exception as exc:
            return None, f"IP2WHOIS {type(exc).__name__}"

    @staticmethod
    def _parse_date(raw: object) -> datetime | None:
        if not raw:
            return None
        value = str(raw).strip()
        if value.endswith(" UTC"):
            value = value[:-4] + "+00:00"
        candidates = (value, value.replace("Z", "+00:00"))
        for candidate in candidates:
            try:
                parsed = datetime.fromisoformat(candidate)
                return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
            except ValueError:
                pass
        for pattern in ("%Y-%m-%d", "%Y/%m/%d", "%d-%b-%Y", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(value, pattern).replace(tzinfo=UTC)
            except ValueError:
                pass
        return None

    @classmethod
    def _age_from_created(cls, raw: object) -> tuple[int | None, str | None]:
        created = cls._parse_date(raw)
        if created is None:
            return None, None
        elapsed = datetime.now(UTC) - created
        # A creation timestamp materially in the future is malformed provider
        # data, not evidence of a zero-day-old domain. Allow one day for clock
        # skew and date-only registry timestamps.
        if elapsed.total_seconds() < -86400:
            return None, None
        return max(0, elapsed.days), str(raw)

    @classmethod
    def _ip2whois_age(cls, data: dict[str, Any] | None) -> tuple[int | None, str | None]:
        if not data:
            return None, None
        for raw in (
            data.get("create_date"),
            data.get("created_date"),
            data.get("createdDate"),
        ):
            result = cls._age_from_created(raw)
            if result[0] is not None:
                return result
        return None, None

    @staticmethod
    def _ip2whois_registrar(data: dict[str, Any] | None) -> str | None:
        if not data:
            return None
        registrar = data.get("registrar")
        if isinstance(registrar, dict):
            return str(registrar.get("name") or registrar.get("organization") or "") or None
        return str(registrar) if registrar else None

    @classmethod
    def _ip2whois_registrant(cls, data: dict[str, Any] | None) -> str | None:
        if not data:
            return None
        return cls._contact_name(data.get("registrant"))

    @classmethod
    def _ip2whois_registrant_phone(cls, data: dict[str, Any] | None) -> str | None:
        if not data:
            return None
        return cls._contact_phone(data.get("registrant"))

    def _query_rdap(self, domain: str) -> tuple[dict[str, Any] | None, str | None]:
        try:
            base_url, bootstrap_error = self._rdap_base_url(domain)
            endpoint = (
                urljoin(base_url.rstrip("/") + "/", f"domain/{quote(domain, safe='')}")
                if base_url
                else f"https://rdap.org/domain/{quote(domain, safe='')}"
            )
            response = httpx.get(
                endpoint,
                timeout=self.timeout_seconds,
                follow_redirects=True,
                headers={"Accept": "application/rdap+json", "User-Agent": "Prewise/0.2"},
            )
            if response.status_code == 200:
                return response.json(), None
            suffix = f"; {bootstrap_error}" if bootstrap_error else ""
            return None, f"RDAP HTTP {response.status_code}{suffix}"
        except Exception as exc:
            return None, f"RDAP {type(exc).__name__}"

    def _rdap_base_url(self, domain: str) -> tuple[str | None, str | None]:
        tld = domain.rstrip(".").rsplit(".", 1)[-1].lower()
        now = time.monotonic()
        with self._rdap_lock:
            cached = self._rdap_bootstrap
            if cached and now - cached[0] < 86400:
                return cached[1].get(tld), None
            try:
                response = httpx.get(
                    "https://data.iana.org/rdap/dns.json",
                    timeout=self.timeout_seconds,
                    headers={"Accept": "application/json", "User-Agent": "Prewise/0.2"},
                )
                if response.status_code != 200:
                    return None, f"IANA bootstrap HTTP {response.status_code}"
                data = response.json()
                mapping: dict[str, str] = {}
                for service in data.get("services", []):
                    if not isinstance(service, list) or len(service) < 2:
                        continue
                    tlds, urls = service[0], service[1]
                    base_url = next(
                        (str(value) for value in urls if str(value).startswith("https://")),
                        None,
                    )
                    if not base_url:
                        continue
                    for value in tlds:
                        mapping[str(value).lower()] = base_url
                self._rdap_bootstrap = (now, mapping)
                return mapping.get(tld), None if tld in mapping else f"IANA bootstrap thiếu TLD {tld}"
            except Exception as exc:
                return None, f"IANA bootstrap {type(exc).__name__}"

    def _query_urlhaus(self, url: str) -> tuple[dict[str, Any] | None, str | None]:
        try:
            response = httpx.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                timeout=self.timeout_seconds,
                headers={"User-Agent": "Prewise/0.2"},
            )
            if response.status_code == 200:
                return response.json(), None
            return None, f"URLhaus HTTP {response.status_code}"
        except Exception as exc:
            return None, f"URLhaus {type(exc).__name__}"

    def _query_certificates(self, domain: str) -> tuple[list[dict[str, Any]] | None, str | None]:
        try:
            response = httpx.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                timeout=self.timeout_seconds,
                headers={"User-Agent": "Prewise/0.2"},
            )
            if response.status_code == 200:
                return response.json(), None
            return None, f"crt.sh HTTP {response.status_code}"
        except Exception as exc:
            return None, f"crt.sh {type(exc).__name__}"

    def _query_reputation(self, domain: str) -> tuple[dict[str, Any] | None, str | None]:
        try:
            response = httpx.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}", "size": 20},
                timeout=self.timeout_seconds,
                headers={"User-Agent": "Prewise/0.2"},
            )
            if response.status_code == 200:
                payload = response.json()
                if not isinstance(payload, dict):
                    return None, "urlscan invalid response"
                return self._add_shared_hosting_history(domain, payload), None
            return None, f"urlscan HTTP {response.status_code}"
        except Exception as exc:
            return None, f"urlscan {type(exc).__name__}"

    def _add_shared_hosting_history(
        self,
        domain: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Attach reverse-IP abuse context without confusing it with this domain.

        The first query is scoped to the exact registrable domain. Its observed
        public IPs are then queried separately. Only malicious results belonging
        to other registrable domains count as shared-hosting evidence.
        """

        addresses = self._reputation_ips(payload)
        if not addresses:
            return {**payload, "shared_hosting_available": False}
        malicious_domains: set[str] = set()
        malicious_observations = 0
        completed_queries = 0
        errors: list[str] = []

        def query(address: str) -> tuple[str, dict[str, Any] | None, str | None]:
            try:
                response = httpx.get(
                    "https://urlscan.io/api/v1/search/",
                    params={"q": f"ip:{address}", "size": 100},
                    timeout=self.timeout_seconds,
                    headers={"User-Agent": "Prewise/0.2"},
                )
                if response.status_code != 200:
                    return address, None, f"{address}:HTTP {response.status_code}"
                data = response.json()
                if not isinstance(data, dict):
                    return address, None, f"{address}:invalid response"
                return address, data, None
            except (httpx.HTTPError, ValueError, TypeError) as exc:
                return address, None, f"{address}:{type(exc).__name__}"

        candidates = addresses[:2]
        with ThreadPoolExecutor(
            max_workers=len(candidates),
            thread_name_prefix="reverse-ip-intel",
        ) as pool:
            results = list(pool.map(query, candidates))
        for _address, data, error in results:
            if error:
                errors.append(error)
                continue
            if data is not None:
                completed_queries += 1
                for item in data.get("results", []):
                    if not isinstance(item, dict) or not bool(
                        item.get("verdicts", {}).get("overall", {}).get("malicious")
                    ):
                        continue
                    page = item.get("page") if isinstance(item.get("page"), dict) else {}
                    observed = str(page.get("domain") or "").lower().rstrip(".")
                    if not observed or observed == domain or observed.endswith("." + domain):
                        continue
                    malicious_observations += 1
                    malicious_domains.add(observed)
        return {
            **payload,
            "shared_hosting_available": completed_queries > 0,
            "shared_malicious_domains": sorted(malicious_domains),
            "shared_malicious_observations": malicious_observations,
            "shared_hosting_errors": errors,
        }

    @staticmethod
    def _certificate_age(data: list[dict[str, Any]] | None) -> tuple[int | None, str | None]:
        dates: list[datetime] = []
        for item in data or []:
            raw = item.get("not_before") or item.get("entry_timestamp")
            if not raw:
                continue
            try:
                dates.append(datetime.fromisoformat(str(raw).replace("Z", "+00:00")).astimezone(UTC))
            except ValueError:
                continue
        if not dates:
            return None, None
        earliest = min(dates)
        return max(0, (datetime.now(UTC) - earliest).days), earliest.isoformat()

    @staticmethod
    def _reputation_listed(data: dict[str, Any] | None) -> bool | None:
        if not data:
            return None
        results = data.get("results", [])
        return any(bool(item.get("verdicts", {}).get("overall", {}).get("malicious")) for item in results)

    @staticmethod
    def _reputation_ips(
        data: dict[str, Any] | None, *, malicious_only: bool = False
    ) -> tuple[str, ...]:
        values: set[str] = set()
        for item in (data or {}).get("results", []):
            if not isinstance(item, dict):
                continue
            if malicious_only and not bool(
                item.get("verdicts", {}).get("overall", {}).get("malicious")
            ):
                continue
            page = item.get("page") if isinstance(item.get("page"), dict) else {}
            ip = str(page.get("ip") or "").strip()
            if ip:
                values.add(ip)
        return tuple(sorted(values))

    @staticmethod
    def _malicious_observation_count(data: dict[str, Any] | None) -> int:
        return sum(
            1
            for item in (data or {}).get("results", [])
            if isinstance(item, dict)
            and bool(item.get("verdicts", {}).get("overall", {}).get("malicious"))
        )

    @classmethod
    def _domain_age(cls, data: dict[str, Any] | None) -> tuple[int | None, str | None]:
        if not data:
            return None, None
        for event in data.get("events", []):
            if not isinstance(event, dict):
                continue
            action = str(event.get("eventAction") or "").strip().lower()
            if action not in {"registration", "registered"}:
                continue
            result = cls._age_from_created(event.get("eventDate"))
            if result[0] is not None:
                return result
        return None, None

    @classmethod
    def _registration_age(
        cls,
        whoisxml: dict[str, Any] | None,
        whois: dict[str, Any] | None,
        rdap: dict[str, Any] | None,
    ) -> tuple[int | None, str | None, str | None]:
        for source, result in (
            ("WhoisXML API", cls._whoisxml_age(whoisxml)),
            ("IP2WHOIS", cls._ip2whois_age(whois)),
            ("RDAP", cls._domain_age(rdap)),
        ):
            age_days, created_at = result
            if age_days is not None:
                return age_days, created_at, source
        return None, None, None

    @classmethod
    def _expiry_days(cls, whoisxml: dict[str, Any] | None,
                     whois: dict[str, Any] | None, rdap: dict[str, Any] | None) -> int | None:
        raw = cls._expiry_date(whoisxml, whois, rdap)
        expires = cls._parse_date(raw)
        return (expires - datetime.now(UTC)).days if expires else None

    @classmethod
    def _expiry_date(cls, whoisxml: dict[str, Any] | None,
                     whois: dict[str, Any] | None, rdap: dict[str, Any] | None) -> str | None:
        registry = (whoisxml or {}).get("registryData") or {}
        raw = (registry.get("expiresDateNormalized") or registry.get("expiresDate")
               or (whoisxml or {}).get("expiresDateNormalized")
               or (whoisxml or {}).get("expiresDate")
               or (whois or {}).get("expire_date") or (whois or {}).get("expiration_date"))
        if not raw and rdap:
            for event in rdap.get("events", []):
                if event.get("eventAction") in {"expiration", "expiry", "expires"}:
                    raw = event.get("eventDate")
                    break
        return str(raw) if raw else None

    @classmethod
    def _updated_date(cls, whoisxml: dict[str, Any] | None,
                      whois: dict[str, Any] | None, rdap: dict[str, Any] | None) -> str | None:
        registry = (whoisxml or {}).get("registryData") or {}
        raw = (registry.get("updatedDateNormalized") or registry.get("updatedDate")
               or (whoisxml or {}).get("updatedDateNormalized")
               or (whoisxml or {}).get("updatedDate")
               or (whois or {}).get("update_date") or (whois or {}).get("updated_date"))
        if not raw and rdap:
            for event in rdap.get("events", []):
                if event.get("eventAction") in {"last changed", "last update of RDAP database", "updated"}:
                    raw = event.get("eventDate")
                    break
        return str(raw) if raw else None

    @staticmethod
    def _registrar(data: dict[str, Any] | None) -> str | None:
        if not data:
            return None
        for entity in data.get("entities", []):
            if "registrar" not in entity.get("roles", []):
                continue
            for row in entity.get("vcardArray", [None, []])[1]:
                if row and row[0] == "fn" and len(row) > 3:
                    return str(row[3])
        return None

    @classmethod
    def _rdap_entity_name(cls, data: dict[str, Any] | None, role: str) -> str | None:
        if not data:
            return None
        for entity in data.get("entities", []):
            if role not in entity.get("roles", []):
                continue
            rows = entity.get("vcardArray", [None, []])
            if not isinstance(rows, list) or len(rows) < 2:
                continue
            for field in ("org", "fn"):
                for row in rows[1]:
                    if row and row[0] == field and len(row) > 3:
                        value = row[3]
                        if isinstance(value, list):
                            value = " ".join(str(item) for item in value if item)
                        cleaned = cls._public_identity(value)
                        if cleaned:
                            return cleaned
        return None

    @classmethod
    def _rdap_entity_phone(cls, data: dict[str, Any] | None, role: str) -> str | None:
        if not data:
            return None
        for entity in data.get("entities", []):
            if role not in entity.get("roles", []):
                continue
            rows = entity.get("vcardArray", [None, []])
            if not isinstance(rows, list) or len(rows) < 2:
                continue
            for row in rows[1]:
                if row and row[0] == "tel" and len(row) > 3:
                    value = row[3]
                    if isinstance(value, list):
                        value = next((item for item in value if item), None)
                    cleaned = cls._public_identity(value)
                    if cleaned:
                        return cleaned.removeprefix("tel:")
        return None

    @classmethod
    def _contact_name(cls, record: object) -> str | None:
        if isinstance(record, dict):
            for key in ("organization", "name", "organizationName"):
                value = cls._public_identity(record.get(key))
                if value:
                    return value
        return cls._public_identity(record) if isinstance(record, str) else None

    @classmethod
    def _contact_phone(cls, record: object) -> str | None:
        if not isinstance(record, dict):
            return None
        for key in ("telephone", "phone", "phoneNumber", "voice"):
            value = cls._public_identity(record.get(key))
            if value:
                return value.removeprefix("tel:")
        return None

    @staticmethod
    def _public_identity(value: object) -> str | None:
        if not value:
            return None
        text = str(value).strip()
        hidden_markers = (
            "redacted",
            "data protected",
            "not disclosed",
            "privacy service",
            "privacy protection",
            "gdpr masked",
        )
        return None if any(marker in text.lower() for marker in hidden_markers) else text

    @classmethod
    def _registration_nameservers(
        cls,
        whoisxml: dict[str, Any] | None,
        whois: dict[str, Any] | None,
        rdap: dict[str, Any] | None,
    ) -> tuple[str, ...]:
        registry = (whoisxml or {}).get("registryData") or {}
        candidates = [
            registry.get("nameServers"),
            (whoisxml or {}).get("nameServers"),
            (whois or {}).get("name_servers"),
            (whois or {}).get("nameservers"),
        ]
        values: list[str] = []
        for candidate in candidates:
            values.extend(cls._nameserver_values(candidate))
        for record in (rdap or {}).get("nameservers", []):
            if isinstance(record, dict):
                values.extend(
                    cls._nameserver_values(record.get("ldhName") or record.get("unicodeName"))
                )
        return tuple(dict.fromkeys(value.lower().rstrip(".") for value in values if value))

    @classmethod
    def _nameserver_values(cls, value: object) -> list[str]:
        if isinstance(value, dict):
            for key in ("hostNames", "nameservers", "name_servers"):
                if key in value:
                    return cls._nameserver_values(value[key])
            for key in ("name", "host", "hostname", "ldhName"):
                if value.get(key):
                    return cls._nameserver_values(value[key])
            return []
        if isinstance(value, (list, tuple, set)):
            result: list[str] = []
            for item in value:
                result.extend(cls._nameserver_values(item))
            return result
        if isinstance(value, str):
            return [part.strip() for part in value.replace(",", " ").split() if part.strip()]
        return []


domain_intelligence_service = DomainIntelligenceService()
