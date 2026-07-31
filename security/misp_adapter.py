"""Read-only MISP attribute lookup for URL and domain IOCs."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from security.risk_core.normalization import (
    make_finding_key,
    make_incident_key,
    normalize_url,
)
from security.risk_core.types import (
    CriterionStatus,
    EvidenceV2,
    MatchedSubject,
    ProviderVerdict,
)


def _status_evidence(
    url: str,
    *,
    status: CriterionStatus,
    verdict: ProviderVerdict,
    adapter_status: str,
    summary: str,
    check_status: str,
    detail: str = "",
) -> EvidenceV2:
    keys = normalize_url(url)
    return EvidenceV2(
        evidence_id=f"misp-status-{keys.exact_subject_key[:24]}",
        exact_subject_key=keys.exact_subject_key,
        campaign_subject_key=keys.campaign_subject_key,
        finding_key=make_finding_key(keys.exact_subject_key, "misp_lookup_status", "misp"),
        incident_key=make_incident_key(keys.campaign_subject_key, "misp_lookup", "scan"),
        criterion_id=None,
        source_id="misp",
        organization_id="misp",
        source_family="threat_intelligence_platform",
        matched_subject=MatchedSubject.EXACT_URL,
        finding_type="misp_lookup_status",
        status=status,
        provider_verdict=verdict,
        observed_at=datetime.now(UTC).isoformat(),
        metadata={
            "summary": summary,
            "adapter_status": adapter_status,
            "checks": [
                {
                    "id": "misp_ioc_lookup",
                    "label": "MISP IOC",
                    "status": check_status,
                    "detail": detail,
                }
            ],
        },
    )


def _risk_evidence(url: str, attribute: dict[str, Any], *, exact: bool) -> EvidenceV2:
    keys = normalize_url(url)
    finding_type = "misp_exact_url_match" if exact else "misp_domain_match"
    matched = MatchedSubject.EXACT_URL if exact else MatchedSubject.EXACT_DOMAIN
    severity = 0.98 if exact else 0.72
    return EvidenceV2(
        evidence_id=f"misp-{attribute.get('uuid') or attribute.get('id') or finding_type}",
        exact_subject_key=keys.exact_subject_key,
        campaign_subject_key=keys.campaign_subject_key,
        finding_key=make_finding_key(keys.exact_subject_key, finding_type, "misp"),
        incident_key=make_incident_key(keys.campaign_subject_key, "misp_ioc", "active"),
        criterion_id=11 if exact else 12,
        source_id="misp",
        organization_id=str(attribute.get("Orgc", {}).get("name") or "misp"),
        source_family="threat_intelligence_platform",
        matched_subject=matched,
        finding_type=finding_type,
        status=CriterionStatus.MALICIOUS if exact else CriterionStatus.SUSPICIOUS,
        provider_verdict=ProviderVerdict.MALICIOUS if exact else ProviderVerdict.SUSPICIOUS,
        severity=severity,
        evidence_quality=0.95 if exact else 0.75,
        match_strength=1.0 if exact else 0.7,
        authority_tier=3,
        observed_at=datetime.now(UTC).isoformat(),
        metadata={
            "summary": "MISP matched the exact URL IOC." if exact else "MISP matched the URL domain.",
            "attribute_id": str(attribute.get("id") or ""),
            "event_id": str(attribute.get("event_id") or ""),
            "attribute_type": str(attribute.get("type") or ""),
            "category": str(attribute.get("category") or ""),
            "tags": [
                str(tag.get("name"))
                for tag in attribute.get("Tag", [])
                if isinstance(tag, dict) and tag.get("name")
            ][:20],
            "read_only_lookup": True,
        },
    )


def _client(*, verify_tls: bool, timeout: float) -> httpx.Client:
    return httpx.Client(verify=verify_tls, timeout=timeout, follow_redirects=False)


def _attributes(data: object) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        data = data.get("response", data.get("Attribute", []))
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    output = []
    for item in data:
        if not isinstance(item, dict):
            continue
        attribute = item.get("Attribute") if isinstance(item.get("Attribute"), dict) else item
        if isinstance(attribute, dict):
            output.append(attribute)
    return output


def collect_misp(
    url: str,
    *,
    enabled: bool,
    base_url: str,
    api_key: str,
    verify_tls: bool = True,
    timeout: float = 8.0,
    last: str = "90d",
) -> list[EvidenceV2]:
    if not enabled:
        return [
            _status_evidence(
                url,
                status=CriterionStatus.NOT_CHECKED,
                verdict=ProviderVerdict.UNKNOWN,
                adapter_status="disabled",
                summary="MISP lookup is disabled.",
                check_status="unavailable",
            )
        ]
    parsed = urlsplit(base_url.strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or not api_key:
        return [
            _status_evidence(
                url,
                status=CriterionStatus.UNAVAILABLE,
                verdict=ProviderVerdict.UNAVAILABLE,
                adapter_status="not_configured",
                summary="MISP requires an HTTPS base URL and API key.",
                check_status="unavailable",
            )
        ]
    if not verify_tls and host not in {"127.0.0.1", "localhost", "::1"}:
        return [
            _status_evidence(
                url,
                status=CriterionStatus.UNAVAILABLE,
                verdict=ProviderVerdict.UNAVAILABLE,
                adapter_status="unsafe_tls_configuration",
                summary="TLS verification can be disabled only for loopback MISP.",
                check_status="unavailable",
            )
        ]

    keys = normalize_url(url)
    endpoint = base_url.rstrip("/") + "/attributes/restSearch"
    headers = {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    try:
        hits: list[tuple[dict[str, Any], bool]] = []
        with _client(verify_tls=verify_tls, timeout=timeout) as client:
            for value, attribute_type, exact in (
                (keys.normalized_url, "url", True),
                (keys.registrable_domain_key, "domain", False),
            ):
                response = client.post(
                    endpoint,
                    headers=headers,
                    json={
                        "returnFormat": "json",
                        "value": value,
                        "type": attribute_type,
                        "last": last,
                        "limit": 20,
                        "enforceWarninglist": True,
                    },
                )
                response.raise_for_status()
                hits.extend((attribute, exact) for attribute in _attributes(response.json()))
    except httpx.TimeoutException:
        return [
            _status_evidence(
                url,
                status=CriterionStatus.UNAVAILABLE,
                verdict=ProviderVerdict.UNAVAILABLE,
                adapter_status="timeout",
                summary="MISP lookup timed out.",
                check_status="unavailable",
            )
        ]
    except (httpx.HTTPError, ValueError) as exc:
        return [
            _status_evidence(
                url,
                status=CriterionStatus.UNAVAILABLE,
                verdict=ProviderVerdict.UNAVAILABLE,
                adapter_status="provider_error",
                summary=f"MISP lookup failed: {type(exc).__name__}.",
                check_status="unavailable",
            )
        ]

    deduplicated: dict[tuple[str, bool], dict[str, Any]] = {}
    for attribute, exact in hits:
        key = str(attribute.get("uuid") or attribute.get("id") or attribute.get("value"))
        deduplicated[(key, exact)] = attribute
    evidence = [
        _risk_evidence(url, attribute, exact=exact)
        for (key, exact), attribute in deduplicated.items()
        if key
    ]
    has_exact = any(exact for _, exact in deduplicated)
    has_match = bool(deduplicated)
    evidence.insert(
        0,
        _status_evidence(
            url,
            status=(
                CriterionStatus.MALICIOUS
                if has_exact
                else CriterionStatus.SUSPICIOUS
                if has_match
                else CriterionStatus.NO_HIT
            ),
            verdict=(
                ProviderVerdict.MALICIOUS
                if has_exact
                else ProviderVerdict.SUSPICIOUS
                if has_match
                else ProviderVerdict.NO_HIT
            ),
            adapter_status="completed",
            summary=f"MISP lookup completed with {len(evidence)} IOC match(es).",
            check_status="danger" if evidence else "safe",
            detail=f"Matches: {len(evidence)}",
        ),
    )
    return evidence
