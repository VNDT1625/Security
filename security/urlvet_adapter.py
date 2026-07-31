"""Clean-room HTTP adapter for the separately licensed url.vet service.

No url.vet implementation code is copied here.  The adapter consumes the public
REST response documented by the upstream AGPL service and maps concrete findings
to this project's evidence contracts.  The upstream aggregate verdict is displayed
but is never independently awarded risk points.
"""
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


def _nested(data: dict[str, Any], *path: str) -> Any:
    value: Any = data
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _bool(data: dict[str, Any], *path: str) -> bool:
    return _nested(data, *path) is True


def _number(data: dict[str, Any], *path: str) -> float:
    try:
        return float(_nested(data, *path) or 0)
    except (TypeError, ValueError):
        return 0.0


def _endpoint(base_url: str) -> str:
    base = base_url.strip().rstrip("/")
    parsed = urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URLVET_API_URL must be an absolute HTTP(S) URL")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Plain HTTP is allowed only for a loopback url.vet service")
    if base.endswith("/api/v1/analyze"):
        return base
    return f"{base}/api/v1/analyze"


def _status_evidence(
    url: str,
    *,
    status: CriterionStatus,
    verdict: ProviderVerdict,
    summary: str,
    adapter_status: str,
    checks: list[dict[str, str]] | None = None,
    feature_context: dict[str, float] | None = None,
) -> EvidenceV2:
    keys = normalize_url(url)
    return EvidenceV2(
        evidence_id=f"urlvet-status-{keys.exact_subject_key[:24]}",
        exact_subject_key=keys.exact_subject_key,
        campaign_subject_key=keys.campaign_subject_key,
        finding_key=make_finding_key(keys.exact_subject_key, "urlvet_scan_status", "urlvet"),
        incident_key=make_incident_key(keys.campaign_subject_key, "urlvet_scan", "scan"),
        criterion_id=None,
        source_id="urlvet",
        organization_id="urlvet",
        source_family="independent_analyzer",
        matched_subject=MatchedSubject.EXACT_URL,
        finding_type="urlvet_scan_status",
        status=status,
        provider_verdict=verdict,
        severity=0.0,
        evidence_quality=0.0,
        match_strength=1.0,
        authority_tier=2,
        observed_at=datetime.now(UTC).isoformat(),
        metadata={
            "summary": summary[:500],
            "adapter_status": adapter_status,
            "checks": checks or [],
            "feature_context": feature_context or {},
            "license_boundary": "separate_agpl_http_service",
        },
    )


def _risk_evidence(
    url: str,
    criterion_id: int,
    finding_type: str,
    severity: float,
    summary: str,
    *,
    feed_lineage: tuple[str, ...] = (),
) -> EvidenceV2:
    keys = normalize_url(url)
    return EvidenceV2(
        evidence_id=f"urlvet-{finding_type}-{keys.exact_subject_key[:18]}",
        exact_subject_key=keys.exact_subject_key,
        campaign_subject_key=keys.campaign_subject_key,
        finding_key=make_finding_key(keys.exact_subject_key, finding_type, "urlvet"),
        incident_key=make_incident_key(keys.campaign_subject_key, "urlvet_scan", "scan"),
        criterion_id=criterion_id,
        source_id="urlvet",
        organization_id="urlvet",
        source_family="independent_analyzer",
        feed_lineage=feed_lineage,
        matched_subject=MatchedSubject.EXACT_URL,
        finding_type=finding_type,
        status=CriterionStatus.MALICIOUS if severity >= 0.75 else CriterionStatus.SUSPICIOUS,
        provider_verdict=(
            ProviderVerdict.MALICIOUS if severity >= 0.75 else ProviderVerdict.SUSPICIOUS
        ),
        severity=severity,
        evidence_quality=0.75,
        match_strength=1.0,
        authority_tier=2,
        observed_at=datetime.now(UTC).isoformat(),
        metadata={"summary": summary, "adapter_status": "completed"},
    )


def _check(
    check_id: str,
    label: str,
    danger: bool | None,
    detail: str = "",
) -> dict[str, str]:
    return {
        "id": check_id,
        "label": label,
        "status": "danger" if danger is True else "safe" if danger is False else "unavailable",
        "detail": detail,
    }


def _observation_check(
    check_id: str,
    label: str,
    observed: bool | None,
    detail: str = "",
) -> dict[str, str]:
    """Represent page context that needs corroboration before it adds risk."""
    return {
        "id": check_id,
        "label": label,
        "status": "review" if observed is True else "safe" if observed is False else "unavailable",
        "detail": detail,
    }


def _map_response(url: str, data: dict[str, Any]) -> list[EvidenceV2]:
    if data.get("incomplete"):
        errors = data.get("errors") if isinstance(data.get("errors"), list) else []
        return [
            _status_evidence(
                url,
                status=CriterionStatus.UNAVAILABLE,
                verdict=ProviderVerdict.UNAVAILABLE,
                summary="url.vet returned an incomplete scan: " + "; ".join(map(str, errors[:3])),
                adapter_status="incomplete",
            )
        ]

    url_features = _nested(data, "features", "url")
    tld = _nested(data, "features", "tld")
    content = data.get("content_data")
    phishing = data.get("phishing")
    redirect = _nested(data, "analysis", "redirection_result")
    tls = data.get("tls_info")
    ssl = data.get("ssl_info")
    randomness = data.get("domain_randomness")
    domain_info = data.get("domain_info")
    typosquat = data.get("typosquat_result")

    url_features = url_features if isinstance(url_features, dict) else {}
    tld = tld if isinstance(tld, dict) else {}
    content = content if isinstance(content, dict) else None
    phishing = phishing if isinstance(phishing, dict) else None
    redirect = redirect if isinstance(redirect, dict) else None
    tls = tls if isinstance(tls, dict) else None
    ssl = ssl if isinstance(ssl, dict) else None
    randomness = randomness if isinstance(randomness, dict) else None
    domain_info = domain_info if isinstance(domain_info, dict) else None
    typosquat = typosquat if isinstance(typosquat, dict) else None

    keywords = url_features.get("keywords")
    keywords = keywords if isinstance(keywords, dict) else {}
    keyword_names = keywords.get("found") if isinstance(keywords.get("found"), list) else []
    forms = content.get("forms") if content is not None else []
    forms = [item for item in forms if isinstance(item, dict)] if isinstance(forms, list) else []
    external_form = any(item.get("is_external") is True for item in forms)
    password_without_tls = (
        any(item.get("has_password") is True for item in forms)
        and tls is not None
        and tls.get("Present") is False
    )
    phishing_reported = phishing is not None and phishing.get("valid") is True
    phishing_verified = phishing_reported and phishing.get("verified") is True
    checks = [
        _check("urlvet_ip_host", "Hostname dùng địa chỉ IP", url_features.get("uses_ip") is True),
        _check("urlvet_punycode", "Punycode/IDN", url_features.get("contains_punycode") is True),
        _check("urlvet_homoglyph", "Ký tự homoglyph", url_features.get("has_homoglyph") is True),
        _check("urlvet_shortener", "Dịch vụ rút gọn URL", url_features.get("url_shortener") is True),
        _check("urlvet_long_url", "URL dài bất thường", url_features.get("too_long") is True),
        _check("urlvet_deep_path", "Đường dẫn quá sâu", url_features.get("too_deep") is True),
        _check(
            "urlvet_subdomains",
            "Quá nhiều subdomain",
            int(url_features.get("subdomain_count") or 0) > 2,
        ),
        _check(
            "urlvet_keywords",
            "Từ khóa phishing trong URL",
            keywords.get("has_keywords") is True,
            ", ".join(map(str, keyword_names[:8])),
        ),
        _check("urlvet_risky_tld", "TLD có mức lạm dụng cao", tld.get("is_risky_tld") is True),
        _check(
            "urlvet_redirect",
            "Chuyển hướng khác tên miền",
            redirect.get("has_domain_jump") is True if redirect is not None else None,
        ),
        _check(
            "urlvet_tls",
            "TLS và hostname chứng chỉ",
            (
                tls.get("Present") is False or tls.get("HostnameMismatch") is True
                if tls is not None
                else None
            ),
        ),
        _check(
            "urlvet_ssl_chain",
            "Chuỗi chứng thư SSL",
            (
                ssl.get("KnownBadChain") is True
                or ssl.get("IsSuspicious") is True
                or ssl.get("ChainValid") is False
                if ssl is not None and ssl.get("HasTLS") is True
                else None
            ),
        ),
        _check(
            "urlvet_domain_age",
            "Tên miền mới đăng ký",
            int(domain_info.get("age_days") or 0) <= 30
            if domain_info is not None and domain_info.get("age_days") is not None
            else None,
        ),
        _check(
            "urlvet_domain_randomness",
            "Tên miền sinh ngẫu nhiên",
            randomness.get("IsSuspicious") is True if randomness is not None else None,
        ),
        _check(
            "urlvet_typosquat",
            "Typosquatting/combo-squatting",
            typosquat.get("is_suspicious") is True if typosquat is not None else None,
        ),
        _observation_check(
            "urlvet_login_form",
            "Biểu mẫu đăng nhập",
            content.get("has_login_form") is True if content is not None else None,
            "Form presence alone is not scored without domain, transport, or exfiltration risk.",
        ),
        _observation_check(
            "urlvet_payment_form",
            "Biểu mẫu thanh toán",
            content.get("has_payment_form") is True if content is not None else None,
            "Payment fields alone are not scored without recipient or deception evidence.",
        ),
        _check(
            "urlvet_hidden_iframe",
            "Iframe ẩn",
            content.get("has_hidden_iframe") is True if content is not None else None,
        ),
        _check(
            "urlvet_external_form",
            "Biểu mẫu gửi sang tên miền khác",
            external_form if content is not None else None,
        ),
        _check(
            "urlvet_password_without_tls",
            "Mật khẩu truyền khi không có TLS",
            password_without_tls if content is not None and tls is not None else None,
        ),
        _check(
            "urlvet_brand_mismatch",
            "Thương hiệu trên trang khác miền",
            _nested(content or {}, "brand_check", "is_mismatch") is True
            if content is not None
            else None,
        ),
        _check(
            "urlvet_phishtank",
            "PhishTank báo cáo/xác nhận",
            phishing_reported if phishing is not None else None,
            "Đã xác nhận" if phishing_verified else "Chưa xác minh" if phishing_reported else "",
        ),
    ]

    result = data.get("result") if isinstance(data.get("result"), dict) else {}
    verdict_name = str(result.get("verdict", "Unknown")).lower()
    if verdict_name == "risky":
        status, verdict = CriterionStatus.MALICIOUS, ProviderVerdict.MALICIOUS
    elif verdict_name == "suspicious":
        status, verdict = CriterionStatus.SUSPICIOUS, ProviderVerdict.SUSPICIOUS
    elif verdict_name == "safe":
        status, verdict = CriterionStatus.CLEAN, ProviderVerdict.CLEAN
    else:
        status, verdict = CriterionStatus.NOT_CHECKED, ProviderVerdict.UNKNOWN
    checks.insert(
        0,
        _check(
            "urlvet_overall_verdict",
            "Kết luận tổng hợp URLVet",
            True
            if verdict_name in {"risky", "suspicious"}
            else False
            if verdict_name == "safe"
            else None,
            (
                f"Verdict={result.get('verdict', 'unknown')}; "
                f"risk={result.get('risk_score', '—')}; trust={result.get('trust_score', '—')}"
            ),
        ),
    )
    redirect_chain = redirect.get("chain") if redirect is not None else []
    redirect_chain = redirect_chain if isinstance(redirect_chain, list) else []
    redirect_count = (
        _number(data, "analysis", "redirection_result", "chain_length")
        or len(redirect_chain)
        if redirect is not None
        else 0
    )
    password_form = any(item.get("has_password") is True for item in forms)
    scripts = content.get("scripts") if content is not None else []
    scripts = scripts if isinstance(scripts, list) else []
    feature_context = {
        "rdap_available": float(
            domain_info is not None and domain_info.get("age_days") is not None
        ),
        "domain_age_days": _number(data, "domain_info", "age_days"),
        "tls_available": float(tls is not None or ssl is not None),
        "tls_present": float(
            (tls or {}).get("Present") is True or (ssl or {}).get("HasTLS") is True
        ),
        "tls_hostname_match": float(
            tls is not None and tls.get("HostnameMismatch") is False
        ),
        "redirect_available": float(redirect is not None),
        "redirect_count": float(redirect_count),
        "cross_domain_redirect_count": float(
            redirect is not None and redirect.get("has_domain_jump") is True
        ),
        "final_domain_changed": float(
            redirect is not None and redirect.get("has_domain_jump") is True
        ),
        "dom_available": float(content is not None),
        "login_form_present": float(
            content is not None and content.get("has_login_form") is True
        ),
        "password_form_present": float(password_form),
        "external_form_present": float(external_form),
        "hidden_iframe_present": float(
            content is not None and content.get("has_hidden_iframe") is True
        ),
        "script_count": _number(data, "content_data", "script_count") or float(len(scripts)),
    }
    output = [
        _status_evidence(
            url,
            status=status,
            verdict=verdict,
            summary=(
                f"url.vet completed: verdict={result.get('verdict', 'unknown')}, "
                f"trust={result.get('trust_score', '—')}, risk={result.get('risk_score', '—')}"
            ),
            adapter_status="completed",
            checks=checks,
            feature_context=feature_context,
        )
    ]

    mappings = (
        (url_features.get("uses_ip") is True, 18, "urlvet_ip_host", 0.85, "url.vet found a raw IP hostname."),
        (url_features.get("contains_punycode") is True, 6, "urlvet_punycode", 0.85, "url.vet found punycode/IDN encoding."),
        (url_features.get("has_homoglyph") is True, 6, "urlvet_homoglyph", 0.9, "url.vet found a homoglyph attack."),
        (url_features.get("url_shortener") is True, 17, "urlvet_shortener", 0.65, "url.vet found a URL shortener."),
        (url_features.get("too_long") is True, 18, "urlvet_long_url", 0.4, "url.vet found an abnormally long URL."),
        (url_features.get("too_deep") is True, 18, "urlvet_deep_path", 0.55, "url.vet found an excessively deep path."),
        (int(url_features.get("subdomain_count") or 0) > 2, 7, "urlvet_subdomains", 0.6, "url.vet found excessive subdomains."),
        (keywords.get("has_keywords") is True, 29, "urlvet_phishing_keywords", 0.55, "url.vet found phishing keywords in the URL."),
        (tld.get("is_risky_tld") is True, 12, "urlvet_risky_tld", 0.55, "url.vet classified the TLD as high risk."),
        (redirect is not None and redirect.get("has_domain_jump") is True, 16, "urlvet_cross_domain_redirect", 0.8, "url.vet observed a cross-domain redirect."),
        (tls is not None and tls.get("HostnameMismatch") is True, 10, "urlvet_tls_hostname_mismatch", 0.9, "url.vet observed a TLS hostname mismatch."),
        (ssl is not None and ssl.get("KnownBadChain") is True, 9, "urlvet_known_bad_certificate", 1.0, "url.vet matched a known-bad certificate chain."),
        (ssl is not None and ssl.get("IsSuspicious") is True, 9, "urlvet_suspicious_certificate", 0.8, "url.vet found suspicious certificate properties."),
        (domain_info is not None and int(domain_info.get("age_days") or 0) <= 30, 1, "urlvet_new_domain", 0.75, "url.vet found a domain registered within 30 days."),
        (randomness is not None and randomness.get("IsSuspicious") is True, 5, "urlvet_random_domain", 0.7, "url.vet found an algorithmically random-looking domain."),
        (typosquat is not None and typosquat.get("is_suspicious") is True, 5, "urlvet_typosquat", 0.85, "url.vet detected typosquatting or combo-squatting."),
        (content is not None and content.get("has_hidden_iframe") is True, 36, "urlvet_hidden_iframe", 0.75, "url.vet found a hidden iframe."),
        (external_form, 30, "urlvet_external_form_action", 0.95, "url.vet found a form posting data to another domain."),
        (password_without_tls, 29, "urlvet_password_without_tls", 1.0, "url.vet found a password form without TLS."),
        (_nested(content or {}, "brand_check", "is_mismatch") is True, 19, "urlvet_content_brand_mismatch", 0.9, "url.vet found brand content on an unofficial domain."),
    )
    for triggered, criterion_id, finding, severity, summary in mappings:
        if triggered:
            output.append(_risk_evidence(url, criterion_id, finding, severity, summary))
    if phishing_verified:
        output.append(
            _risk_evidence(
                url,
                11,
                "urlvet_phishtank_confirmed",
                1.0,
                "url.vet relayed an exact, verified PhishTank match.",
                feed_lineage=("phishtank",),
            )
        )
    elif phishing_reported:
        output.append(
            _risk_evidence(
                url,
                11,
                "urlvet_phishtank_reported_unverified",
                0.7,
                "url.vet relayed a PhishTank report that has not yet been verified.",
                feed_lineage=("phishtank",),
            )
        )
    return output


def collect_urlvet(
    url: str,
    *,
    base_url: str = "",
    enabled: bool = False,
    timeout: float = 12.0,
) -> list[EvidenceV2]:
    """Run the optional url.vet service and return auditable evidence."""

    if not enabled or not base_url.strip():
        return [
            _status_evidence(
                url,
                status=CriterionStatus.NOT_CHECKED,
                verdict=ProviderVerdict.NOT_OBSERVED,
                summary="url.vet is not configured.",
                adapter_status="not_configured",
            )
        ]
    try:
        response = httpx.get(
            _endpoint(base_url),
            params={"url": url},
            timeout=timeout,
            follow_redirects=False,
            headers={"Accept": "application/json", "User-Agent": "ai-security-armor/urlvet-adapter"},
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise TypeError("url.vet response must be a JSON object")
        return _map_response(url, payload)
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return [
            _status_evidence(
                url,
                status=CriterionStatus.UNAVAILABLE,
                verdict=ProviderVerdict.UNAVAILABLE,
                summary=f"url.vet unavailable: {type(exc).__name__}",
                adapter_status="provider_error",
            )
        ]
