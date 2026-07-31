"""Explainable offline URL evidence collector.

This module deliberately separates fast, offline analysis from live execution.  A
finding is not a final score: every observation is forwarded to the unified Risk
Core, which alone deduplicates and scores it.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlparse

from ai.adapters.url_adapter import (
    URLSignals,
    analyze_url_signals,
    min_brand_distance,
    shannon_entropy,
)
from shared.schemas import Evidence, Severity


@dataclass(frozen=True)
class URLRiskObservations:
    evidence: list[Evidence]
    requires_deep_analysis: bool


def _e(message: str, severity: Severity, feature: str, contribution: float) -> Evidence:
    return Evidence(
        source="url_risk_core", message=message, severity=severity,
        feature=feature, contribution=round(contribution, 3),
    )


def collect_url_evidence(url: str) -> URLRiskObservations:
    """Collect URL evidence without fetching an untrusted site.

    Layer 0 validates normalization; Layer 1 checks lexical/deception patterns;
    Layer 2 identifies credential-theft intent and evasion.
    """
    signals: URLSignals = analyze_url_signals(url)
    parsed = urlparse(signals.parts.normalized_url)
    decoded = unquote(signals.parts.normalized_url).lower()
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    evidence: list[Evidence] = []
    # Layer 0: parsing and protocol abuse. These indicators are especially valuable
    # because they do not depend on reputation feeds or a live fetch.
    raw_host = parsed.hostname or ""
    if raw_host.startswith("xn--") or ".xn--" in raw_host:
        evidence.append(_e("Tên miền IDN/punycode cần được kiểm tra kỹ vì có thể che ký tự giống nhau.",
                           Severity.HIGH, "punycode_domain", 0.18))
    if parsed.username or parsed.password:
        evidence.append(_e("URL chứa thông tin đăng nhập trước ký tự @, có thể che đích thật.",
                           Severity.CRITICAL, "embedded_credentials", 0.30))
    if parsed.port and parsed.port not in {80, 443}:
        evidence.append(_e("URL sử dụng cổng không chuẩn; cần xác minh dịch vụ đích.",
                           Severity.LOW, "nonstandard_port", 0.08))

    # Layer 1: identity and routing deception.
    if signals.brand_mismatch:
        evidence.append(_e(
            f"Tên thương hiệu xuất hiện trên tên miền không chính chủ ({signals.parts.registrable_domain}).",
            Severity.CRITICAL, "brand_domain_mismatch", 0.42))
    if signals.deceptive_subdomain:
        evidence.append(_e("Thương hiệu hoặc nhãn 'secure/login' bị đặt ở subdomain để che tên miền thật.",
                           Severity.CRITICAL, "deceptive_subdomain", 0.25))
    if signals.homoglyph:
        evidence.append(_e("Tên miền có ký tự/dạng viết gần giống thương hiệu (homoglyph).",
                           Severity.CRITICAL, "homoglyph", 0.32))
    # Bắt biến thể gõ sai thương hiệu ngay cả khi không có chữ số/punycode.
    # Ví dụ: vietcombank-login.example hoặc paypa-security.example.
    brand_distance = min_brand_distance(signals.parts.domain_label)
    if 0.0 < brand_distance <= 0.25 and len(signals.parts.domain_label) >= 5:
        evidence.append(_e(
            "Nhãn tên miền gần giống một thương hiệu đã biết; có thể là biến thể gõ sai để giả mạo.",
            Severity.HIGH,
            "brand_typosquatting",
            0.24,
        ))
    if signals.ip_host:
        evidence.append(_e("URL dùng địa chỉ IP thay vì tên miền, thường dùng để né nhận diện.",
                           Severity.HIGH, "ip_host", 0.20))
    if signals.risky_tld:
        evidence.append(_e("Tên miền cấp cao có mức lạm dụng phishing cao hơn trung bình.",
                           Severity.MEDIUM, "risky_tld", 0.12))
    if signals.no_https:
        evidence.append(_e("Không dùng HTTPS; dữ liệu nhập có thể bị lộ trên đường truyền.",
                           Severity.MEDIUM, "no_https", 0.10))
    if signals.shortlink:
        evidence.append(_e("Shortlink che giấu đích đến; cần mở rộng redirect trong sandbox.",
                           Severity.LOW, "is_shortlink", 0.03))
    if signals.long_url:
        evidence.append(_e(
            "URL dài bất thường; cần kiểm tra phần đích và tham số đã được che khuất.",
            Severity.LOW,
            "long_url",
            0.05,
        ))
    if signals.excessive_dots:
        evidence.append(_e(
            "Hostname có nhiều lớp subdomain, có thể làm người dùng đọc nhầm tên miền đăng ký.",
            Severity.LOW,
            "excessive_subdomains",
            0.06,
        ))

    # Layer 2: credential theft intent and URL obfuscation/evasion.
    # Decode repeatedly (bounded) so percent-encoding cannot hide another URL or
    # an account/credential lure from the offline gate.
    decoded_rounds = decoded
    for _ in range(2):
        next_value = unquote(decoded_rounds)
        if next_value == decoded_rounds:
            break
        decoded_rounds = next_value
    credential_terms = {"password", "passwd", "otp", "2fa", "mfa", "card", "cvv", "payment", "billing", "bank", "wallet", "cccd", "token", "seed", "mnemonic"}
    matched_sensitive = {term for term in credential_terms if term in decoded_rounds}
    embedded_urls = decoded_rounds.count("http://") + decoded_rounds.count("https://")
    if embedded_urls >= 2:
        evidence.append(_e("URL lồng nhiều địa chỉ đích; đây là mẫu chuyển hướng/che giấu phổ biến.",
                           Severity.HIGH, "nested_url_redirect", 0.18))
    if any(key in decoded_rounds for key in ("redirect=", "redirect_uri=", "return_url=", "continue=", "next=", "target=", "url=")):
        evidence.append(_e("URL có tham số chuyển hướng; đích cuối cần được xác thực trong sandbox.",
                           Severity.LOW, "redirect_parameter", 0.07))
    if matched_sensitive:
        sensitive_contribution = min(0.26, 0.09 * len(matched_sensitive))
        evidence.append(_e("URL nhắm tới dữ liệu nhạy cảm: " + ", ".join(sorted(matched_sensitive)) + ".",
                           Severity.HIGH, "credential_theft_intent", sensitive_contribution))
    if signals.suspicious_keywords:
        # Keep this monotonic: three coordinated lure terms must never contribute
        # less risk than one or two. Cap at three to avoid unlimited accumulation.
        keyword_contribution = 0.12 * min(len(signals.suspicious_keywords), 3)
        evidence.append(_e(
            "URL chứa cụm từ dụ xác thực/đăng nhập: "
            + ", ".join(sorted(signals.suspicious_keywords)),
            Severity.HIGH if len(signals.suspicious_keywords) >= 3 else Severity.MEDIUM,
            "credential_lure_cluster" if len(signals.suspicious_keywords) >= 3 else "suspicious_keywords",
            keyword_contribution,
        ))
    if signals.suspicious_keywords and (
        signals.brand_mismatch or (0.0 < brand_distance <= 0.25)
    ):
        evidence.append(_e(
            "Tên miền giả/gần giống thương hiệu được kết hợp với lời dụ đăng nhập, "
            "xác minh hoặc thanh toán.",
            Severity.CRITICAL,
            "brand_credential_lure_combination",
            0.38,
        ))
    if signals.dangerous_download:
        evidence.append(_e(
            "URL trỏ trực tiếp tới loại tệp có thể thực thi; không tải hoặc chạy ngoài sandbox.",
            Severity.HIGH,
            "dangerous_download",
            0.14,
        ))
    if signals.disguised_download:
        evidence.append(_e(
            "Tên tệp dùng đuôi tài liệu giả trước đuôi thực thi (ví dụ PDF.EXE), phù hợp mẫu phát tán mã độc ngụy trang.",
            Severity.CRITICAL,
            "disguised_executable_download",
            0.72,
        ))
    if signals.archive_lure:
        evidence.append(_e(
            "Tệp nén gắn với ngữ cảnh CV/hóa đơn/tài liệu hoặc dùng đuôi kép; cần phân tích trong sandbox.",
            Severity.HIGH,
            "archive_download_lure",
            0.22,
        ))
    shared_hosting_abuse = signals.shared_hosting and (
        signals.brand_mismatch
        or len(signals.suspicious_keywords) >= 2
        or signals.dangerous_download
        or signals.archive_lure
    )
    if shared_hosting_abuse:
        evidence.append(_e(
            "Hosting dùng chung đi kèm dấu hiệu mạo danh/dụ tải; nền tảng không bị coi là độc nếu đứng riêng.",
            Severity.HIGH,
            "shared_hosting_abuse_context",
            0.16,
        ))
    if signals.at_symbol:
        evidence.append(_e("Ký tự @ có thể làm người dùng hiểu sai đích thực của URL.",
                           Severity.HIGH, "at_symbol", 0.22))
    if signals.percent_encoded or signals.many_delimiters:
        evidence.append(_e("URL bị mã hóa hoặc phân mảnh bất thường để né kiểm tra trực quan.",
                           Severity.MEDIUM, "url_obfuscation", 0.12))
    if signals.query_param_count >= 5 or len(query_pairs) >= 7:
        evidence.append(_e("URL chứa số lượng tham số truy vấn bất thường.",
                           Severity.LOW, "excessive_query_parameters", 0.08))
    host_entropy = shannon_entropy(signals.parts.domain_label)
    if len(signals.parts.domain_label) >= 14 and host_entropy >= 3.5:
        evidence.append(_e("Nhãn tên miền dài, entropy cao; có thể là tên miền sinh tự động.",
                           Severity.MEDIUM, "high_entropy_domain", 0.10))

    risk_findings = [item for item in evidence if item.contribution > 0]
    high_impact = bool(
        matched_sensitive
        or signals.shortlink
        or signals.brand_mismatch
        or signals.dangerous_download
        or signals.archive_lure
        or shared_hosting_abuse
    )
    requires_deep = signals.shortlink or high_impact
    if requires_deep:
        evidence.append(_e("Khuyến nghị sandbox cô lập: mở trang bằng canary tổng hợp, chặn submit và theo dõi redirect/exfiltration.",
                           Severity.INFO, "deep_analysis_recommended", 0.0))
    if not evidence:
        evidence.append(_e("Không phát hiện tín hiệu rủi ro rõ rệt ở lớp phân tích ngoại tuyến.",
                           Severity.INFO, "no_offline_signal", 0.0))
    return URLRiskObservations(evidence, requires_deep)
