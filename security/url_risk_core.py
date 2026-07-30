"""Explainable multi-layer URL phishing risk core.

This module deliberately separates fast, offline analysis from live execution.  A
score is *not* a blacklist lookup: every layer emits independently auditable
signals, and expensive sandbox execution is only recommended for uncertain or
high-impact targets.
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
class URLRiskAssessment:
    score: float
    evidence: list[Evidence]
    requires_deep_analysis: bool
    layer_scores: dict[str, float]


# Minimum classifier probability before the URL model becomes scored evidence.
# Chosen from a threshold sweep on the frozen holdout: at 0.98 the model reaches
# precision 0.8511 at a 4.20% false-positive rate, the only point where its
# false-alarm rate is comparable to the deterministic decision path (3.20%).
MODEL_HIGH_CONFIDENCE = 0.98


def _clip(value: float) -> float:
    return max(0.0, min(1.0, value))


def _e(message: str, severity: Severity, feature: str, contribution: float) -> Evidence:
    return Evidence(
        source="url_risk_core", message=message, severity=severity,
        feature=feature, contribution=round(contribution, 3),
    )


def assess_url(url: str, model_score: float | None = None) -> URLRiskAssessment:
    """Score URL evidence in layers 0--2 without fetching an untrusted site.

    Layer 0 validates normalization; Layer 1 checks lexical/deception patterns;
    Layer 2 identifies credential-theft intent and evasion.  The caller may pass
    an ML score, but deterministic high-confidence indicators always dominate.
    """
    signals: URLSignals = analyze_url_signals(url)
    parsed = urlparse(signals.parts.normalized_url)
    decoded = unquote(signals.parts.normalized_url).lower()
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    evidence: list[Evidence] = []
    # A clean URL has no risk evidence.  Keep the score at zero so every displayed
    # L1/L2 point can be traced to a criterion rather than a hidden baseline.
    lexical = 0.0
    intent = 0.0
    evasion = 0.0

    # Layer 0: parsing and protocol abuse. These indicators are especially valuable
    # because they do not depend on reputation feeds or a live fetch.
    raw_host = parsed.hostname or ""
    if raw_host.startswith("xn--") or ".xn--" in raw_host:
        lexical += 0.18
        evidence.append(_e("Tên miền IDN/punycode cần được kiểm tra kỹ vì có thể che ký tự giống nhau.",
                           Severity.HIGH, "punycode_domain", 0.18))
    if parsed.username or parsed.password:
        evasion += 0.30
        evidence.append(_e("URL chứa thông tin đăng nhập trước ký tự @, có thể che đích thật.",
                           Severity.CRITICAL, "embedded_credentials", 0.30))
    if parsed.port and parsed.port not in {80, 443}:
        evasion += 0.08
        evidence.append(_e("URL sử dụng cổng không chuẩn; cần xác minh dịch vụ đích.",
                           Severity.LOW, "nonstandard_port", 0.08))

    # Layer 1: identity and routing deception.
    if signals.brand_mismatch:
        lexical += 0.42
        evidence.append(_e(
            f"Tên thương hiệu xuất hiện trên tên miền không chính chủ ({signals.parts.registrable_domain}).",
            Severity.CRITICAL, "brand_domain_mismatch", 0.42))
    if signals.deceptive_subdomain:
        lexical += 0.25
        evidence.append(_e("Thương hiệu hoặc nhãn 'secure/login' bị đặt ở subdomain để che tên miền thật.",
                           Severity.CRITICAL, "deceptive_subdomain", 0.25))
    if signals.homoglyph:
        lexical += 0.32
        evidence.append(_e("Tên miền có ký tự/dạng viết gần giống thương hiệu (homoglyph).",
                           Severity.CRITICAL, "homoglyph", 0.32))
    # Bắt biến thể gõ sai thương hiệu ngay cả khi không có chữ số/punycode.
    # Ví dụ: vietcombank-login.example hoặc paypa-security.example.
    brand_distance = min_brand_distance(signals.parts.domain_label)
    if 0.0 < brand_distance <= 0.25 and len(signals.parts.domain_label) >= 5:
        lexical += 0.24
        evidence.append(_e(
            "Nhãn tên miền gần giống một thương hiệu đã biết; có thể là biến thể gõ sai để giả mạo.",
            Severity.HIGH,
            "brand_typosquatting",
            0.24,
        ))
    if signals.ip_host:
        lexical += 0.20
        evidence.append(_e("URL dùng địa chỉ IP thay vì tên miền, thường dùng để né nhận diện.",
                           Severity.HIGH, "ip_host", 0.20))
    if signals.risky_tld:
        lexical += 0.12
        evidence.append(_e("Tên miền cấp cao có mức lạm dụng phishing cao hơn trung bình.",
                           Severity.MEDIUM, "risky_tld", 0.12))
    if signals.no_https:
        lexical += 0.10
        evidence.append(_e("Không dùng HTTPS; dữ liệu nhập có thể bị lộ trên đường truyền.",
                           Severity.MEDIUM, "no_https", 0.10))
    if signals.shortlink:
        lexical += 0.10
        evidence.append(_e("Shortlink che giấu đích đến; cần mở rộng redirect trong sandbox.",
                           Severity.MEDIUM, "is_shortlink", 0.10))
    if signals.long_url:
        evasion += 0.05
        evidence.append(_e(
            "URL dài bất thường; cần kiểm tra phần đích và tham số đã được che khuất.",
            Severity.LOW,
            "long_url",
            0.05,
        ))
    if signals.excessive_dots:
        evasion += 0.06
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
        evasion += 0.18
        evidence.append(_e("URL lồng nhiều địa chỉ đích; đây là mẫu chuyển hướng/che giấu phổ biến.",
                           Severity.HIGH, "nested_url_redirect", 0.18))
    if any(key in decoded_rounds for key in ("redirect=", "redirect_uri=", "return_url=", "continue=", "next=", "target=", "url=")):
        evasion += 0.07
        evidence.append(_e("URL có tham số chuyển hướng; đích cuối cần được xác thực trong sandbox.",
                           Severity.LOW, "redirect_parameter", 0.07))
    if matched_sensitive:
        intent += min(0.26, 0.09 * len(matched_sensitive))
        evidence.append(_e("URL nhắm tới dữ liệu nhạy cảm: " + ", ".join(sorted(matched_sensitive)) + ".",
                           Severity.HIGH, "credential_theft_intent", intent))
    if signals.suspicious_keywords:
        # Keep this monotonic: three coordinated lure terms must never contribute
        # less risk than one or two. Cap at three to avoid unlimited accumulation.
        keyword_contribution = 0.12 * min(len(signals.suspicious_keywords), 3)
        intent += keyword_contribution
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
        intent += 0.38
        evidence.append(_e(
            "Tên miền giả/gần giống thương hiệu được kết hợp với lời dụ đăng nhập, "
            "xác minh hoặc thanh toán.",
            Severity.CRITICAL,
            "brand_credential_lure_combination",
            0.38,
        ))
    if signals.dangerous_download:
        intent += 0.14
        evidence.append(_e(
            "URL trỏ trực tiếp tới loại tệp có thể thực thi; không tải hoặc chạy ngoài sandbox.",
            Severity.HIGH,
            "dangerous_download",
            0.14,
        ))
    if signals.disguised_download:
        evasion += 0.72
        evidence.append(_e(
            "Tên tệp dùng đuôi tài liệu giả trước đuôi thực thi (ví dụ PDF.EXE), phù hợp mẫu phát tán mã độc ngụy trang.",
            Severity.CRITICAL,
            "disguised_executable_download",
            0.72,
        ))
    if signals.archive_lure:
        intent += 0.22
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
        evasion += 0.16
        evidence.append(_e(
            "Hosting dùng chung đi kèm dấu hiệu mạo danh/dụ tải; nền tảng không bị coi là độc nếu đứng riêng.",
            Severity.HIGH,
            "shared_hosting_abuse_context",
            0.16,
        ))
    if signals.at_symbol:
        evasion += 0.22
        evidence.append(_e("Ký tự @ có thể làm người dùng hiểu sai đích thực của URL.",
                           Severity.HIGH, "at_symbol", 0.22))
    if signals.percent_encoded or signals.many_delimiters:
        evasion += 0.12
        evidence.append(_e("URL bị mã hóa hoặc phân mảnh bất thường để né kiểm tra trực quan.",
                           Severity.MEDIUM, "url_obfuscation", 0.12))
    if signals.query_param_count >= 5 or len(query_pairs) >= 7:
        evasion += 0.08
        evidence.append(_e("URL chứa số lượng tham số truy vấn bất thường.",
                           Severity.LOW, "excessive_query_parameters", 0.08))
    host_entropy = shannon_entropy(signals.parts.domain_label)
    if len(signals.parts.domain_label) >= 14 and host_entropy >= 3.5:
        evasion += 0.10
        evidence.append(_e("Nhãn tên miền dài, entropy cao; có thể là tên miền sinh tự động.",
                           Severity.MEDIUM, "high_entropy_domain", 0.10))

    rule_score = _clip(lexical + intent + evasion)
    model_value = _clip(float(model_score or 0.0))
    # Không để một dự đoán ML không có bằng chứng hiển thị được tự đẩy URL lên
    # mức cao: điều đó tạo mâu thuẫn giữa tổng điểm và checklist L1/L2. Khi model
    # không được quy tắc nào xác nhận, giữ nó ở mức cần xem xét và đề xuất sandbox.
    uncorroborated_model = rule_score == 0.0 and model_value > 0.0
    if uncorroborated_model:
        score = min(model_value, 0.35)
    else:
        # ML augments the deterministic score but cannot reduce a strong rule verdict.
        score = _clip(max(rule_score, model_value, (rule_score * 0.75) + (model_value * 0.25)))
    uncertain = 0.30 <= score < 0.70
    high_impact = bool(
        matched_sensitive
        or signals.shortlink
        or signals.brand_mismatch
        or signals.dangerous_download
        or signals.archive_lure
        or shared_hosting_abuse
    )
    requires_deep = uncertain or signals.shortlink or (high_impact and score >= 0.45)
    # A very confident model verdict is real evidence and must reach Risk Core v2,
    # which builds criteria from evidence rather than from this score. Below this
    # bar the model stays INFO-only: measured on the frozen holdout, lowering the
    # bar to 0.90 doubles the false-alarm rate (9.27% vs 4.20%) for little gain.
    # The matching override caps the effect at WARN, so the model can draw
    # attention to a URL but can never block one on its own.
    if model_value >= MODEL_HIGH_CONFIDENCE:
        evidence.append(_e(
            "Mô hình phân loại URL rất tự tin đây là trang lừa đảo, dù chưa có dấu hiệu "
            "từ vựng rõ rệt. Đây là tín hiệu cảnh báo, không phải kết luận chắc chắn.",
            Severity.MEDIUM,
            "model_high_confidence_phishing",
            0.20,
        ))
    elif uncorroborated_model:
        evidence.append(_e(
            "Model nhận thấy mẫu cần xem xét nhưng chưa có tín hiệu URL xác thực; không nâng lên mức rủi ro cao nếu chưa chạy sandbox hoặc đối chiếu danh tiếng.",
            Severity.INFO,
            "model_review_recommended",
            0.0,
        ))
    if requires_deep:
        evidence.append(_e("Khuyến nghị sandbox cô lập: mở trang bằng canary tổng hợp, chặn submit và theo dõi redirect/exfiltration.",
                           Severity.INFO, "deep_analysis_recommended", 0.0))
    if not evidence:
        evidence.append(_e("Không phát hiện tín hiệu rủi ro rõ rệt ở lớp phân tích ngoại tuyến.",
                           Severity.INFO, "no_offline_signal", 0.0))
    return URLRiskAssessment(score, evidence, requires_deep, {
        "lexical_identity": _clip(lexical), "credential_intent": _clip(intent), "evasion": _clip(evasion),
    })
