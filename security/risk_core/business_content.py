"""Conservative, evidence-based assessments for website criteria 21-28."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

AssessmentStatus = Literal["clean", "suspicious", "not_applicable"]
_EMAIL = re.compile(r"^[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,63})$", re.I)
_FREE_MAIL = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}
_COMMON_SECOND_LEVEL_SUFFIXES = {
    "ac.uk",
    "co.jp",
    "co.kr",
    "co.nz",
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.hk",
    "com.mx",
    "com.sg",
    "com.tr",
    "com.tw",
    "com.vn",
    "edu.vn",
    "gov.uk",
    "gov.vn",
    "net.au",
    "net.cn",
    "net.vn",
    "org.au",
    "org.uk",
    "org.vn",
}
_STREET_MARKERS = re.compile(
    r"\b(?:street|st\.?|road|rd\.?|avenue|ave\.?|boulevard|lane|drive|"
    r"đường|duong|phố|pho|quận|quan|huyện|huyen|phường|phuong|tỉnh|tinh|"
    r"thành phố|thanh pho)\b",
    re.I,
)


@dataclass(frozen=True)
class BusinessAssessment:
    status: AssessmentStatus
    summary: str
    finding_type: str | None = None
    severity: float = 0.0
    quality: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


def _registrable(value: str) -> str:
    host = (urlsplit(value).hostname or value).strip().casefold().rstrip(".")
    parts = host.split(".")
    if len(parts) < 2:
        return host
    suffix = ".".join(parts[-2:])
    if suffix in _COMMON_SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix


def assess_business_email(
    url: str,
    *,
    commercial: bool,
    emails: Iterable[str] = (),
) -> BusinessAssessment:
    if not commercial:
        return BusinessAssessment("not_applicable", "Verified non-commercial website context.")
    domains = []
    for value in emails:
        match = _EMAIL.fullmatch(str(value).strip())
        if match:
            domains.append(match.group(1).casefold().rstrip("."))
    domains = list(dict.fromkeys(domains))
    if not domains:
        return BusinessAssessment(
            "not_applicable",
            "No business email was published; criterion 20 separately checks contact availability.",
        )
    corporate = [domain for domain in domains if _registrable(domain) not in _FREE_MAIL]
    if not corporate:
        return BusinessAssessment(
            "not_applicable",
            "Only public mailbox providers were observed; mailbox ownership cannot be verified here.",
            metadata={"email_domains": domains},
        )
    site_domain = _registrable(url)
    aligned = [domain for domain in corporate if _registrable(domain) == site_domain]
    metadata = {
        "site_domain": site_domain,
        "corporate_email_domains": corporate,
        "aligned_domains": aligned,
    }
    if aligned:
        return BusinessAssessment(
            "clean",
            "At least one published business email uses the website's registrable domain.",
            quality=0.9,
            metadata=metadata,
        )
    return BusinessAssessment(
        "suspicious",
        "Published corporate-style email domains do not match the website's registrable domain.",
        "business_email_domain_mismatch",
        0.55,
        0.85,
        metadata,
    )


def assess_business_address(
    *,
    commercial: bool,
    addresses: Iterable[str] = (),
) -> BusinessAssessment:
    if not commercial:
        return BusinessAssessment("not_applicable", "Verified non-commercial website context.")
    candidates = [re.sub(r"\s+", " ", str(value)).strip(" ,;") for value in addresses]
    candidates = [value for value in dict.fromkeys(candidates) if 10 <= len(value) <= 300]
    plausible = [
        value
        for value in candidates
        if re.search(r"\d", value)
        and (_STREET_MARKERS.search(value) or value.count(",") >= 2)
    ]
    metadata = {"candidate_count": len(candidates), "plausible_count": len(plausible)}
    if plausible:
        return BusinessAssessment(
            "clean",
            "The page publishes a syntactically plausible business address; physical existence is not verified.",
            quality=0.75,
            metadata=metadata,
        )
    return BusinessAssessment(
        "suspicious",
        "The commercial page does not publish a complete, syntactically plausible business address.",
        "business_address_not_published",
        0.45,
        0.85,
        metadata,
    )


def assess_legal_identity(
    *,
    commercial: bool,
    legal_names: Iterable[str] = (),
    business_ids: Iterable[str] = (),
) -> BusinessAssessment:
    if not commercial:
        return BusinessAssessment("not_applicable", "Verified non-commercial website context.")
    names = [str(value).strip() for value in legal_names if len(str(value).strip()) >= 3]
    identifiers = [str(value).strip() for value in business_ids if len(str(value).strip()) >= 5]
    metadata = {"legal_name_count": len(names), "business_id_count": len(identifiers)}
    if names or identifiers:
        return BusinessAssessment(
            "clean",
            "The page publishes a legal name or business identifier; registry validity is not verified.",
            quality=0.75,
            metadata=metadata,
        )
    return BusinessAssessment(
        "suspicious",
        "The commercial page publishes no identifiable legal entity or business identifier.",
        "missing_legal_identity",
        0.5,
        0.85,
        metadata,
    )


def assess_privacy_policy(
    *,
    collects_sensitive_data: bool,
    privacy_links: Iterable[str] = (),
) -> BusinessAssessment:
    if not collects_sensitive_data:
        return BusinessAssessment(
            "not_applicable",
            "No sensitive-data collection was observed on the inspected page.",
        )
    links = [str(value).strip() for value in privacy_links if str(value).strip()]
    if links:
        return BusinessAssessment(
            "clean",
            "A dedicated privacy-policy link is published near the inspected page.",
            quality=0.9,
            metadata={"policy_link_count": len(links)},
        )
    return BusinessAssessment(
        "suspicious",
        "Sensitive-data collection was observed without a discoverable privacy-policy link.",
        "privacy_policy_link_missing",
        0.5,
        0.95,
    )


def assess_terms_refund(
    *,
    commercial: bool,
    terms_links: Iterable[str] = (),
    refund_links: Iterable[str] = (),
) -> BusinessAssessment:
    if not commercial:
        return BusinessAssessment("not_applicable", "Verified non-commercial website context.")
    terms = [str(value).strip() for value in terms_links if str(value).strip()]
    refunds = [str(value).strip() for value in refund_links if str(value).strip()]
    if terms or refunds:
        return BusinessAssessment(
            "clean",
            "A dedicated terms, returns, or refund-policy link is published.",
            quality=0.9,
            metadata={"terms_link_count": len(terms), "refund_link_count": len(refunds)},
        )
    return BusinessAssessment(
        "suspicious",
        "The commercial page has no discoverable terms, returns, or refund-policy link.",
        "transaction_policy_link_missing",
        0.45,
        0.95,
    )


def assess_content_quality(
    *,
    word_count: int,
    unique_word_ratio: float | None,
    placeholder_hits: Iterable[str] = (),
) -> BusinessAssessment:
    hits = list(dict.fromkeys(str(value) for value in placeholder_hits if str(value)))
    if word_count < 20:
        return BusinessAssessment(
            "not_applicable",
            "Too little visible text was available for a reliable content-quality check.",
        )
    repetitive = word_count >= 80 and unique_word_ratio is not None and unique_word_ratio < 0.18
    if len(hits) >= 2 or repetitive:
        return BusinessAssessment(
            "suspicious",
            "The page contains multiple placeholder markers or extremely repetitive visible text.",
            "low_quality_or_template_content",
            0.45,
            0.85,
            {
                "word_count": word_count,
                "unique_word_ratio": unique_word_ratio,
                "placeholder_hits": hits,
            },
        )
    return BusinessAssessment(
        "clean",
        "No strong placeholder or extreme-repetition pattern was found in visible text.",
        quality=0.8,
        metadata={"word_count": word_count, "unique_word_ratio": unique_word_ratio},
    )


def assess_promotion_claim(max_discount_percent: int | None) -> BusinessAssessment:
    if max_discount_percent is None:
        return BusinessAssessment(
            "not_applicable",
            "No explicit percentage discount claim was observed; no market-price baseline was inferred.",
        )
    if max_discount_percent >= 90:
        return BusinessAssessment(
            "suspicious",
            "The page explicitly claims an extreme discount of at least 90%; sale legitimacy is not inferred.",
            "extreme_discount_claim",
            0.4,
            1.0,
            {"max_discount_percent": max_discount_percent},
        )
    return BusinessAssessment(
        "clean",
        "The observed discount claim is below the conservative extreme-claim threshold.",
        quality=1.0,
        metadata={"max_discount_percent": max_discount_percent},
    )


def assess_coercive_content(
    *,
    urgency_hits: Iterable[str] = (),
    sensitive_context: bool,
    transaction_context: bool,
    external_form: bool,
) -> BusinessAssessment:
    hits = list(dict.fromkeys(str(value) for value in urgency_hits if str(value)))
    if not hits:
        return BusinessAssessment("clean", "No configured coercive phrase was observed.", quality=0.85)
    coupled = sensitive_context or transaction_context or external_form
    if not coupled:
        return BusinessAssessment(
            "clean",
            "Urgency wording was present without a sensitive-data, payment, or cross-origin form action.",
            quality=0.75,
            metadata={"urgency_hits": hits},
        )
    return BusinessAssessment(
        "suspicious",
        "Urgency or threat language is coupled with a sensitive-data, payment, or external-form action.",
        "coercive_action_context",
        0.7,
        0.95,
        {"urgency_hits": hits},
    )
