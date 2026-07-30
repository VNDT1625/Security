"""Conservative brand-identity checks for criterion 19."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Literal

from ai.adapters.url_adapter import BRAND_CANONICAL_DOMAINS, parse_url_parts

BrandContentStatus = Literal["clean", "suspicious", "not_checked"]


@dataclass(frozen=True)
class BrandContentAssessment:
    status: BrandContentStatus
    summary: str
    claimed_brand: str = ""
    finding_type: str | None = None
    severity: float = 0.0
    quality: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


def _fold(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", "ignore").decode().casefold()
    return " ".join(re.findall(r"[a-z0-9]+", ascii_value))


def _official(brand: str, host: str) -> bool:
    return any(
        host == domain or host.endswith("." + domain)
        for domain in BRAND_CANONICAL_DOMAINS.get(brand, ())
    )


def assess_brand_content(
    url: str,
    *,
    title: str = "",
    site_name: str = "",
    legal_names: list[str] | tuple[str, ...] = (),
    password_fields: int = 0,
    sensitive_fields: int = 0,
) -> BrandContentAssessment:
    """Detect a strong on-page brand claim hosted outside official domains.

    General article text is deliberately ignored. A claim must come from the
    rendered site name, structured organization identity, or a brand-led title
    coupled with sensitive input fields.
    """

    parts = parse_url_parts(url)
    host = parts.host.casefold()
    site_identity = _fold(site_name)
    legal_identities = tuple(_fold(value) for value in legal_names if value)
    title_identity = _fold(title)
    inspected = bool(site_identity or legal_identities or title_identity)
    if not inspected:
        return BrandContentAssessment(
            status="not_checked",
            summary="The rendered page exposed no stable brand identity for comparison.",
        )

    for brand in BRAND_CANONICAL_DOMAINS:
        brand_folded = _fold(brand)
        exact_site_claim = site_identity == brand_folded
        exact_legal_claim = brand_folded in legal_identities
        title_tokens = title_identity.split()
        title_claim_with_sensitive_input = (
            bool(title_tokens)
            and title_tokens[0] == brand_folded
            and (password_fields > 0 or sensitive_fields > 0)
        )
        if not (
            exact_site_claim
            or exact_legal_claim
            or title_claim_with_sensitive_input
        ):
            continue
        if _official(brand, host):
            return BrandContentAssessment(
                status="clean",
                summary=f"Rendered {brand} identity is hosted on an official domain.",
                claimed_brand=brand,
                metadata={"host": host, "official": True},
            )
        claim_source = (
            "site_name"
            if exact_site_claim
            else "structured_legal_name"
            if exact_legal_claim
            else "title_with_sensitive_input"
        )
        return BrandContentAssessment(
            status="suspicious",
            summary=(
                f"The rendered page claims the {brand} identity on a non-official domain."
            ),
            claimed_brand=brand,
            finding_type="brand_content_impersonation",
            severity=0.7,
            quality=0.9 if exact_site_claim or exact_legal_claim else 0.8,
            metadata={
                "host": host,
                "claimed_brand": brand,
                "claim_source": claim_source,
                "official_domains": list(BRAND_CANONICAL_DOMAINS[brand]),
            },
        )

    return BrandContentAssessment(
        status="clean",
        summary="No supported brand identity was falsely claimed by the rendered page.",
    )
