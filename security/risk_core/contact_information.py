"""Evidence-based contact channel validation for criterion 20."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

ContactStatus = Literal["clean", "suspicious", "not_applicable"]
_EMAIL = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}$", re.I)


@dataclass(frozen=True)
class ContactAssessment:
    status: ContactStatus
    summary: str
    finding_type: str | None = None
    severity: float = 0.0
    quality: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


def _valid_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return 7 <= len(digits) <= 15 and len(set(digits)) >= 3


def _support_href(value: object) -> str:
    if isinstance(value, dict):
        return str(value.get("href") or "")
    return str(value or "")


def assess_contact_information(
    *,
    commercial: bool,
    emails: Iterable[str] = (),
    phones: Iterable[str] = (),
    support_links: Iterable[object] = (),
) -> ContactAssessment:
    if not commercial:
        return ContactAssessment(
            status="not_applicable",
            summary="Verified non-commercial website context.",
        )

    valid_emails = tuple(
        dict.fromkeys(value.strip().casefold() for value in emails if _EMAIL.fullmatch(value.strip()))
    )
    valid_phones = tuple(
        dict.fromkeys(value.strip() for value in phones if value and _valid_phone(value))
    )
    valid_links: list[str] = []
    for item in support_links:
        href = _support_href(item).strip()
        if not href:
            continue
        parsed = urlsplit(href)
        if parsed.scheme in {"mailto", "tel"}:
            valid_links.append(href)
        elif parsed.scheme in {"http", "https"} and re.search(
            r"/(?:contact|support|help)(?:[/#?]|$)", parsed.path.casefold()
        ):
            valid_links.append(href)

    metadata = {
        "valid_email_count": len(valid_emails),
        "valid_phone_count": len(valid_phones),
        "valid_support_link_count": len(valid_links),
    }
    if valid_emails or valid_phones or valid_links:
        return ContactAssessment(
            status="clean",
            summary="The commercial page publishes at least one syntactically valid contact channel.",
            quality=0.85,
            metadata=metadata,
        )
    return ContactAssessment(
        status="suspicious",
        summary="The commercial page publishes no syntactically valid contact channel.",
        finding_type="contact_information_missing_or_invalid",
        severity=0.55,
        quality=0.9,
        metadata=metadata,
    )
