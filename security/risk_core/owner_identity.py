"""Conservative owner-identity comparison for Risk Core criterion 3.

The detector deliberately does not treat private/redacted WHOIS data as risk.
It only reports a conflict when a public organizational registrant can be
compared with a clear, internally consistent legal identity published by the
website.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

OwnerIdentityStatus = Literal["clean", "suspicious", "not_applicable", "not_checked"]

_LEGAL_SUFFIXES = {
    "ag",
    "co",
    "company",
    "corp",
    "corporation",
    "gmbh",
    "inc",
    "incorporated",
    "jsc",
    "limited",
    "llc",
    "ltd",
    "plc",
    "sa",
    "sas",
    "tnhh",
}
_ORGANIZATION_MARKERS = _LEGAL_SUFFIXES | {
    "business",
    "company",
    "cong",
    "corporate",
    "doanh",
    "enterprise",
    "group",
    "nghiep",
    "organization",
    "tap",
    "ty",
}
_GENERIC_IDENTITY_WORDS = _LEGAL_SUFFIXES | {
    "and",
    "business",
    "cong",
    "doanh",
    "enterprise",
    "group",
    "nghiep",
    "organization",
    "services",
    "service",
    "tap",
    "the",
    "ty",
}
_PRIVACY_PHRASES = {
    "contact privacy",
    "data protected",
    "domains by proxy",
    "identity protection service",
    "not disclosed",
    "privacy guardian",
    "privacy protect",
    "privacy protected",
    "private person",
    "redacted for privacy",
    "registration private",
    "whois privacy",
    "whoisguard protected",
    "withheld for privacy",
}


@dataclass(frozen=True)
class OwnerIdentityEvidence:
    """Portable evidence contract consumed by the Risk Core snapshot adapter."""

    status: OwnerIdentityStatus
    summary: str
    finding_type: str = "owner_identity_check"
    source: str = "cross_source_identity"
    severity: float = 0.0
    quality: float = 0.0
    metadata: tuple[tuple[str, object], ...] = ()

    def as_observation(self) -> dict[str, object]:
        return {
            "status": self.status,
            "summary": self.summary,
            "finding_type": self.finding_type,
            "source": self.source,
            "severity": self.severity,
            "quality": self.quality,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class OwnerIdentityAssessment:
    status: OwnerIdentityStatus
    public_registrant: str | None
    declared_legal_names: tuple[str, ...]
    matched_legal_name: str | None
    confidence: float
    evidence: tuple[OwnerIdentityEvidence, ...]

    @property
    def conflict(self) -> bool:
        return self.status == "suspicious"

    def as_risk_snapshot(self) -> dict[str, dict[str, object]]:
        """Return the shape accepted by ``add_structured_snapshot``."""

        return {"domain_owner": self.evidence[0].as_observation()}


def assess_owner_identity(
    public_registrant: str | None,
    *,
    page_legal_names: Iterable[str | None] = (),
    structured_legal_names: Iterable[str | None] = (),
) -> OwnerIdentityAssessment:
    """Compare a public registrant with website-declared legal identities.

    ``page_legal_names`` must contain explicit legal-owner declarations (for
    example a legal notice or copyright owner), not inferred brands or page
    titles. ``structured_legal_names`` is intended for schema.org Organization
    or LocalBusiness names extracted from JSON-LD.
    """

    registrant = _clean_name(public_registrant)
    page_names = _unique_names(page_legal_names)
    structured_names = _unique_names(structured_legal_names)
    declared_names = _merge_equivalent_names((*structured_names, *page_names))

    if not registrant or _is_privacy_identity(registrant):
        return _assessment(
            "not_applicable",
            None,
            declared_names,
            summary="Registrant identity is not public or is privacy-redacted.",
        )

    if not declared_names:
        return _assessment(
            "not_checked",
            registrant,
            (),
            summary="The website did not publish a legal organization identity that can be compared.",
        )

    # Multiple incompatible legal identities make the page itself ambiguous.
    # Do not turn that ambiguity into an owner-conflict accusation.
    if not _identities_are_consistent(declared_names):
        return _assessment(
            "not_checked",
            registrant,
            declared_names,
            summary="The website publishes incompatible legal identities, so owner comparison is inconclusive.",
        )

    matched_name = next(
        (name for name in declared_names if _same_identity(registrant, name)),
        None,
    )
    if matched_name:
        quality = 0.9 if structured_names else 0.82
        return _assessment(
            "clean",
            registrant,
            declared_names,
            matched_name=matched_name,
            confidence=quality,
            summary="Public registrant and website legal identity are consistent.",
        )

    canonical = declared_names[0]
    if not _looks_like_organization(registrant) or not _looks_like_organization(canonical):
        return _assessment(
            "not_checked",
            registrant,
            declared_names,
            summary="Published names are insufficient to establish two organizational legal identities.",
        )

    quality = 0.88 if structured_names else 0.8
    evidence = OwnerIdentityEvidence(
        status="suspicious",
        finding_type="owner_identity_conflict",
        source="cross_source_identity",
        severity=0.65,
        quality=quality,
        summary="Public organizational registrant conflicts with the website's declared legal identity.",
        metadata=(
            ("public_registrant", registrant),
            ("declared_legal_names", declared_names),
            ("comparison", "normalized_legal_identity_mismatch"),
        ),
    )
    return OwnerIdentityAssessment(
        status="suspicious",
        public_registrant=registrant,
        declared_legal_names=declared_names,
        matched_legal_name=None,
        confidence=quality,
        evidence=(evidence,),
    )


def _assessment(
    status: OwnerIdentityStatus,
    registrant: str | None,
    names: tuple[str, ...],
    *,
    matched_name: str | None = None,
    confidence: float = 0.0,
    summary: str,
) -> OwnerIdentityAssessment:
    evidence = OwnerIdentityEvidence(
        status=status,
        summary=summary,
        quality=confidence,
        metadata=(
            ("public_registrant", registrant),
            ("declared_legal_names", names),
        ),
    )
    return OwnerIdentityAssessment(
        status=status,
        public_registrant=registrant,
        declared_legal_names=names,
        matched_legal_name=matched_name,
        confidence=confidence,
        evidence=(evidence,),
    )


def _clean_name(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(str(value).split()).strip(" ,;|")
    return cleaned or None


def _unique_names(values: Iterable[str | None]) -> tuple[str, ...]:
    names: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = _clean_name(value)
        if not cleaned or _is_privacy_identity(cleaned):
            continue
        key = _fold(cleaned)
        if key not in seen:
            seen.add(key)
            names.append(cleaned)
    return tuple(names)


def _fold(value: str) -> str:
    value = value.replace("Đ", "D").replace("đ", "d")
    folded = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    return " ".join(re.findall(r"[a-z0-9]+", folded.casefold()))


def _all_tokens(value: str) -> tuple[str, ...]:
    return tuple(_fold(value).split())


def _identity_tokens(value: str) -> frozenset[str]:
    return frozenset(
        token
        for token in _all_tokens(value)
        if len(token) > 1 and token not in _GENERIC_IDENTITY_WORDS
    )


def _is_privacy_identity(value: str) -> bool:
    folded = _fold(value)
    return (
        folded in {"redacted", "private", "privacy", "unknown", "not available"}
        or any(phrase in folded for phrase in _PRIVACY_PHRASES)
    )


def _looks_like_organization(value: str) -> bool:
    tokens = set(_all_tokens(value))
    return bool(tokens & _ORGANIZATION_MARKERS)


def _same_identity(left: str, right: str) -> bool:
    left_tokens = _identity_tokens(left)
    right_tokens = _identity_tokens(right)
    if not left_tokens or not right_tokens:
        return _fold(left) == _fold(right)
    overlap = left_tokens & right_tokens
    if overlap and (
        overlap == left_tokens
        or overlap == right_tokens
        or len(overlap) / len(left_tokens | right_tokens) >= 0.5
    ):
        return True

    # Keep words such as "Business" in an acronym (IBM), while still dropping
    # legal suffixes such as Corporation/LLC.
    left_ordered = tuple(
        token for token in _all_tokens(left) if token not in _LEGAL_SUFFIXES
    )
    right_ordered = tuple(
        token for token in _all_tokens(right) if token not in _LEGAL_SUFFIXES
    )
    left_acronym = "".join(token[0] for token in left_ordered)
    right_acronym = "".join(token[0] for token in right_ordered)
    return (
        len(left_acronym) >= 2
        and left_acronym in right_tokens
        or len(right_acronym) >= 2
        and right_acronym in left_tokens
    )


def _merge_equivalent_names(names: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    for name in names:
        if not any(_same_identity(name, existing) for existing in result):
            result.append(name)
    return tuple(result)


def _identities_are_consistent(names: tuple[str, ...]) -> bool:
    return len(names) <= 1 or all(_same_identity(names[0], name) for name in names[1:])
