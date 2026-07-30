"""Conservative cross-source checks for criterion 4 (domain registrar)."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

RegistrarStatus = Literal["clean", "conflict", "unavailable"]

_LEGAL_SUFFIXES = {
    "co",
    "company",
    "corp",
    "corporation",
    "gmbh",
    "inc",
    "incorporated",
    "limited",
    "llc",
    "ltd",
    "registrar",
    "sa",
    "sas",
}


@dataclass(frozen=True)
class RegistrarAssessment:
    status: RegistrarStatus
    names: tuple[str, ...]
    summary: str


def _identity_tokens(value: str) -> frozenset[str]:
    folded = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    tokens = {
        token
        for token in re.findall(r"[a-z0-9]+", folded.casefold())
        if len(token) > 1 and token not in _LEGAL_SUFFIXES
    }
    return frozenset(tokens)


def _same_registrar(left: str, right: str) -> bool:
    left_tokens = _identity_tokens(left)
    right_tokens = _identity_tokens(right)
    if not left_tokens or not right_tokens:
        return left.strip().casefold() == right.strip().casefold()
    overlap = left_tokens & right_tokens
    return bool(overlap) and (
        overlap == left_tokens
        or overlap == right_tokens
        or len(overlap) / len(left_tokens | right_tokens) >= 0.5
    )


def assess_registrar_identity(values: Iterable[str | None]) -> RegistrarAssessment:
    """Compare registrar identities returned by independent registration sources.

    A single published identity is a completed clean check. Missing public data is
    unavailable, not suspicious. A conflict requires at least two non-empty,
    independently collected names that cannot be reconciled after normalization.
    """

    names = tuple(dict.fromkeys(value.strip() for value in values if value and value.strip()))
    if not names:
        return RegistrarAssessment(
            status="unavailable",
            names=(),
            summary="No registration source published a registrar identity.",
        )
    anchor = names[0]
    conflicts = tuple(name for name in names[1:] if not _same_registrar(anchor, name))
    if conflicts:
        return RegistrarAssessment(
            status="conflict",
            names=names,
            summary="Independent registration sources returned conflicting registrar identities.",
        )
    return RegistrarAssessment(
        status="clean",
        names=names,
        summary="Registration sources consistently identify the domain registrar.",
    )
