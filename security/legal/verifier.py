"""Deterministic, fail-closed verification for generated Vietnamese legal claims.

The language model is allowed to propose claims and quotes.  This module decides
whether those proposals may be displayed.  It intentionally has no dependency on
the retriever: context records are accepted through a small duck-typed interface.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

LegalAnswerStatus = Literal[
    "answered",
    "need_more_facts",
    "insufficient_legal_basis",
    "conflicting_sources",
    "human_legal_review",
]
ClaimType = Literal[
    "fact",
    "definition",
    "permission",
    "prohibition",
    "obligation",
    "penalty",
    "liability",
    "exception",
    "procedure",
    "recommendation",
]
IssueSeverity = Literal["error", "review", "warning"]


class ClaimEvidence(BaseModel):
    """A quote selected by the model; metadata is deliberately not accepted."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    provision_id: str = Field(min_length=1, max_length=240)
    chunk_id: str = Field(min_length=1, max_length=240)
    quote: str = Field(min_length=8, max_length=8_000)


class GeneratedClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    claim_id: str = Field(min_length=1, max_length=100)
    claim_type: ClaimType
    text: str = Field(min_length=3, max_length=4_000)
    evidence: list[ClaimEvidence] = Field(min_length=1, max_length=8)


class LegalGeneration(BaseModel):
    """Strict model-output contract used before any semantic processing."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    status: LegalAnswerStatus
    claims: list[GeneratedClaim] = Field(default_factory=list, max_length=20)
    missing_facts: list[str] = Field(default_factory=list, max_length=20)
    uncertainties: list[str] = Field(default_factory=list, max_length=20)
    requires_human_review: bool = False

    @model_validator(mode="after")
    def validate_status_payload(self) -> LegalGeneration:
        claim_ids = [claim.claim_id for claim in self.claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("claim_id values must be unique")
        if self.status == "answered" and not self.claims:
            raise ValueError("answered output must contain at least one claim")
        return self


class VerificationIssue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    severity: IssueSeverity
    message: str
    claim_id: str = ""
    chunk_id: str = ""


class VerificationResult(BaseModel):
    """Safe outcome.  Only ``status=answered`` claims may be rendered."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: LegalAnswerStatus
    verified_claims: tuple[GeneratedClaim, ...] = ()
    used_chunk_ids: tuple[str, ...] = ()
    issues: tuple[VerificationIssue, ...] = ()
    requires_human_review: bool = False
    accepted: bool = False


_NORMATIVE_TYPES = {"permission", "prohibition", "obligation", "penalty", "liability"}
_BINDING_WEIGHTS = {"binding", "binding_law", "statutory", "regulation"}
_VERIFIED_TEXT = {
    "verified",
    "human_verified",
    "human-verified",
    "human_verified_against_pdf",
    "verified_against_pdf",
    "approved",
}
_TRUSTED_NATIVE_METHODS = {
    "native_pdf_text",
    "pymupdf_native_text",
    "official_html_text",
    "official_docx_text",
    "docx_text_layer",
}
_CURRENT_STATUSES = {"current", "in_force", "effective"}
_SPACE = re.compile(r"\s+")
_TOKEN = re.compile(r"[0-9A-Za-zÀ-ỹĐđ]+", re.UNICODE)
_DIGIT_TOKEN = re.compile(r"\d+", re.UNICODE)
_STOPWORDS = {
    "ai",
    "bị",
    "bởi",
    "các",
    "cho",
    "có",
    "của",
    "do",
    "đó",
    "được",
    "hay",
    "khi",
    "không",
    "là",
    "mà",
    "một",
    "này",
    "những",
    "phải",
    "theo",
    "thì",
    "trong",
    "trên",
    "từ",
    "và",
    "về",
    "với",
    "việc",
    "người",
    "tổ",
    "chức",
}
_PROHIBITION = re.compile(
    r"\b(?:không được|không có quyền|không cho phép|nghiêm cấm|bị cấm|cấm|"
    r"không hợp pháp|không thể|trái pháp luật|bất hợp pháp|vi phạm pháp luật)\b",
    re.I,
)
_OBLIGATION = re.compile(
    r"\b(?:phải|bắt buộc|có trách nhiệm|nghĩa vụ|có bổn phận|buộc(?: phải)?|cần)\b",
    re.I,
)
_PERMISSION = re.compile(
    r"\b(?:được phép|có quyền|cho phép|được quyền|được|hợp pháp|có thể)\b", re.I
)
_PENALTY = re.compile(r"\b(?:xử phạt|mức phạt|phạt tiền|hình phạt|phạt)\b", re.I)
_LIABILITY = re.compile(r"\b(?:chịu trách nhiệm|bồi thường|trách nhiệm pháp lý)\b", re.I)
_QUALIFIER = re.compile(
    r"\b(?:trong trường hợp|nếu|khi|chỉ|trừ|ngoại trừ|với điều kiện|"
    r"theo điều kiện|tùy thuộc|không áp dụng|tối đa|ít nhất|không quá)\b",
    re.I,
)

# Values which can materially change a legal conclusion must be copied from evidence.
_NUMBER_PATTERNS = (
    re.compile(r"\b\d{1,4}/\d{4}/[A-ZĐ][A-ZĐ0-9-]*\b", re.I),
    re.compile(r"\b(?:điều|khoản|điểm)\s+(?:\d+[a-z]?|[a-zđ])\b", re.I),
    re.compile(r"\b\d+(?:[.,]\d+)*\s*(?:%|phần trăm|đồng|triệu|tỷ)\b", re.I),
    re.compile(r"\b\d+(?:[.,]\d+)*\s*(?:giờ|ngày|tháng|năm)\b", re.I),
    re.compile(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"),
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
    re.compile(r"\bngày\s+\d{1,2}\s+tháng\s+\d{1,2}\s+năm\s+\d{4}\b", re.I),
    re.compile(
        r"\b(?:không|một|hai|ba|bốn|tư|năm|lăm|sáu|bảy|tám|chín|mười|mươi|"
        r"trăm|nghìn|triệu|tỷ)(?:\s+(?:không|một|hai|ba|bốn|tư|năm|lăm|sáu|"
        r"bảy|tám|chín|mười|mươi|trăm|nghìn|triệu|tỷ))*\s+"
        r"(?:giờ|ngày|tháng|năm|phần trăm|đồng|nghìn|triệu|tỷ)\b",
        re.I,
    ),
)


def _normalized(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    # Format controls (zero-width space/joiner, BOM, soft hyphen) must not split
    # safety keywords such as "phải" or "không được".
    text = "".join(character for character in text if unicodedata.category(character) != "Cf")
    return _SPACE.sub(" ", text).strip().casefold()


def _has_non_latin_letters(value: str) -> bool:
    """Reject cross-script homoglyphs in Vietnamese generated claims/quotes."""

    normalized = unicodedata.normalize("NFKC", value)
    for character in normalized:
        if not character.isalpha():
            continue
        if "LATIN" not in unicodedata.name(character, ""):
            return True
    return False


def _has_format_controls(value: str) -> bool:
    return any(unicodedata.category(character) == "Cf" for character in value)


def _field(record: object, *names: str, default: Any = "") -> Any:
    for name in names:
        if isinstance(record, Mapping) and name in record:
            return record[name]
        if hasattr(record, name):
            return getattr(record, name)
    return default


def _evidence_text(record: object) -> str:
    for name in ("full_text", "text", "text_preview"):
        value = _field(record, name, default="")
        if value:
            return str(value)
    return ""


def _parse_date(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _significant_tokens(value: str) -> set[str]:
    return {
        token
        for token in _TOKEN.findall(_normalized(value))
        if len(token) >= 2 and token not in _STOPWORDS and not token.isdigit()
    }


def _material_values(value: str) -> set[str]:
    found: set[str] = set()
    for pattern in _NUMBER_PATTERNS:
        found.update(_normalized(match.group(0)) for match in pattern.finditer(value))
    return found


def _digit_tokens(value: str) -> set[str]:
    return set(_DIGIT_TOKEN.findall(_normalized(value)))


def _provision_matches(citation: ClaimEvidence, record: object) -> bool:
    grounded = {
        _normalized(value)
        for value in (
            _field(record, "provision_id"),
            _field(record, "section"),
            _field(record, "chunk_id"),
        )
        if str(value or "").strip()
    }
    return bool(grounded) and _normalized(citation.provision_id) in grounded


def _canonical_provision_id(record: object) -> str:
    for name in ("provision_id", "section", "chunk_id"):
        value = str(_field(record, name) or "").strip()
        if value:
            return value
    return ""


def _is_binding(record: object) -> bool:
    return _normalized(_field(record, "legal_weight")) in _BINDING_WEIGHTS


def _is_unverified_ocr(record: object) -> bool:
    method = str(_field(record, "extraction_method") or "")
    verification = _normalized(_field(record, "text_verification_status"))
    if verification in _VERIFIED_TEXT:
        return False
    normalized_method = _normalized(method).replace("-", "_").replace(" ", "_")
    # Provenance is allowlisted.  Unknown, blank, OCR, scan and homoglyph-spoofed
    # method names need review rather than silently becoming trusted native text.
    return normalized_method not in _TRUSTED_NATIVE_METHODS


def _quote_omits_qualifier(source: str, quote: str) -> bool:
    """Detect a quote cropped to hide a condition/exception in the same sentence."""

    quote_qualifiers = [match.group(0) for match in _QUALIFIER.finditer(quote)]
    start = 0
    omitted = False
    while True:
        index = source.find(quote, start)
        if index < 0:
            return omitted
        left = max(source.rfind(delimiter, 0, index) for delimiter in (".", ";", "\n"))
        ends = [
            position
            for delimiter in (".", ";", "\n")
            if (position := source.find(delimiter, index + len(quote))) >= 0
        ]
        right = min(ends) if ends else len(source)
        sentence = source[left + 1 : right]
        sentence_qualifiers = [match.group(0) for match in _QUALIFIER.finditer(sentence)]
        if all(
            quote_qualifiers.count(qualifier) >= sentence_qualifiers.count(qualifier)
            for qualifier in set(sentence_qualifiers)
        ):
            return False
        omitted = bool(sentence_qualifiers)
        start = index + 1


def _relevance_issue(claim: GeneratedClaim, quote: str) -> str:
    """Return an explanation for obvious citation laundering/contradiction."""

    claim_tokens = _significant_tokens(claim.text)
    quote_tokens = _significant_tokens(quote)
    overlap = claim_tokens & quote_tokens
    minimum = 1 if len(claim_tokens) <= 3 else 2
    coverage = len(overlap) / max(1, len(claim_tokens))
    # Deterministic verification cannot prove a remote paraphrase.  Generation is
    # therefore expected to keep atomic claim wording close to its exact quote.
    if len(overlap) < minimum or coverage < 0.70:
        return "citation quote has insufficient lexical support for this claim"

    quote_norm = _normalized(quote)
    if claim.claim_type == "permission" and not _PERMISSION.search(quote_norm):
        return "permission claim is not supported by permission language in the quote"
    if claim.claim_type == "prohibition" and not _PROHIBITION.search(quote_norm):
        return "prohibition claim is not supported by prohibition language in the quote"
    if claim.claim_type == "obligation" and not _OBLIGATION.search(quote_norm):
        return "obligation claim is not supported by obligation language in the quote"
    if claim.claim_type == "penalty" and not _PENALTY.search(quote_norm):
        return "penalty claim is not supported by penalty language in the quote"
    if claim.claim_type == "liability" and not _LIABILITY.search(quote_norm):
        return "liability claim is not supported by liability language in the quote"

    claim_prohibits = bool(_PROHIBITION.search(_normalized(claim.text)))
    quote_prohibits = bool(_PROHIBITION.search(quote_norm))
    if claim.claim_type in {"permission", "prohibition"} and claim_prohibits != quote_prohibits:
        return "claim and quote have incompatible negation/polarity"
    return ""


def _inferred_normative_type(text: str) -> str:
    normalized = _normalized(text)
    # Order matters because "không được" also contains the permission token "được".
    for claim_type, pattern in (
        ("prohibition", _PROHIBITION),
        ("penalty", _PENALTY),
        ("liability", _LIABILITY),
        ("obligation", _OBLIGATION),
        ("permission", _PERMISSION),
    ):
        if pattern.search(normalized):
            return claim_type
    return ""


class ClaimVerifier:
    """Verify structured generation against the exact evidence supplied to the model."""

    def verify(
        self,
        payload: Mapping[str, Any] | LegalGeneration,
        evidence: Sequence[object],
        *,
        as_of_date: str,
    ) -> VerificationResult:
        try:
            generation = (
                payload
                if isinstance(payload, LegalGeneration)
                else LegalGeneration.model_validate(payload)
            )
        except ValidationError as exc:
            return self._failure(
                "schema_invalid",
                "Model output does not match the strict legal generation schema: "
                f"{exc.errors(include_url=False)[0].get('msg', 'validation failed')}",
            )

        as_of = _parse_date(as_of_date)
        if as_of is None:
            return self._failure("as_of_date_invalid", "as_of_date must be an ISO calendar date")

        # A safe state proposed by an upstream conflict/fact/sufficiency gate stays safe.
        if generation.status != "answered":
            return VerificationResult(
                status=generation.status,
                issues=(),
                requires_human_review=(
                    generation.requires_human_review
                    or generation.status in {"conflicting_sources", "human_legal_review"}
                ),
                accepted=False,
            )

        by_id: dict[str, object] = {}
        duplicate_ids: set[str] = set()
        for record in evidence:
            chunk_id = str(_field(record, "chunk_id") or "")
            if not chunk_id:
                continue
            if chunk_id in by_id:
                duplicate_ids.add(chunk_id)
            by_id[chunk_id] = record
        if duplicate_ids:
            return self._failure(
                "context_duplicate_id",
                f"Evidence context contains duplicate chunk ids: {', '.join(sorted(duplicate_ids))}",
            )

        issues: list[VerificationIssue] = []
        used_ids: list[str] = []
        review_required = generation.requires_human_review

        for claim in generation.claims:
            if _has_non_latin_letters(claim.text) or _has_format_controls(claim.text):
                issues.append(
                    self._issue(
                        "unsafe_unicode",
                        "error",
                        "Claim contains cross-script letters or format controls that may conceal text",
                        claim,
                    )
                )
            inferred_type = _inferred_normative_type(claim.text)
            if inferred_type and claim.claim_type != inferred_type:
                issues.append(
                    self._issue(
                        "claim_type_mismatch",
                        "error",
                        f"Claim text is {inferred_type} but was labelled {claim.claim_type}",
                        claim,
                    )
                )
            claim_records: list[tuple[ClaimEvidence, object]] = []
            claim_has_binding = False
            trusted_support = False
            trusted_binding_support = False
            for citation in claim.evidence:
                record = by_id.get(citation.chunk_id)
                if record is None:
                    issues.append(
                        self._issue(
                            "unknown_chunk_id",
                            "error",
                            "Citation was not supplied in model context",
                            claim,
                            citation.chunk_id,
                        )
                    )
                    continue

                if not _provision_matches(citation, record):
                    issues.append(
                        self._issue(
                            "unknown_provision_id",
                            "error",
                            "Provision id does not match the cited record's DB section or chunk id",
                            claim,
                            citation.chunk_id,
                        )
                    )
                    continue

                source_text = _normalized(_evidence_text(record))
                quote = _normalized(citation.quote)
                if _has_non_latin_letters(citation.quote) or _has_format_controls(citation.quote):
                    issues.append(
                        self._issue(
                            "unsafe_unicode",
                            "error",
                            "Citation quote contains cross-script letters or format controls",
                            claim,
                            citation.chunk_id,
                        )
                    )
                    continue
                if not source_text or quote not in source_text:
                    issues.append(
                        self._issue(
                            "quote_not_found",
                            "error",
                            "Citation quote is not an exact normalized substring of the evidence",
                            claim,
                            citation.chunk_id,
                        )
                    )
                    continue

                if _quote_omits_qualifier(source_text, quote):
                    issues.append(
                        self._issue(
                            "citation_omits_qualifier",
                            "error",
                            "Citation quote omits a condition or exception from the same sentence",
                            claim,
                            citation.chunk_id,
                        )
                    )
                    continue

                temporal = self._temporal_issue(record, as_of)
                if temporal:
                    issues.append(
                        self._issue(
                            temporal[0],
                            "error",
                            temporal[1],
                            claim,
                            citation.chunk_id,
                        )
                    )
                    continue

                relevance = _relevance_issue(claim, citation.quote)
                if relevance:
                    issues.append(
                        self._issue(
                            "citation_not_relevant",
                            "error",
                            relevance,
                            claim,
                            citation.chunk_id,
                        )
                    )
                    continue

                claim_records.append((citation, record))
                binding = _is_binding(record)
                trusted = not _is_unverified_ocr(record)
                claim_has_binding = claim_has_binding or binding
                trusted_support = trusted_support or trusted
                trusted_binding_support = trusted_binding_support or (binding and trusted)
                if citation.chunk_id not in used_ids:
                    used_ids.append(citation.chunk_id)

            if not claim_records:
                issues.append(
                    self._issue(
                        "claim_without_valid_evidence",
                        "error",
                        "Claim has no evidence that passed deterministic verification",
                        claim,
                    )
                )
                continue

            if claim.claim_type in _NORMATIVE_TYPES and not claim_has_binding:
                issues.append(
                    self._issue(
                        "binding_basis_required",
                        "error",
                        f"{claim.claim_type} claim requires at least one binding legal source",
                        claim,
                    )
                )

            evidence_text = " ".join(citation.quote for citation, _ in claim_records)
            evidence_values = _material_values(evidence_text)
            missing_values = sorted(_material_values(claim.text) - evidence_values)
            if missing_values:
                issues.append(
                    self._issue(
                        "material_value_not_in_evidence",
                        "error",
                        "Claim contains legal number/date/provision absent from its evidence: "
                        + ", ".join(missing_values),
                        claim,
                    )
                )

            missing_digits = sorted(_digit_tokens(claim.text) - _digit_tokens(evidence_text))
            if missing_digits:
                issues.append(
                    self._issue(
                        "digit_not_in_evidence",
                        "error",
                        "Claim contains digit tokens absent from its exact evidence quotes: "
                        + ", ".join(missing_digits),
                        claim,
                    )
                )

            has_trusted_basis = (
                trusted_binding_support if claim.claim_type in _NORMATIVE_TYPES else trusted_support
            )
            if not has_trusted_basis:
                review_required = True
                issues.append(
                    self._issue(
                        "unverified_ocr_sole_basis",
                        "review",
                        "Unverified OCR cannot be the sole basis of an answered claim",
                        claim,
                    )
                )

        if any(issue.severity == "error" for issue in issues):
            return VerificationResult(
                status="insufficient_legal_basis",
                issues=tuple(issues),
                requires_human_review=False,
                accepted=False,
            )
        if review_required or any(issue.severity == "review" for issue in issues):
            return VerificationResult(
                status="human_legal_review",
                issues=tuple(issues),
                requires_human_review=True,
                accepted=False,
            )
        hydrated_claims = tuple(
            claim.model_copy(
                update={
                    "evidence": [
                        citation.model_copy(
                            update={
                                "provision_id": _canonical_provision_id(by_id[citation.chunk_id])
                            }
                        )
                        for citation in claim.evidence
                    ]
                }
            )
            for claim in generation.claims
        )
        return VerificationResult(
            status="answered",
            # The renderer receives only server-canonical provision metadata, never
            # the model's spelling/casing of an otherwise matched identifier.
            verified_claims=hydrated_claims,
            used_chunk_ids=tuple(used_ids),
            issues=tuple(issues),
            requires_human_review=False,
            accepted=True,
        )

    @staticmethod
    def _issue(
        code: str,
        severity: IssueSeverity,
        message: str,
        claim: GeneratedClaim,
        chunk_id: str = "",
    ) -> VerificationIssue:
        return VerificationIssue(
            code=code,
            severity=severity,
            message=message,
            claim_id=claim.claim_id,
            chunk_id=chunk_id,
        )

    @staticmethod
    def _failure(code: str, message: str) -> VerificationResult:
        return VerificationResult(
            status="insufficient_legal_basis",
            issues=(VerificationIssue(code=code, severity="error", message=message),),
            accepted=False,
        )

    @staticmethod
    def _temporal_issue(record: object, as_of: date) -> tuple[str, str] | None:
        status = _normalized(_field(record, "status"))
        if status not in _CURRENT_STATUSES:
            return "source_not_current", "Evidence source is not marked current/in force"
        effective = _parse_date(_field(record, "effective_date"))
        if effective is None:
            return "effective_date_missing", "Evidence has no valid effective date"
        if effective > as_of:
            return "source_not_yet_effective", "Evidence was not effective on as_of_date"
        checked = _parse_date(_field(record, "status_checked_at"))
        if checked is None:
            return "status_check_missing", "Evidence has no genuine status verification date"
        if checked < as_of:
            return "status_check_stale", "Evidence status was not verified through as_of_date"
        return None


def verify_legal_claims(
    payload: Mapping[str, Any] | LegalGeneration,
    evidence: Sequence[object],
    *,
    as_of_date: str,
) -> VerificationResult:
    """Functional entry point for services that do not retain a verifier instance."""

    return ClaimVerifier().verify(payload, evidence, as_of_date=as_of_date)


__all__ = [
    "ClaimEvidence",
    "ClaimVerifier",
    "GeneratedClaim",
    "LegalGeneration",
    "VerificationIssue",
    "VerificationResult",
    "verify_legal_claims",
]
