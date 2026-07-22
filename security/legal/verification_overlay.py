"""Strict, read-only loading for signed OCR verification overlays."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

OVERLAY_SCHEMA_VERSION = "legal-ocr-verification-overlay.v1"
ALLOWED_VERIFICATION_STATUSES = frozenset({"human_verified", "rejected", "needs_correction"})

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_PAYLOAD_KEYS = frozenset(
    {
        "schema_version",
        "corpus",
        "review_input_sha256",
        "record_count",
        "records",
    }
)
_OUTER_KEYS = _PAYLOAD_KEYS | {"integrity", "authentication"}
_CORPUS_KEYS = frozenset({"release_id", "sha256", "verified_through"})
_INTEGRITY_KEYS = frozenset({"algorithm", "canonicalization", "payload_sha256"})
_AUTHENTICATION_KEYS = frozenset({"algorithm", "key_id", "value"})
_RECORD_KEYS = frozenset(
    {
        "text_verification_status",
        "reviewer",
        "reviewed_at",
        "review_notes",
        "source_pdf_sha256",
        "text_sha256",
        "page_start",
        "page_end",
        "source_page_url",
    }
)


class VerificationOverlayError(ValueError):
    """Raised when a configured verification overlay cannot be trusted."""


@dataclass(frozen=True, slots=True)
class VerificationRecord:
    """Human-review decision bound to one immutable corpus chunk."""

    chunk_id: str
    text_verification_status: str
    reviewer: str
    reviewed_at: str
    review_notes: str
    source_pdf_sha256: str
    text_sha256: str
    page_start: int | None
    page_end: int | None
    source_page_url: str

    @property
    def human_verified(self) -> bool:
        return self.text_verification_status == "human_verified"


@dataclass(frozen=True, slots=True)
class VerificationOverlay:
    """Verified overlay metadata and an immutable chunk-to-review mapping."""

    schema_version: str
    corpus_release_id: str
    corpus_sha256: str
    corpus_verified_through: str
    review_input_sha256: str
    signing_key_id: str
    payload_sha256: str
    records: Mapping[str, VerificationRecord]

    def get(self, chunk_id: str) -> VerificationRecord | None:
        return self.records.get(chunk_id)


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _hmac_message(payload: bytes, key_id: str) -> bytes:
    return payload + b"\nkey-id:" + key_id.encode("utf-8")


def _reject_constant(value: str) -> None:
    raise VerificationOverlayError(f"Non-finite JSON number is not allowed: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise VerificationOverlayError(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise VerificationOverlayError(f"Cannot read verification overlay: {path}") from exc
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise VerificationOverlayError("Verification overlay is not valid JSON") from exc
    if not isinstance(value, dict):
        raise VerificationOverlayError("Verification overlay root must be an object")
    return value


def _require_exact_keys(value: Mapping[str, Any], expected: frozenset[str], name: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise VerificationOverlayError(
            f"Invalid {name} fields (missing={missing}, unexpected={unexpected})"
        )


def _require_sha256(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise VerificationOverlayError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def _require_nonempty_string(value: object, name: str, *, max_length: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
        or any(ord(character) < 32 for character in value)
    ):
        raise VerificationOverlayError(f"{name} must be a non-empty normalized string")
    return value


def _require_utc_timestamp(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise VerificationOverlayError(f"{name} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise VerificationOverlayError(f"{name} must be an RFC3339 UTC timestamp") from exc
    normalized = parsed.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    if parsed.utcoffset() != UTC.utcoffset(parsed) or normalized != value:
        raise VerificationOverlayError(f"{name} must be normalized to UTC seconds")
    return value


def _require_date(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise VerificationOverlayError(f"{name} must be an ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise VerificationOverlayError(f"{name} must be an ISO date") from exc
    if parsed.isoformat() != value:
        raise VerificationOverlayError(f"{name} must be a normalized ISO date")
    return value


def _require_page(value: object, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise VerificationOverlayError(f"{name} must be a positive integer or null")
    return value


def _parse_record(chunk_id: str, value: object) -> VerificationRecord:
    if not isinstance(value, dict):
        raise VerificationOverlayError(f"Record {chunk_id!r} must be an object")
    _require_exact_keys(value, _RECORD_KEYS, f"record {chunk_id!r}")

    status = value["text_verification_status"]
    if not isinstance(status, str) or status not in ALLOWED_VERIFICATION_STATUSES:
        raise VerificationOverlayError(f"Record {chunk_id!r} has an invalid verification status")
    reviewer = _require_nonempty_string(value["reviewer"], "reviewer", max_length=200)
    reviewed_at = _require_utc_timestamp(value["reviewed_at"], "reviewed_at")
    notes = value["review_notes"]
    if not isinstance(notes, str) or len(notes) > 4000:
        raise VerificationOverlayError("review_notes must be a string of at most 4000 characters")
    source_pdf_sha256 = _require_sha256(value["source_pdf_sha256"], "source_pdf_sha256")
    text_sha256 = _require_sha256(value["text_sha256"], "text_sha256")
    page_start = _require_page(value["page_start"], "page_start")
    page_end = _require_page(value["page_end"], "page_end")
    if page_start is not None and page_end is not None and page_end < page_start:
        raise VerificationOverlayError("page_end cannot precede page_start")
    source_page_url = value["source_page_url"]
    if not isinstance(source_page_url, str) or len(source_page_url) > 4096:
        raise VerificationOverlayError("source_page_url must be a string")

    return VerificationRecord(
        chunk_id=chunk_id,
        text_verification_status=status,
        reviewer=reviewer,
        reviewed_at=reviewed_at,
        review_notes=notes,
        source_pdf_sha256=source_pdf_sha256,
        text_sha256=text_sha256,
        page_start=page_start,
        page_end=page_end,
        source_page_url=source_page_url,
    )


def load_verification_overlay(
    path: str | Path | None,
    *,
    signing_key: bytes,
    expected_corpus_sha256: str,
    expected_release_id: str,
    expected_signing_key_id: str | None = None,
    required: bool = False,
) -> VerificationOverlay | None:
    """Load and authenticate an OCR review overlay without modifying runtime state.

    ``None`` or a missing file is accepted only when ``required`` is false. Any file
    that exists but fails schema, release binding, checksum, signature, or record
    validation raises :class:`VerificationOverlayError` (fail closed).
    """

    if path is None:
        if required:
            raise VerificationOverlayError("Verification overlay is required")
        return None
    overlay_path = Path(path).expanduser()
    if not overlay_path.is_file():
        if required:
            raise VerificationOverlayError(f"Verification overlay is missing: {overlay_path}")
        return None
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise VerificationOverlayError("Verification overlay signing key must be at least 32 bytes")
    expected_sha = _require_sha256(expected_corpus_sha256, "expected_corpus_sha256")
    expected_release = _require_nonempty_string(
        expected_release_id, "expected_release_id", max_length=256
    )

    outer = _load_json(overlay_path)
    _require_exact_keys(outer, _OUTER_KEYS, "overlay")
    if outer["schema_version"] != OVERLAY_SCHEMA_VERSION:
        raise VerificationOverlayError("Unsupported verification overlay schema_version")

    integrity = outer["integrity"]
    if not isinstance(integrity, dict):
        raise VerificationOverlayError("integrity must be an object")
    _require_exact_keys(integrity, _INTEGRITY_KEYS, "integrity")
    if integrity["algorithm"] != "sha256":
        raise VerificationOverlayError("Unsupported verification overlay integrity algorithm")
    if integrity["canonicalization"] != "json-sort-keys-compact-utf8-v1":
        raise VerificationOverlayError("Unsupported verification overlay canonicalization")

    authentication = outer["authentication"]
    if not isinstance(authentication, dict):
        raise VerificationOverlayError("authentication must be an object")
    _require_exact_keys(authentication, _AUTHENTICATION_KEYS, "authentication")
    if authentication["algorithm"] != "hmac-sha256":
        raise VerificationOverlayError("Unsupported verification overlay signature algorithm")
    signing_key_id = _require_nonempty_string(
        authentication["key_id"], "authentication.key_id", max_length=128
    )
    if expected_signing_key_id is not None and signing_key_id != expected_signing_key_id:
        raise VerificationOverlayError("Verification overlay signing key identity mismatch")

    payload = {key: outer[key] for key in _PAYLOAD_KEYS}
    canonical = _canonical_json(payload)
    actual_payload_sha256 = hashlib.sha256(canonical).hexdigest()
    declared_payload_sha256 = _require_sha256(
        integrity["payload_sha256"], "integrity.payload_sha256"
    )
    if not hmac.compare_digest(declared_payload_sha256, actual_payload_sha256):
        raise VerificationOverlayError("Verification overlay payload checksum mismatch")
    signature_value = _require_sha256(authentication["value"], "authentication.value")
    actual_signature = hmac.new(
        signing_key, _hmac_message(canonical, signing_key_id), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature_value, actual_signature):
        raise VerificationOverlayError("Verification overlay signature mismatch")

    corpus = outer["corpus"]
    if not isinstance(corpus, dict):
        raise VerificationOverlayError("corpus must be an object")
    _require_exact_keys(corpus, _CORPUS_KEYS, "corpus")
    release_id = _require_nonempty_string(corpus["release_id"], "corpus.release_id", max_length=256)
    corpus_sha256 = _require_sha256(corpus["sha256"], "corpus.sha256")
    verified_through = _require_date(corpus["verified_through"], "corpus.verified_through")
    if release_id != expected_release:
        raise VerificationOverlayError("Verification overlay corpus release identity mismatch")
    if not hmac.compare_digest(corpus_sha256, expected_sha):
        raise VerificationOverlayError("Verification overlay corpus SHA-256 mismatch")

    review_input_sha256 = _require_sha256(outer["review_input_sha256"], "review_input_sha256")
    record_count = outer["record_count"]
    if isinstance(record_count, bool) or not isinstance(record_count, int) or record_count < 0:
        raise VerificationOverlayError("record_count must be a non-negative integer")
    raw_records = outer["records"]
    if not isinstance(raw_records, dict):
        raise VerificationOverlayError("records must be an object")
    if record_count != len(raw_records):
        raise VerificationOverlayError("record_count does not match records")

    parsed_records: dict[str, VerificationRecord] = {}
    for raw_chunk_id, value in raw_records.items():
        chunk_id = _require_nonempty_string(raw_chunk_id, "chunk_id", max_length=512)
        parsed_records[chunk_id] = _parse_record(chunk_id, value)

    return VerificationOverlay(
        schema_version=OVERLAY_SCHEMA_VERSION,
        corpus_release_id=release_id,
        corpus_sha256=corpus_sha256,
        corpus_verified_through=verified_through,
        review_input_sha256=review_input_sha256,
        signing_key_id=signing_key_id,
        payload_sha256=declared_payload_sha256,
        records=MappingProxyType(parsed_records),
    )
