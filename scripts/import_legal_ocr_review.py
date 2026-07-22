"""Validate OCR reviews and publish an integrity-hashed sidecar overlay."""

# ruff: noqa: E402 -- direct script execution needs the repository root on sys.path.

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from security.legal.corpus import inspect_corpus, sha256_file

DEFAULT_DB_PATH = REPOSITORY_ROOT / "data" / "legal_rag" / "rag.sqlite3"
QUEUE_SCHEMA_VERSION = "legal-ocr-review-queue.v1"
OVERLAY_SCHEMA_VERSION = "legal-ocr-verification-overlay.v1"
ALLOWED_STATUSES = {"human_verified", "rejected", "needs_correction"}
QUEUE_HASH_ALGORITHM = "sha256"
CANONICALIZATION = "json-sort-keys-compact-utf8-v1"

_REVIEW_FIELDS = {"review_status", "reviewer", "reviewed_at", "review_notes"}
_QUEUE_FIELDS = {
    "schema_version",
    "corpus_sha256",
    "corpus_release_id",
    "chunk_id",
    "document_id",
    "title",
    "document_number",
    "jurisdiction",
    "legal_weight",
    "retrieval_default",
    "benchmark_gold",
    "benchmark_max_relevance",
    "benchmark_case_ids",
    "extraction_method",
    "section",
    "page_start",
    "page_end",
    "source_page_url",
    "source_file_url",
    "source_pdf_sha256",
    "text_sha256",
    "text",
    "queue_position",
    "queue_hash_algorithm",
    "queue_record_sha256",
    *_REVIEW_FIELDS,
}

_IMMUTABLE_FIELDS = (
    "document_id",
    "title",
    "document_number",
    "jurisdiction",
    "legal_weight",
    "retrieval_default",
    "extraction_method",
    "section",
    "page_start",
    "page_end",
    "source_page_url",
    "source_file_url",
    "source_pdf_sha256",
    "text",
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _queue_record_sha256(record: dict[str, Any]) -> str:
    immutable = {
        key: value
        for key, value in record.items()
        if key not in {*_REVIEW_FIELDS, "queue_record_sha256"}
    }
    return hashlib.sha256(_canonical_json(immutable)).hexdigest()


def _hmac_message(payload: bytes, key_id: str) -> bytes:
    return payload + b"\nkey-id:" + key_id.encode("utf-8")


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=2.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _is_ocr_method(value: object) -> bool:
    normalized = str(value or "").casefold()
    return any(token in normalized for token in ("ocr", "scan", "tesseract"))


def _normalize_reviewed_at(value: object) -> str:
    raw = str(value or "")
    if not raw.endswith("Z"):
        raise ValueError("reviewed_at must be an RFC3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("reviewed_at must be a valid RFC3339 timestamp") from exc
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("reviewed_at must use UTC")
    return parsed.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _load_reviews(path: Path) -> list[dict[str, Any]]:
    reviews: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw_line.strip():
            continue
        try:
            value = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid review JSON at line {line_number}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"Review line {line_number} must be a JSON object")
        reviews.append(value)
    if not reviews:
        raise ValueError("Review input is empty")
    return reviews


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing overlay: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with staging.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staging, path)
    finally:
        staging.unlink(missing_ok=True)


def verify_overlay(path: str | Path, key: bytes) -> bool:
    """Verify SHA-256 integrity and the optional-keyed HMAC authentication tag."""

    if len(key) < 32:
        return False
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        integrity = value.pop("integrity")
        authentication = value.pop("authentication")
        payload = _canonical_json(value)
        actual_hash = hashlib.sha256(payload).hexdigest()
        key_id = str(authentication.get("key_id", ""))
        actual_signature = hmac.new(key, _hmac_message(payload, key_id), hashlib.sha256).hexdigest()
        return (
            integrity.get("algorithm") == "sha256"
            and integrity.get("canonicalization") == CANONICALIZATION
            and authentication.get("algorithm") == "hmac-sha256"
            and bool(key_id.strip())
            and hmac.compare_digest(str(integrity.get("payload_sha256", "")), actual_hash)
            and hmac.compare_digest(str(authentication.get("value", "")), actual_signature)
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


def import_reviews(
    db_path: str | Path,
    reviews_path: str | Path,
    output_path: str | Path,
    *,
    signing_key_path: str | Path,
    key_id: str,
    manifest_path: str | Path | None = None,
    require_manifest: bool = False,
) -> dict[str, Any]:
    """Validate queue rows and publish a hashed, HMAC-authenticated overlay."""

    db = Path(db_path).expanduser().resolve()
    reviews_file = Path(reviews_path).expanduser().resolve()
    output = Path(output_path).expanduser().resolve()
    key_file = Path(signing_key_path).expanduser().resolve()
    manifest = Path(manifest_path).expanduser().resolve() if manifest_path else None
    protected = {db, reviews_file, key_file, manifest}
    if output in protected:
        raise ValueError("Overlay output must not overwrite an input artifact")
    if not key_id.strip() or len(key_id) > 128:
        raise ValueError("key_id must be non-empty and at most 128 characters")
    key = key_file.read_bytes()
    if len(key) < 32:
        raise ValueError("Signing key must contain at least 32 bytes")

    health = inspect_corpus(db, manifest_path=manifest, require_manifest=require_manifest)
    if not health.ready:
        raise ValueError(f"Corpus validation failed: {', '.join(health.reason_codes)}")
    reviews = _load_reviews(reviews_file)

    with _connect(db) as connection:
        rows = {
            str(row["chunk_id"]): dict(row)
            for row in connection.execute("SELECT * FROM chunks").fetchall()
        }

    overlay_records: dict[str, dict[str, Any]] = {}
    for review in reviews:
        if set(review) != _QUEUE_FIELDS:
            missing = sorted(_QUEUE_FIELDS - set(review))
            unknown = sorted(set(review) - _QUEUE_FIELDS)
            raise ValueError(f"Review queue fields changed (missing={missing}, unknown={unknown})")
        if review.get("schema_version") != QUEUE_SCHEMA_VERSION:
            raise ValueError("Unknown review queue schema_version")
        chunk_id = str(review.get("chunk_id") or "")
        if not chunk_id or chunk_id not in rows:
            raise ValueError(f"Unknown chunk_id: {chunk_id}")
        if chunk_id in overlay_records:
            raise ValueError(f"Duplicate chunk_id: {chunk_id}")
        row = rows[chunk_id]
        if not _is_ocr_method(row.get("extraction_method")):
            raise ValueError(f"Chunk is not OCR-derived: {chunk_id}")
        if str(review.get("corpus_sha256", "")).casefold() != health.snapshot.sha256.casefold():
            raise ValueError(f"Corpus hash mismatch for chunk: {chunk_id}")
        if str(review.get("corpus_release_id", "")) != health.snapshot.release_id:
            raise ValueError(f"Corpus release mismatch for chunk: {chunk_id}")
        if review.get("queue_hash_algorithm") != QUEUE_HASH_ALGORITHM:
            raise ValueError(f"Unknown queue hash algorithm for chunk: {chunk_id}")

        for field in _IMMUTABLE_FIELDS:
            expected: object = row.get(field)
            actual: object = review.get(field)
            if field in {"source_pdf_sha256"}:
                expected = str(expected or "").casefold()
                actual = str(actual or "").casefold()
            elif field == "retrieval_default":
                expected = bool(expected)
                actual = actual if isinstance(actual, bool) else None
            elif field in {"page_start", "page_end"}:
                pass
            else:
                expected = str(expected or "")
                actual = str(actual or "")
            if actual != expected:
                raise ValueError(f"Tampered immutable field {field!r} for chunk: {chunk_id}")

        text = str(row.get("text") or "")
        expected_text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if str(review.get("text_sha256", "")).casefold() != expected_text_hash:
            raise ValueError(f"Text hash mismatch for chunk: {chunk_id}")
        expected_queue_hash = _queue_record_sha256(review)
        if not hmac.compare_digest(
            str(review.get("queue_record_sha256", "")).casefold(),
            expected_queue_hash,
        ):
            raise ValueError(f"Queue record hash mismatch for chunk: {chunk_id}")
        status = str(review.get("review_status") or "")
        if status not in ALLOWED_STATUSES:
            raise ValueError(f"Invalid or pending review_status for chunk: {chunk_id}")
        reviewer = str(review.get("reviewer") or "").strip()
        if not reviewer or len(reviewer) > 200:
            raise ValueError(f"Invalid reviewer for chunk: {chunk_id}")
        reviewed_at = _normalize_reviewed_at(review.get("reviewed_at"))
        notes = review.get("review_notes", "")
        if not isinstance(notes, str) or len(notes) > 4000:
            raise ValueError(f"Invalid review_notes for chunk: {chunk_id}")

        overlay_records[chunk_id] = {
            "text_verification_status": status,
            "reviewer": reviewer,
            "reviewed_at": reviewed_at,
            "review_notes": notes,
            "source_pdf_sha256": str(row.get("source_pdf_sha256") or "").casefold(),
            "text_sha256": expected_text_hash,
            "page_start": row.get("page_start"),
            "page_end": row.get("page_end"),
            "source_page_url": str(row.get("source_page_url") or ""),
        }

    payload: dict[str, Any] = {
        "schema_version": OVERLAY_SCHEMA_VERSION,
        "corpus": {
            "release_id": health.snapshot.release_id,
            "sha256": health.snapshot.sha256,
            "verified_through": health.snapshot.verified_through,
        },
        "review_input_sha256": sha256_file(reviews_file),
        "record_count": len(overlay_records),
        "records": dict(sorted(overlay_records.items())),
    }
    canonical = _canonical_json(payload)
    overlay = {
        **payload,
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": CANONICALIZATION,
            "payload_sha256": hashlib.sha256(canonical).hexdigest(),
        },
        "authentication": {
            "algorithm": "hmac-sha256",
            "key_id": key_id.strip(),
            "value": hmac.new(
                key,
                _hmac_message(canonical, key_id.strip()),
                hashlib.sha256,
            ).hexdigest(),
        },
    }
    _write_new_json(output, overlay)
    return {
        "schema_version": OVERLAY_SCHEMA_VERSION,
        "corpus_sha256": health.snapshot.sha256,
        "output": str(output),
        "record_count": len(overlay_records),
        "payload_sha256": overlay["integrity"]["payload_sha256"],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--reviews", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--signing-key-file", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--require-manifest", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = import_reviews(
            args.db,
            args.reviews,
            args.output,
            signing_key_path=args.signing_key_file,
            key_id=args.key_id,
            manifest_path=args.manifest,
            require_manifest=args.require_manifest,
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        _parser().error(str(exc))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
