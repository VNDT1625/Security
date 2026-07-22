from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from scripts.export_legal_ocr_review_queue import export_queue
from scripts.import_legal_ocr_review import import_reviews
from security.legal.verification_overlay import (
    OVERLAY_SCHEMA_VERSION,
    VerificationOverlayError,
    load_verification_overlay,
)

KEY = b"verification-overlay-test-key-32-bytes"
CORPUS_SHA = "a" * 64
RELEASE_ID = "vn-legal-2026-07-22.1"
KEY_ID = "legal-review-2026-01"


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _record(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "text_verification_status": "human_verified",
        "reviewer": "legal-reviewer@example.test",
        "reviewed_at": "2026-07-22T08:30:00Z",
        "review_notes": "Đã đối chiếu PDF chính thức.",
        "source_pdf_sha256": "b" * 64,
        "text_sha256": "c" * 64,
        "page_start": 12,
        "page_end": 12,
        "source_page_url": "https://vanban.chinhphu.vn/example",
    }
    value.update(updates)
    return value


def _overlay(*, records: dict[str, object] | None = None, **updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": OVERLAY_SCHEMA_VERSION,
        "corpus": {
            "release_id": RELEASE_ID,
            "sha256": CORPUS_SHA,
            "verified_through": "2026-07-22",
        },
        "review_input_sha256": "d" * 64,
        "record_count": 1,
        "records": records if records is not None else {"chunk-1": _record()},
    }
    payload.update(updates)
    canonical = _canonical(payload)
    return {
        **payload,
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": "json-sort-keys-compact-utf8-v1",
            "payload_sha256": hashlib.sha256(canonical).hexdigest(),
        },
        "authentication": {
            "algorithm": "hmac-sha256",
            "key_id": KEY_ID,
            "value": hmac.new(
                KEY, canonical + b"\nkey-id:" + KEY_ID.encode(), hashlib.sha256
            ).hexdigest(),
        },
    }


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _load(path: Path, **updates: object):
    arguments = {
        "signing_key": KEY,
        "expected_corpus_sha256": CORPUS_SHA,
        "expected_release_id": RELEASE_ID,
        "expected_signing_key_id": KEY_ID,
        **updates,
    }
    return load_verification_overlay(path, **arguments)


def _build_importer_corpus(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE chunks (
          chunk_id TEXT PRIMARY KEY, document_id TEXT NOT NULL, title TEXT NOT NULL,
          document_number TEXT, document_type TEXT, jurisdiction TEXT, authority TEXT,
          legal_weight TEXT, status TEXT, effective_date TEXT, status_checked_at TEXT,
          retrieval_default INTEGER NOT NULL, language TEXT, topics TEXT, section TEXT,
          page_start INTEGER, page_end INTEGER, source_page_url TEXT,
          source_file_url TEXT, source_pdf_sha256 TEXT, extraction_method TEXT,
          text TEXT NOT NULL
        );
        CREATE VIRTUAL TABLE chunks_fts USING fts5(
          chunk_id UNINDEXED, title, document_number, topics, section, text
        );
        """
    )
    row = (
        "ocr-1",
        "doc-1",
        "Luật A",
        "01/2026/QH15",
        "law",
        "VN",
        "Quốc hội",
        "binding",
        "current",
        "2026-01-01",
        "2026-07-22",
        1,
        "vi",
        '["data"]',
        "Điều 1",
        1,
        1,
        "https://vanban.chinhphu.vn/a",
        "https://datafiles.chinhphu.vn/a.pdf",
        "b" * 64,
        "ocr_tesseract",
        "Nội dung OCR đã đối chiếu.",
    )
    connection.execute(
        "INSERT INTO chunks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", row
    )
    connection.execute(
        "INSERT INTO chunks_fts VALUES (?,?,?,?,?,?)",
        (row[0], row[2], row[3], row[13], row[14], row[21]),
    )
    connection.commit()
    connection.close()


def test_loads_authenticated_overlay_as_immutable_mapping(tmp_path: Path) -> None:
    path = tmp_path / "overlay.json"
    _write(path, _overlay())

    overlay = _load(path)

    assert overlay is not None
    assert overlay.corpus_release_id == RELEASE_ID
    assert overlay.get("chunk-1") is overlay.records["chunk-1"]
    assert overlay.records["chunk-1"].human_verified is True
    with pytest.raises(TypeError):
        overlay.records["other"] = overlay.records["chunk-1"]  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        overlay.records["chunk-1"].reviewer = "attacker"  # type: ignore[misc]


def test_loads_overlay_emitted_by_real_importer(tmp_path: Path) -> None:
    db = tmp_path / "rag.sqlite3"
    queue = tmp_path / "queue.jsonl"
    reviews = tmp_path / "reviews.jsonl"
    overlay_path = tmp_path / "overlay.json"
    key_file = tmp_path / "overlay.key"
    _build_importer_corpus(db)
    key_file.write_bytes(KEY)
    export_queue(db, queue, benchmark_path=None)
    review = json.loads(queue.read_text(encoding="utf-8"))
    review.update(
        review_status="human_verified",
        reviewer="legal-reviewer@example.test",
        reviewed_at="2026-07-22T08:30:00Z",
        review_notes="Đã đối chiếu PDF chính thức.",
    )
    reviews.write_text(json.dumps(review, ensure_ascii=False) + "\n", encoding="utf-8")
    import_reviews(
        db,
        reviews,
        overlay_path,
        signing_key_path=key_file,
        key_id=KEY_ID,
    )
    emitted = json.loads(overlay_path.read_text(encoding="utf-8"))

    loaded = load_verification_overlay(
        overlay_path,
        signing_key=KEY,
        expected_corpus_sha256=emitted["corpus"]["sha256"],
        expected_release_id=emitted["corpus"]["release_id"],
        expected_signing_key_id=KEY_ID,
        required=True,
    )

    assert loaded is not None
    assert loaded.records["ocr-1"].human_verified is True


def test_missing_overlay_is_optional_or_required(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    assert _load(missing) is None
    assert (
        load_verification_overlay(
            None,
            signing_key=KEY,
            expected_corpus_sha256=CORPUS_SHA,
            expected_release_id=RELEASE_ID,
        )
        is None
    )
    with pytest.raises(VerificationOverlayError, match="missing"):
        _load(missing, required=True)


@pytest.mark.parametrize(
    ("loader_update", "error"),
    [
        ({"signing_key": b"wrong-key-material-that-is-at-least-32"}, "signature mismatch"),
        ({"expected_corpus_sha256": "e" * 64}, "corpus SHA-256 mismatch"),
        ({"expected_release_id": "other-release"}, "release identity mismatch"),
        ({"expected_signing_key_id": "other-key"}, "signing key identity mismatch"),
    ],
)
def test_fails_closed_on_wrong_runtime_identity(
    tmp_path: Path, loader_update: dict[str, object], error: str
) -> None:
    path = tmp_path / "overlay.json"
    _write(path, _overlay())
    with pytest.raises(VerificationOverlayError, match=error):
        _load(path, **loader_update)


def test_rejects_payload_tampering_even_when_declared_hash_is_changed(tmp_path: Path) -> None:
    path = tmp_path / "overlay.json"
    value = _overlay()
    records = value["records"]
    assert isinstance(records, dict)
    record = records["chunk-1"]
    assert isinstance(record, dict)
    record["reviewer"] = "tampered-reviewer"
    payload = {key: value[key] for key in value if key not in {"integrity", "authentication"}}
    integrity = value["integrity"]
    assert isinstance(integrity, dict)
    integrity["payload_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    _write(path, value)

    with pytest.raises(VerificationOverlayError, match="signature mismatch"):
        _load(path)


@pytest.mark.parametrize(
    ("record_update", "error"),
    [
        ({"text_verification_status": "pending"}, "verification status"),
        ({"reviewer": ""}, "reviewer"),
        ({"reviewed_at": "2026-07-22T08:30:00+07:00"}, "RFC3339 UTC"),
        ({"source_pdf_sha256": "not-a-hash"}, "source_pdf_sha256"),
        ({"text_sha256": "C" * 64}, "text_sha256"),
        ({"page_start": 13, "page_end": 12}, "page_end"),
    ],
)
def test_rejects_invalid_record_provenance(
    tmp_path: Path, record_update: dict[str, object], error: str
) -> None:
    path = tmp_path / "overlay.json"
    _write(path, _overlay(records={"chunk-1": _record(**record_update)}))

    with pytest.raises(VerificationOverlayError, match=error):
        _load(path)


def test_rejects_record_count_and_schema_drift(tmp_path: Path) -> None:
    path = tmp_path / "overlay.json"
    _write(path, _overlay(record_count=2))
    with pytest.raises(VerificationOverlayError, match="record_count"):
        _load(path)

    _write(path, _overlay(schema_version="overlay.v2"))
    with pytest.raises(VerificationOverlayError, match="schema_version"):
        _load(path)


def test_rejects_duplicate_chunk_ids_before_signature_validation(tmp_path: Path) -> None:
    path = tmp_path / "overlay.json"
    value = _overlay()
    encoded_record = json.dumps(_record(), ensure_ascii=False)
    raw = json.dumps(value, ensure_ascii=False)
    records_start = raw.index('"records": {')
    first_record_start = raw.index('"chunk-1"', records_start)
    first_record_end = raw.index("}", first_record_start) + 1
    duplicate = raw[:first_record_end] + f', "chunk-1": {encoded_record}' + raw[first_record_end:]
    path.write_text(duplicate, encoding="utf-8")

    with pytest.raises(VerificationOverlayError, match="Duplicate JSON key: chunk-1"):
        _load(path)


def test_rejects_unexpected_fields_and_noncanonical_timestamp(tmp_path: Path) -> None:
    path = tmp_path / "overlay.json"
    record = _record(reviewed_at="2026-07-22T08:30:00.000Z")
    record["untrusted"] = True
    _write(path, _overlay(records={"chunk-1": record}))
    with pytest.raises(VerificationOverlayError, match="Invalid record"):
        _load(path)

    _write(
        path,
        _overlay(records={"chunk-1": _record(reviewed_at="2026-07-22T08:30:00.000Z")}),
    )
    with pytest.raises(VerificationOverlayError, match="normalized to UTC seconds"):
        _load(path)
