from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from scripts.export_legal_ocr_review_queue import export_queue
from scripts.import_legal_ocr_review import import_reviews, verify_overlay
from security.legal.corpus import sha256_file


def _build_corpus(path: Path) -> None:
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
    rows = [
        (
            "ocr-binding",
            "doc-a",
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
            '["personal_data"]',
            "Điều 1",
            1,
            1,
            "https://vanban.chinhphu.vn/a",
            "https://datafiles.chinhphu.vn/a.pdf",
            "a" * 64,
            "ocr_tesseract_vie_120dpi",
            "Nội dung OCR ràng buộc.",
        ),
        (
            "ocr-gold",
            "doc-b",
            "Hướng dẫn B",
            "02/2026/HD",
            "guidance",
            "VN",
            "Cơ quan B",
            "guidance",
            "current",
            "2026-01-01",
            "2026-07-22",
            1,
            "vi",
            '["ai"]',
            "Mục 2",
            2,
            2,
            "https://vanban.chinhphu.vn/b",
            "https://datafiles.chinhphu.vn/b.pdf",
            "b" * 64,
            "ocr_engine_v2",
            "Nội dung OCR benchmark.",
        ),
        (
            "ocr-archive",
            "doc-c",
            "Văn bản C",
            "03/2025/VB",
            "reference",
            "VN",
            "Cơ quan C",
            "reference",
            "current",
            "2025-01-01",
            "2026-07-22",
            0,
            "vi",
            '["other"]',
            "Mục 3",
            3,
            3,
            "https://vanban.chinhphu.vn/c",
            "https://datafiles.chinhphu.vn/c.pdf",
            "c" * 64,
            "scanned_pdf_ocr",
            "Nội dung OCR lưu trữ.",
        ),
        (
            "native",
            "doc-d",
            "Văn bản D",
            "04/2026/VB",
            "law",
            "VN",
            "Cơ quan D",
            "binding",
            "current",
            "2026-01-01",
            "2026-07-22",
            1,
            "vi",
            '["other"]',
            "Điều 4",
            4,
            4,
            "https://vanban.chinhphu.vn/d",
            "https://datafiles.chinhphu.vn/d.pdf",
            "d" * 64,
            "native_pdf_text",
            "Nội dung PDF native.",
        ),
    ]
    connection.executemany(
        "INSERT INTO chunks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows
    )
    connection.executemany(
        "INSERT INTO chunks_fts VALUES (?,?,?,?,?,?)",
        [(row[0], row[2], row[3], row[13], row[14], row[21]) for row in rows],
    )
    connection.commit()
    connection.close()


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write_review(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
        encoding="utf-8",
    )


def test_export_is_deterministic_prioritized_and_read_only(tmp_path: Path) -> None:
    db = tmp_path / "rag.sqlite3"
    benchmark = tmp_path / "benchmark.jsonl"
    queue_a = tmp_path / "queue-a.jsonl"
    queue_b = tmp_path / "queue-b.jsonl"
    _build_corpus(db)
    benchmark.write_text(
        json.dumps({"case_id": "gold-case", "query": "q", "relevance": {"ocr-gold": 3}}) + "\n",
        encoding="utf-8",
    )
    original_db_hash = sha256_file(db)

    export_queue(db, queue_a, benchmark_path=benchmark)
    export_queue(db, queue_b, benchmark_path=benchmark)

    assert queue_a.read_bytes() == queue_b.read_bytes()
    assert sha256_file(db) == original_db_hash
    records = _read_jsonl(queue_a)
    assert [record["chunk_id"] for record in records] == [
        "ocr-binding",
        "ocr-gold",
        "ocr-archive",
    ]
    assert records[1]["benchmark_gold"] is True
    assert records[1]["benchmark_case_ids"] == ["gold-case"]
    assert records[1]["review_status"] == "pending"
    assert records[1]["queue_hash_algorithm"] == "sha256"
    assert len(str(records[1]["queue_record_sha256"])) == 64
    assert "native" not in {record["chunk_id"] for record in records}


def test_import_publishes_verifiable_overlay_without_mutating_db(tmp_path: Path) -> None:
    db = tmp_path / "rag.sqlite3"
    queue = tmp_path / "queue.jsonl"
    reviews = tmp_path / "reviews.jsonl"
    overlay = tmp_path / "overlay.json"
    overlay_copy = tmp_path / "overlay-copy.json"
    key_file = tmp_path / "review.key"
    _build_corpus(db)
    key = b"review-signing-key-material-32-bytes!!"
    key_file.write_bytes(key)
    export_queue(db, queue, benchmark_path=None)
    records = _read_jsonl(queue)
    for record in records:
        record.update(
            {
                "review_status": "human_verified",
                "reviewer": "legal-reviewer@example.test",
                "reviewed_at": "2026-07-22T08:30:00Z",
                "review_notes": "Đã đối chiếu PDF chính thức.",
            }
        )
    _write_review(reviews, records)
    original_db_hash = sha256_file(db)

    report = import_reviews(
        db,
        reviews,
        overlay,
        signing_key_path=key_file,
        key_id="legal-review-2026-01",
    )
    import_reviews(
        db,
        reviews,
        overlay_copy,
        signing_key_path=key_file,
        key_id="legal-review-2026-01",
    )

    assert report["record_count"] == 3
    assert verify_overlay(overlay, key)
    assert not verify_overlay(overlay, b"x" * 32)
    assert sha256_file(db) == original_db_hash
    assert overlay.read_bytes() == overlay_copy.read_bytes()
    payload = json.loads(overlay.read_text(encoding="utf-8"))
    assert payload["integrity"] == {
        "algorithm": "sha256",
        "canonicalization": "json-sort-keys-compact-utf8-v1",
        "payload_sha256": report["payload_sha256"],
    }
    assert payload["authentication"]["algorithm"] == "hmac-sha256"
    assert payload["records"]["ocr-gold"]["text_verification_status"] == "human_verified"
    payload["records"]["ocr-gold"]["reviewer"] = "tampered-reviewer"
    overlay.write_text(json.dumps(payload), encoding="utf-8")
    assert not verify_overlay(overlay, key)

    payload = json.loads(overlay_copy.read_text(encoding="utf-8"))
    payload["authentication"]["key_id"] = "tampered-key-id"
    overlay.write_text(json.dumps(payload), encoding="utf-8")
    assert not verify_overlay(overlay, key)


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (lambda rows: rows[0].update(chunk_id="unknown"), "Unknown chunk_id"),
        (
            lambda rows: rows[0].update(source_pdf_sha256="0" * 64),
            "Tampered immutable field",
        ),
        (lambda rows: rows[0].update(text="tampered"), "Tampered immutable field"),
        (lambda rows: rows[0].update(text_sha256="0" * 64), "Text hash mismatch"),
        (
            lambda rows: rows[0].update(corpus_release_id="tampered-release"),
            "Corpus release mismatch",
        ),
        (
            lambda rows: rows[0].update(queue_position=999),
            "Queue record hash mismatch",
        ),
        (
            lambda rows: rows[0].update(unexpected_field="tampered"),
            "Review queue fields changed",
        ),
        (lambda rows: rows[0].update(review_status="pending"), "Invalid or pending"),
    ],
)
def test_import_rejects_unknown_pending_or_tampered_records(
    tmp_path: Path, mutation, error: str
) -> None:
    db = tmp_path / "rag.sqlite3"
    queue = tmp_path / "queue.jsonl"
    reviews = tmp_path / "reviews.jsonl"
    key_file = tmp_path / "review.key"
    _build_corpus(db)
    key_file.write_bytes(b"k" * 32)
    export_queue(db, queue, benchmark_path=None)
    rows = _read_jsonl(queue)
    rows = rows[:1]
    rows[0].update(
        review_status="human_verified",
        reviewer="reviewer",
        reviewed_at="2026-07-22T00:00:00Z",
    )
    mutation(rows)
    _write_review(reviews, rows)

    with pytest.raises(ValueError, match=error):
        import_reviews(
            db,
            reviews,
            tmp_path / "overlay.json",
            signing_key_path=key_file,
            key_id="test-key",
        )


def test_import_rejects_duplicate_records_and_existing_output(tmp_path: Path) -> None:
    db = tmp_path / "rag.sqlite3"
    queue = tmp_path / "queue.jsonl"
    reviews = tmp_path / "reviews.jsonl"
    key_file = tmp_path / "review.key"
    _build_corpus(db)
    key_file.write_bytes(b"k" * 32)
    export_queue(db, queue, benchmark_path=None, limit=1)
    row = _read_jsonl(queue)[0]
    row.update(
        review_status="rejected",
        reviewer="reviewer",
        reviewed_at="2026-07-22T00:00:00Z",
    )
    _write_review(reviews, [row, row])
    with pytest.raises(ValueError, match="Duplicate chunk_id"):
        import_reviews(
            db,
            reviews,
            tmp_path / "overlay.json",
            signing_key_path=key_file,
            key_id="test-key",
        )

    output = tmp_path / "already-exists.json"
    output.write_text("do not replace", encoding="utf-8")
    with pytest.raises(FileExistsError):
        export_queue(db, output, benchmark_path=None)
    assert output.read_text(encoding="utf-8") == "do not replace"
