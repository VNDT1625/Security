"""Export a deterministic, read-only human review queue for OCR legal chunks."""

# ruff: noqa: E402 -- direct script execution needs the repository root on sys.path.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from security.legal.corpus import inspect_corpus

DEFAULT_DB_PATH = REPOSITORY_ROOT / "data" / "legal_rag" / "rag.sqlite3"
DEFAULT_BENCHMARK = REPOSITORY_ROOT / "benchmarks" / "legal_rag" / "v1" / "canary.jsonl"
QUEUE_SCHEMA_VERSION = "legal-ocr-review-queue.v1"
QUEUE_HASH_ALGORITHM = "sha256"

_BINDING_WEIGHTS = {
    "binding": 0,
    "binding_law": 0,
    "statutory": 1,
    "regulation": 2,
    "authoritative": 3,
    "guidance": 4,
    "reference": 5,
}


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=2.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _is_ocr_method(value: object) -> bool:
    normalized = str(value or "").casefold()
    return any(token in normalized for token in ("ocr", "scan", "tesseract"))


def _text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _queue_record_sha256(record: dict[str, Any]) -> str:
    immutable = {
        key: value
        for key, value in record.items()
        if key
        not in {
            "queue_record_sha256",
            "review_status",
            "reviewer",
            "reviewed_at",
            "review_notes",
        }
    }
    return hashlib.sha256(_canonical_json(immutable)).hexdigest()


def _load_benchmark(path: Path | None) -> dict[str, dict[str, Any]]:
    usage: dict[str, dict[str, Any]] = defaultdict(lambda: {"max_relevance": 0, "case_ids": []})
    if path is None:
        return {}
    if not path.is_file():
        raise ValueError(f"Benchmark does not exist: {path}")
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw_line.strip():
            continue
        try:
            case = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid benchmark JSON at line {line_number}") from exc
        if not isinstance(case, dict):
            raise ValueError(f"Benchmark line {line_number} must be a JSON object")
        case_id = str(case.get("case_id") or case.get("id") or f"line-{line_number}")
        relevance = case.get("relevance", {})
        if not isinstance(relevance, dict):
            raise ValueError(f"Benchmark relevance must be an object at line {line_number}")
        for chunk_id, raw_grade in relevance.items():
            try:
                grade = int(raw_grade)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid relevance grade at line {line_number}") from exc
            if grade <= 0:
                continue
            item = usage[str(chunk_id)]
            item["max_relevance"] = max(int(item["max_relevance"]), grade)
            item["case_ids"].append(case_id)
    return {
        chunk_id: {
            "max_relevance": int(item["max_relevance"]),
            "case_ids": sorted(set(str(value) for value in item["case_ids"])),
        }
        for chunk_id, item in usage.items()
    }


def _method_rank(method: str) -> int:
    normalized = method.casefold()
    if "tesseract" in normalized:
        return 0
    if "ocr" in normalized:
        return 1
    if "scan" in normalized:
        return 2
    return 3


def _priority_key(record: dict[str, Any]) -> tuple[object, ...]:
    weight = str(record["legal_weight"]).casefold()
    return (
        0 if record["retrieval_default"] else 1,
        _BINDING_WEIGHTS.get(weight, 50),
        0 if record["benchmark_gold"] else 1,
        -int(record["benchmark_max_relevance"]),
        _method_rank(str(record["extraction_method"])),
        str(record["document_id"]),
        int(record["page_start"] or 2**31),
        str(record["chunk_id"]),
    )


def _write_new_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing queue: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with staging.open("x", encoding="utf-8", newline="\n") as stream:
            for record in records:
                stream.write(
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                    + "\n"
                )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staging, path)
    finally:
        staging.unlink(missing_ok=True)


def export_queue(
    db_path: str | Path,
    output_path: str | Path,
    *,
    benchmark_path: str | Path | None = DEFAULT_BENCHMARK,
    manifest_path: str | Path | None = None,
    require_manifest: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    """Read OCR chunks and write a deterministic JSONL queue to a new file."""

    db = Path(db_path).expanduser().resolve()
    output = Path(output_path).expanduser().resolve()
    manifest = Path(manifest_path).expanduser().resolve() if manifest_path else None
    benchmark = Path(benchmark_path).expanduser().resolve() if benchmark_path else None
    if output in {db, manifest, benchmark}:
        raise ValueError("Queue output must not overwrite an input artifact")
    if limit is not None and limit <= 0:
        raise ValueError("limit must be greater than zero")

    health = inspect_corpus(db, manifest_path=manifest, require_manifest=require_manifest)
    if not health.ready:
        raise ValueError(f"Corpus validation failed: {', '.join(health.reason_codes)}")
    benchmark_usage = _load_benchmark(benchmark)

    records: list[dict[str, Any]] = []
    with _connect(db) as connection:
        rows = connection.execute(
            """
            SELECT chunk_id, document_id, title, document_number, jurisdiction,
                   legal_weight, retrieval_default, section, page_start, page_end,
                   source_page_url, source_file_url, source_pdf_sha256,
                   extraction_method, text
            FROM chunks
            """
        ).fetchall()
    for row in rows:
        if not _is_ocr_method(row["extraction_method"]):
            continue
        chunk_id = str(row["chunk_id"])
        benchmark_item = benchmark_usage.get(chunk_id, {})
        text = str(row["text"] or "")
        records.append(
            {
                "schema_version": QUEUE_SCHEMA_VERSION,
                "corpus_sha256": health.snapshot.sha256,
                "corpus_release_id": health.snapshot.release_id,
                "chunk_id": chunk_id,
                "document_id": str(row["document_id"] or ""),
                "title": str(row["title"] or ""),
                "document_number": str(row["document_number"] or ""),
                "jurisdiction": str(row["jurisdiction"] or ""),
                "legal_weight": str(row["legal_weight"] or ""),
                "retrieval_default": bool(row["retrieval_default"]),
                "benchmark_gold": bool(benchmark_item),
                "benchmark_max_relevance": int(benchmark_item.get("max_relevance", 0)),
                "benchmark_case_ids": benchmark_item.get("case_ids", []),
                "extraction_method": str(row["extraction_method"] or ""),
                "section": str(row["section"] or ""),
                "page_start": row["page_start"],
                "page_end": row["page_end"],
                "source_page_url": str(row["source_page_url"] or ""),
                "source_file_url": str(row["source_file_url"] or ""),
                "source_pdf_sha256": str(row["source_pdf_sha256"] or "").casefold(),
                "text_sha256": _text_sha256(text),
                "text": text,
                "review_status": "pending",
                "reviewer": "",
                "reviewed_at": "",
                "review_notes": "",
            }
        )
    records.sort(key=_priority_key)
    if limit is not None:
        records = records[:limit]
    for position, record in enumerate(records, 1):
        record["queue_position"] = position
        record["queue_hash_algorithm"] = QUEUE_HASH_ALGORITHM
        record["queue_record_sha256"] = _queue_record_sha256(record)
    _write_new_jsonl(output, records)
    return {
        "schema_version": QUEUE_SCHEMA_VERSION,
        "corpus_sha256": health.snapshot.sha256,
        "output": str(output),
        "record_count": len(records),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument("--no-benchmark", action="store_true")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--require-manifest", action="store_true")
    parser.add_argument("--limit", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = export_queue(
            args.db,
            args.output,
            benchmark_path=None if args.no_benchmark else args.benchmark,
            manifest_path=args.manifest,
            require_manifest=args.require_manifest,
            limit=args.limit,
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        _parser().error(str(exc))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
