"""Build an immutable local dense index from an eligible Legal RAG corpus."""

# ruff: noqa: E402 -- direct script execution needs the repository root on sys.path.

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import uuid
from collections.abc import Sequence
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from security.legal.corpus import inspect_corpus
from security.legal.dense import build_dense_artifacts

DEFAULT_DB_PATH = REPOSITORY_ROOT / "data" / "legal_rag" / "rag.sqlite3"


def _connect_read_only(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=2.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def load_eligible_passages(db_path: str | Path) -> tuple[list[str], list[str]]:
    """Load stable, searchable Vietnamese passages without mutating SQLite."""

    path = Path(db_path).expanduser().resolve()
    with _connect_read_only(path) as connection:
        rows = connection.execute(
            """
            SELECT chunk_id, title, section, text
            FROM chunks
            WHERE retrieval_default = 1
              AND UPPER(jurisdiction) IN ('VN','VIETNAM','VIET NAM','VIỆT NAM')
            ORDER BY chunk_id
            """
        ).fetchall()
    ids = [str(row["chunk_id"]) for row in rows]
    texts = [
        "\n".join(
            part
            for part in (
                str(row["title"] or "").strip(),
                str(row["section"] or "").strip(),
                str(row["text"] or "").strip(),
            )
            if part
        )
        for row in rows
    ]
    return ids, texts


def build_index(
    *,
    db_path: str | Path,
    model_dir: str | Path,
    output_dir: str | Path,
    model_id: str,
    model_revision: str,
    manifest_path: str | Path | None = None,
    require_manifest: bool = False,
    passage_prefix: str = "passage: ",
    query_prefix: str = "query: ",
    batch_size: int = 16,
    max_length: int = 512,
) -> dict[str, object]:
    """Build to a new sibling directory and atomically publish on success."""

    db = Path(db_path).expanduser().resolve()
    model = Path(model_dir).expanduser().resolve()
    output = Path(output_dir).expanduser().resolve()
    if output.exists():
        raise FileExistsError(f"Dense index output already exists: {output}")
    if not model.is_dir():
        raise FileNotFoundError(f"Local ONNX model directory does not exist: {model}")
    if output.is_relative_to(model):
        raise ValueError("Output directory must not be inside the model source directory")

    health = inspect_corpus(db, manifest_path=manifest_path, require_manifest=require_manifest)
    if not health.ready:
        raise ValueError("Corpus validation failed: " + ", ".join(health.reason_codes))
    chunk_ids, texts = load_eligible_passages(db)
    if not chunk_ids:
        raise ValueError("Corpus has no eligible Vietnamese passages")

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.parent / f".{output.name}.{uuid.uuid4().hex}.tmp"
    try:
        staging.mkdir()
        shutil.copytree(model, staging / "model")
        manifest = build_dense_artifacts(
            model_dir=staging / "model",
            output_dir=staging,
            chunk_ids=chunk_ids,
            texts=texts,
            passage_prefix=passage_prefix,
            query_prefix=query_prefix,
            batch_size=batch_size,
            max_length=max_length,
        )
        enriched: dict[str, object] = {
            **manifest,
            "model_id": model_id,
            "model_revision": model_revision,
            "corpus_release_id": health.snapshot.release_id,
            "corpus_sha256": health.snapshot.sha256,
            "eligibility": "retrieval_default=1 AND jurisdiction=VN",
        }
        (staging / "manifest.json").write_text(
            json.dumps(enriched, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        required = (
            staging / "manifest.json",
            staging / "embedding_ids.json",
            staging / "embeddings.f16.npy",
        )
        if not all(path.is_file() for path in required):
            raise RuntimeError("Dense artifact builder did not produce all required files")
        os.replace(staging, output)
        return enriched
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--require-manifest", action="store_true")
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--model-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--passage-prefix", default="passage: ")
    parser.add_argument("--query-prefix", default="query: ")
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--max-length", type=int, default=512)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    manifest = build_index(
        db_path=args.db,
        model_dir=args.model_dir,
        output_dir=args.output,
        model_id=args.model_id,
        model_revision=args.model_revision,
        manifest_path=args.manifest,
        require_manifest=args.require_manifest,
        passage_prefix=args.passage_prefix,
        query_prefix=args.query_prefix,
        batch_size=max(1, args.batch_size),
        max_length=max(32, args.max_length),
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
