"""Package a validated Legal RAG corpus as a side-by-side immutable release."""

# ruff: noqa: E402 -- direct script execution needs the repository root on sys.path.

from __future__ import annotations

import argparse
import gc
import json
import os
import re
import shutil
import sqlite3
import sys
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from security.legal.corpus import build_manifest, inspect_corpus, sha256_file
from security.legal.dense import DenseIndexError, resolve_dense_artifact_path

DEFAULT_DB_PATH = REPOSITORY_ROOT / "data" / "legal_rag" / "rag.sqlite3"
DEFAULT_RELEASES_DIR = REPOSITORY_ROOT / "data" / "legal_rag" / "releases"
_RELEASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _assert_tree_contained(root: Path, directory: Path) -> None:
    for candidate in (directory, *directory.rglob("*")):
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"Dense model contains an invalid path: {candidate}") from exc
        if not resolved.is_relative_to(root):
            raise ValueError(f"Dense model path escapes the artifact root: {candidate}")


def _load_dense_manifest(
    path: Path,
    *,
    expected_corpus_sha256: str,
) -> tuple[dict[str, Any], Path, Path, Path, list[str]]:
    root = path.resolve()
    manifest_path = path / "manifest.json"
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Dense index manifest is invalid: {manifest_path}") from exc
    if not isinstance(value, dict):
        raise ValueError("Dense index manifest must be a JSON object")
    declared_corpus_sha = str(value.get("corpus_sha256", "")).strip().casefold()
    if not declared_corpus_sha or declared_corpus_sha != expected_corpus_sha256.casefold():
        raise ValueError("Dense index corpus_sha256 is missing or does not match the corpus")
    try:
        ids_file = resolve_dense_artifact_path(
            root, value.get("ids_file", "embedding_ids.json"), label="IDs"
        )
        embeddings_file = resolve_dense_artifact_path(
            root,
            value.get("embeddings_file", "embeddings.f16.npy"),
            label="embeddings",
        )
        model_dir = resolve_dense_artifact_path(
            root, value.get("model_dir", "model"), label="model"
        )
    except DenseIndexError as exc:
        raise ValueError(str(exc)) from exc
    if not ids_file.is_file() or not embeddings_file.is_file() or not model_dir.is_dir():
        raise ValueError("Dense index is missing IDs, embedding matrix, or local model")
    _assert_tree_contained(root, model_dir)
    try:
        raw_ids = json.loads(ids_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Dense index IDs are invalid") from exc
    if (
        not isinstance(raw_ids, list)
        or not raw_ids
        or not all(isinstance(item, str) and item for item in raw_ids)
        or len(raw_ids) != len(set(raw_ids))
    ):
        raise ValueError("Dense index IDs must be a non-empty unique string list")
    try:
        matrix = np.load(embeddings_file, mmap_mode="r", allow_pickle=False)
        declared_count = int(value["count"])
        declared_dimension = int(value["dimension"])
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ValueError("Dense matrix or count/dimension metadata is invalid") from exc
    if (
        matrix.ndim != 2
        or matrix.shape[0] != len(raw_ids)
        or declared_count != len(raw_ids)
        or declared_dimension != int(matrix.shape[1])
        or not np.isfinite(matrix).all()
    ):
        raise ValueError("Dense IDs, matrix shape, count, or dimension do not match")
    if (
        not str(value.get("model_id", "")).strip()
        or not str(value.get("model_revision", "")).strip()
    ):
        raise ValueError("Dense model_id and model_revision must be pinned")
    return value, ids_file, embeddings_file, model_dir, raw_ids


def _eligible_chunk_ids(db: Path) -> set[str]:
    connection = sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True, timeout=2.0)
    try:
        connection.execute("PRAGMA query_only=ON")
        return {
            str(row[0])
            for row in connection.execute(
                """
                SELECT chunk_id FROM chunks
                WHERE retrieval_default = 1
                  AND UPPER(jurisdiction) IN ('VN','VIETNAM','VIET NAM','VIỆT NAM')
                """
            )
        }
    finally:
        connection.close()


def _dense_artifact_hashes(root: Path) -> dict[str, str]:
    names = ("embedding_ids.json", "embeddings.f16.npy", "model-manifest.json")
    files = [root / name for name in names]
    files.extend(path for path in (root / "model").rglob("*") if path.is_file())
    return {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in sorted(files, key=lambda item: item.as_posix())
    }


def build_release(
    *,
    db_path: str | Path,
    releases_dir: str | Path,
    release_id: str,
    source_revision: str,
    dense_index_dir: str | Path | None = None,
) -> Path:
    """Build an immutable release directory without changing the source corpus."""

    if not _RELEASE_ID_RE.fullmatch(release_id):
        raise ValueError("release_id may contain only letters, digits, dot, dash and underscore")
    if not source_revision.strip():
        raise ValueError("source_revision must pin the corpus source revision")
    db = Path(db_path).expanduser().resolve()
    releases = Path(releases_dir).expanduser().resolve()
    output = releases / release_id
    if output.exists():
        raise FileExistsError(f"Release already exists: {output}")

    source_health = inspect_corpus(db, require_manifest=False)
    source_errors = [
        reason for reason in source_health.reason_codes if reason != "manifest_missing"
    ]
    if not source_health.ready or source_errors:
        raise ValueError("Corpus validation failed: " + ", ".join(source_errors))

    dense = Path(dense_index_dir).expanduser().resolve() if dense_index_dir else None
    dense_bundle = (
        _load_dense_manifest(dense, expected_corpus_sha256=source_health.snapshot.sha256)
        if dense is not None
        else None
    )
    if dense_bundle is not None:
        dense_ids = set(dense_bundle[4])
        if dense_ids != _eligible_chunk_ids(db):
            raise ValueError("Dense index IDs do not exactly match eligible corpus chunks")

    releases.mkdir(parents=True, exist_ok=True)
    staging = releases / f".{release_id}.{uuid.uuid4().hex}.tmp"
    try:
        staging.mkdir()
        release_db = staging / "rag.sqlite3"
        shutil.copy2(db, release_db)
        manifest: dict[str, Any] = build_manifest(release_db, release_id=release_id)
        manifest["source_revision"] = source_revision

        if dense is not None and dense_bundle is not None:
            dense_manifest, ids_file, embeddings_file, model_source, _dense_ids = dense_bundle
            shutil.copy2(ids_file, staging / "embedding_ids.json")
            shutil.copy2(embeddings_file, staging / "embeddings.f16.npy")
            packaged_dense_manifest = dict(dense_manifest)
            packaged_dense_manifest.pop("dense_artifact_sha256", None)
            packaged_dense_manifest.update(
                {
                    "ids_file": "embedding_ids.json",
                    "embeddings_file": "embeddings.f16.npy",
                    "model_dir": "model",
                }
            )
            (staging / "model-manifest.json").write_text(
                json.dumps(packaged_dense_manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            shutil.copytree(model_source, staging / "model")
            manifest.update(
                {
                    "embedding_model_id": dense_manifest.get("model_id", ""),
                    "embedding_model_revision": dense_manifest.get("model_revision", ""),
                    "embedding_dimension": dense_manifest.get("dimension", 0),
                    "embedding_count": dense_manifest.get("count", 0),
                    "ids_file": "embedding_ids.json",
                    "embeddings_file": "embeddings.f16.npy",
                    "model_dir": "model",
                    "query_prefix": dense_manifest.get("query_prefix", "query: "),
                    "passage_prefix": dense_manifest.get("passage_prefix", "passage: "),
                    "max_length": dense_manifest.get("max_length", 512),
                    "dense_index_manifest": "model-manifest.json",
                    "dense_artifact_sha256": _dense_artifact_hashes(staging),
                }
            )

        (staging / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        health = inspect_corpus(
            release_db,
            manifest_path=staging / "manifest.json",
            require_manifest=True,
        )
        report = health.model_dump()
        (staging / "validation-report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if not health.ready:
            raise ValueError(
                "Packaged release failed validation: " + ", ".join(health.reason_codes)
            )
        # ``inspect_corpus`` is read-only, but older CPython/SQLite combinations on
        # Windows may defer finalizing a connection after its context exits. Force
        # finalization before renaming the immutable bundle directory.
        gc.collect()
        os.replace(staging, output)
        return output
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--releases-dir", type=Path, default=DEFAULT_RELEASES_DIR)
    parser.add_argument("--release-id", required=True)
    parser.add_argument(
        "--source-revision",
        required=True,
        help="Pinned dataset commit, source-control revision, or immutable source ID.",
    )
    parser.add_argument("--dense-index", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output = build_release(
        db_path=args.db,
        releases_dir=args.releases_dir,
        release_id=args.release_id,
        source_revision=args.source_revision,
        dense_index_dir=args.dense_index,
    )
    print(json.dumps({"release_dir": str(output)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
