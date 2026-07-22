from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import numpy as np
import pytest

from scripts import build_legal_dense_index, build_legal_release
from scripts.validate_legal_corpus import main as validate_main
from security.legal.corpus import inspect_corpus, sha256_file
from security.legal.dense import (
    DenseIndexError,
    PrecomputedDenseIndex,
    resolve_dense_artifact_path,
)


def _build_corpus(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE chunks (
          chunk_id TEXT PRIMARY KEY,
          document_id TEXT NOT NULL,
          title TEXT NOT NULL,
          document_number TEXT,
          document_type TEXT,
          jurisdiction TEXT,
          authority TEXT,
          legal_weight TEXT,
          status TEXT,
          effective_date TEXT,
          status_checked_at TEXT,
          retrieval_default INTEGER NOT NULL,
          language TEXT,
          topics TEXT,
          section TEXT,
          page_start INTEGER,
          page_end INTEGER,
          source_page_url TEXT,
          source_file_url TEXT,
          source_pdf_sha256 TEXT,
          extraction_method TEXT,
          text TEXT NOT NULL
        );
        CREATE VIRTUAL TABLE chunks_fts USING fts5(
          chunk_id UNINDEXED, title, document_number, topics, section, text,
          tokenize='unicode61 remove_diacritics 2'
        );
        """
    )
    values = (
        "vn_personal_data::c00001",
        "vn_personal_data",
        "Luật Bảo vệ dữ liệu cá nhân",
        "91/2025/QH15",
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
        "Điều 20. Chuyển giao dữ liệu",
        12,
        12,
        "https://vanban.chinhphu.vn/van-ban",
        "https://datafiles.chinhphu.vn/example.pdf",
        "a" * 64,
        "native_pdf_text",
        "Chuyển giao dữ liệu cá nhân phải có mục đích và biện pháp bảo vệ phù hợp.",
    )
    connection.execute(
        "INSERT INTO chunks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values
    )
    connection.execute(
        "INSERT INTO chunks_fts VALUES (?,?,?,?,?,?)",
        (values[0], values[2], values[3], values[13], values[14], values[21]),
    )
    connection.commit()
    connection.close()


def _build_dense_fixture(
    path: Path,
    *,
    corpus_sha256: str | None,
    count: int = 1,
    dimension: int = 3,
) -> None:
    path.mkdir()
    model = path / "model"
    model.mkdir()
    (model / "model.onnx").write_bytes(b"test-model")
    ids = ["vn_personal_data::c00001"]
    (path / "embedding_ids.json").write_text(json.dumps(ids), encoding="utf-8")
    np.save(path / "embeddings.f16.npy", np.ones((1, 3), dtype=np.float16))
    manifest = {
        "schema_version": 1,
        "ids_file": "embedding_ids.json",
        "embeddings_file": "embeddings.f16.npy",
        "model_dir": "model",
        "dimension": dimension,
        "count": count,
        "model_id": "test/e5",
        "model_revision": "deadbeef",
    }
    if corpus_sha256 is not None:
        manifest["corpus_sha256"] = corpus_sha256
    (path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_validator_is_read_only_and_manifest_is_optional(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "rag.sqlite3"
    _build_corpus(db)
    original_hash = sha256_file(db)

    assert validate_main([str(db)]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["ready"] is True
    assert report["reason_codes"] == ["manifest_missing"]
    assert sha256_file(db) == original_hash
    assert list(tmp_path.iterdir()) == [db]
    assert validate_main([str(db), "--require-manifest"]) == 1


def test_validator_cannot_overwrite_implicit_sibling_manifest(tmp_path: Path) -> None:
    db = tmp_path / "rag.sqlite3"
    _build_corpus(db)
    manifest = tmp_path / "manifest.json"
    original = '{"sentinel": true}\n'
    manifest.write_text(original, encoding="utf-8")

    with pytest.raises(SystemExit):
        validate_main([str(db), "--output", str(manifest)])

    assert manifest.read_text(encoding="utf-8") == original


def test_release_builder_packages_side_by_side_without_mutating_source(tmp_path: Path) -> None:
    db = tmp_path / "source" / "rag.sqlite3"
    db.parent.mkdir()
    _build_corpus(db)
    original_hash = sha256_file(db)

    output = build_legal_release.build_release(
        db_path=db,
        releases_dir=tmp_path / "releases",
        release_id="vn-legal-2026-07-22.1",
        source_revision="hf-commit-abc123",
    )

    assert output == tmp_path / "releases" / "vn-legal-2026-07-22.1"
    assert sha256_file(db) == original_hash
    assert sha256_file(output / "rag.sqlite3") == original_hash
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["source_revision"] == "hf-commit-abc123"
    assert manifest["sqlite_sha256"] == original_hash
    assert (output / "validation-report.json").is_file()
    assert inspect_corpus(
        output / "rag.sqlite3",
        manifest_path=output / "manifest.json",
        require_manifest=True,
    ).ready

    with pytest.raises(FileExistsError):
        build_legal_release.build_release(
            db_path=db,
            releases_dir=tmp_path / "releases",
            release_id="vn-legal-2026-07-22.1",
            source_revision="hf-commit-other",
        )
    assert manifest == json.loads((output / "manifest.json").read_text(encoding="utf-8"))


def test_dense_builder_uses_eligible_rows_and_publishes_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "rag.sqlite3"
    _build_corpus(db)
    original_hash = sha256_file(db)
    model = tmp_path / "local-model"
    model.mkdir()
    (model / "model.onnx").write_bytes(b"test-model")
    output = tmp_path / "dense-v1"
    captured: dict[str, object] = {}

    def fake_build_dense_artifacts(**kwargs: object) -> dict[str, object]:
        root = Path(str(kwargs["output_dir"]))
        chunk_ids = list(kwargs["chunk_ids"])  # type: ignore[arg-type]
        texts = list(kwargs["texts"])  # type: ignore[arg-type]
        captured.update({"chunk_ids": chunk_ids, "texts": texts})
        np.save(root / "embeddings.f16.npy", np.ones((len(chunk_ids), 3), dtype=np.float16))
        (root / "embedding_ids.json").write_text(json.dumps(chunk_ids), encoding="utf-8")
        manifest: dict[str, object] = {
            "schema_version": 1,
            "ids_file": "embedding_ids.json",
            "embeddings_file": "embeddings.f16.npy",
            "model_dir": "model",
            "dimension": 3,
            "count": len(chunk_ids),
        }
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return manifest

    monkeypatch.setattr(
        build_legal_dense_index, "build_dense_artifacts", fake_build_dense_artifacts
    )
    manifest = build_legal_dense_index.build_index(
        db_path=db,
        model_dir=model,
        output_dir=output,
        model_id="test/e5",
        model_revision="deadbeef",
    )

    assert sha256_file(db) == original_hash
    assert captured["chunk_ids"] == ["vn_personal_data::c00001"]
    assert "Điều 20" in str(captured["texts"])
    assert manifest["model_revision"] == "deadbeef"
    assert (output / "model" / "model.onnx").read_bytes() == b"test-model"
    assert not list(tmp_path.glob(".dense-v1.*.tmp"))


def test_dense_builder_does_not_publish_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "rag.sqlite3"
    _build_corpus(db)
    model = tmp_path / "local-model"
    model.mkdir()
    (model / "model.onnx").write_bytes(b"test-model")
    output = tmp_path / "dense-v1"

    def fail_build(**_kwargs: object) -> dict[str, object]:
        raise RuntimeError("encoder failed")

    monkeypatch.setattr(build_legal_dense_index, "build_dense_artifacts", fail_build)
    with pytest.raises(RuntimeError, match="encoder failed"):
        build_legal_dense_index.build_index(
            db_path=db,
            model_dir=model,
            output_dir=output,
            model_id="test/e5",
            model_revision="deadbeef",
        )

    assert not output.exists()
    assert not list(tmp_path.glob(".dense-v1.*.tmp"))


@pytest.mark.parametrize("field", ["ids_file", "embeddings_file", "model_dir"])
def test_dense_loader_rejects_parent_and_absolute_manifest_paths(
    tmp_path: Path, field: str
) -> None:
    dense = tmp_path / "dense"
    _build_dense_fixture(dense, corpus_sha256="a" * 64)
    manifest_path = dense / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    manifest[field] = "../outside"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(DenseIndexError, match="contained relative path"):
        PrecomputedDenseIndex.load(dense)

    manifest[field] = str((tmp_path / "outside").resolve())
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(DenseIndexError, match="contained relative path"):
        PrecomputedDenseIndex.load(dense)


def test_dense_artifact_path_rejects_symlink_escape(tmp_path: Path) -> None:
    dense = tmp_path / "dense"
    dense.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("[]", encoding="utf-8")
    link = dense / "ids-link.json"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation is not permitted on this Windows host")

    with pytest.raises(DenseIndexError, match="escapes"):
        resolve_dense_artifact_path(dense, "ids-link.json", label="IDs")


def test_release_rejects_dense_index_without_corpus_sha_or_with_bad_shape(
    tmp_path: Path,
) -> None:
    db = tmp_path / "rag.sqlite3"
    _build_corpus(db)
    missing_sha = tmp_path / "dense-missing-sha"
    _build_dense_fixture(missing_sha, corpus_sha256=None)

    with pytest.raises(ValueError, match="corpus_sha256"):
        build_legal_release.build_release(
            db_path=db,
            releases_dir=tmp_path / "releases",
            release_id="missing-sha",
            source_revision="source-deadbeef",
            dense_index_dir=missing_sha,
        )

    bad_shape = tmp_path / "dense-bad-shape"
    _build_dense_fixture(bad_shape, corpus_sha256=sha256_file(db), count=2)
    with pytest.raises(ValueError, match="do not match"):
        build_legal_release.build_release(
            db_path=db,
            releases_dir=tmp_path / "releases",
            release_id="bad-shape",
            source_revision="source-deadbeef",
            dense_index_dir=bad_shape,
        )


def test_release_hashes_all_packaged_dense_and_model_artifacts(tmp_path: Path) -> None:
    db = tmp_path / "rag.sqlite3"
    _build_corpus(db)
    dense = tmp_path / "dense"
    _build_dense_fixture(dense, corpus_sha256=sha256_file(db))

    output = build_legal_release.build_release(
        db_path=db,
        releases_dir=tmp_path / "releases",
        release_id="dense-release",
        source_revision="source-deadbeef",
        dense_index_dir=dense,
    )

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    hashes = manifest["dense_artifact_sha256"]
    assert set(hashes) == {
        "embedding_ids.json",
        "embeddings.f16.npy",
        "model-manifest.json",
        "model/model.onnx",
    }
    for relative, digest in hashes.items():
        assert sha256_file(output / relative) == digest
    model_manifest = json.loads((output / "model-manifest.json").read_text(encoding="utf-8"))
    assert model_manifest["ids_file"] == "embedding_ids.json"
    assert model_manifest["embeddings_file"] == "embeddings.f16.npy"
    assert model_manifest["model_dir"] == "model"

    (output / "embedding_ids.json").write_text('["tampered"]', encoding="utf-8")
    with pytest.raises(DenseIndexError, match="checksum mismatch"):
        PrecomputedDenseIndex.load(output)
