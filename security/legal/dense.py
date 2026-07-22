"""Optional local ONNX dense index used by the quality retrieval profile."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np


class DenseIndexError(RuntimeError):
    pass


def resolve_dense_artifact_path(
    root: str | Path,
    value: object,
    *,
    label: str,
) -> Path:
    """Resolve one manifest path while enforcing artifact-root containment."""

    base = Path(root).resolve()
    raw = str(value or "").strip()
    if not raw:
        raise DenseIndexError(f"Dense index {label} path is empty")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise DenseIndexError(f"Dense index {label} path must be a contained relative path")
    candidate = (base / relative).resolve()
    if not candidate.is_relative_to(base):
        raise DenseIndexError(f"Dense index {label} path escapes the artifact root")
    return candidate


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_declared_hashes(root: Path, manifest: dict[str, Any]) -> None:
    declared = manifest.get("dense_artifact_sha256")
    if declared is None:
        return
    if not isinstance(declared, dict) or not declared:
        raise DenseIndexError("Dense artifact checksum manifest is invalid")
    for raw_path, raw_digest in declared.items():
        path = resolve_dense_artifact_path(root, raw_path, label=f"checksum artifact {raw_path!s}")
        digest = str(raw_digest).strip().casefold()
        if not path.is_file() or len(digest) != 64 or _sha256_file(path) != digest:
            raise DenseIndexError(f"Dense artifact checksum mismatch: {raw_path}")


class OnnxTextEncoder:
    """Small local-only mean-pooled sentence encoder.

    The model directory must contain tokenizer files and ``model.onnx``. No network
    access or remote code is allowed at runtime.
    """

    def __init__(self, model_dir: str | Path, *, max_length: int = 512) -> None:
        try:
            import onnxruntime as ort
            from transformers import AutoTokenizer
        except ImportError as exc:  # pragma: no cover - optional quality profile
            raise DenseIndexError("ONNX encoder dependencies are unavailable") from exc

        path = Path(model_dir).resolve()
        model_path = path / "model.onnx"
        if not model_path.is_file():
            candidates = sorted((path / "onnx").glob("*.onnx")) if (path / "onnx").is_dir() else []
            model_path = candidates[0] if candidates else model_path
        if not model_path.is_file():
            raise DenseIndexError(f"Missing ONNX model in {path}")
        self.tokenizer = AutoTokenizer.from_pretrained(
            str(path), local_files_only=True, trust_remote_code=False
        )
        self.session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
        self.input_names = {item.name for item in self.session.get_inputs()}
        self.max_length = max(32, min(8192, int(max_length)))

    def encode(self, texts: list[str], *, prefix: str = "") -> np.ndarray:
        values = [f"{prefix}{text}" for text in texts]
        tokens = self.tokenizer(
            values,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="np",
        )
        inputs = {
            name: np.asarray(value, dtype=np.int64)
            for name, value in tokens.items()
            if name in self.input_names
        }
        output = np.asarray(self.session.run(None, inputs)[0], dtype=np.float32)
        if output.ndim == 2:
            vectors = output
        elif output.ndim == 3:
            mask = np.asarray(tokens["attention_mask"], dtype=np.float32)[..., None]
            vectors = (output * mask).sum(axis=1) / np.maximum(mask.sum(axis=1), 1e-9)
        else:  # pragma: no cover - unsupported export
            raise DenseIndexError(f"Unexpected encoder output shape: {output.shape}")
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        return vectors / np.maximum(norms, 1e-12)


@dataclass
class PrecomputedDenseIndex:
    ids: tuple[str, ...]
    matrix: np.ndarray
    encoder: OnnxTextEncoder
    query_prefix: str = "query: "

    @classmethod
    def load(cls, directory: str | Path) -> PrecomputedDenseIndex:
        root = Path(directory).resolve()
        manifest_path = root / "manifest.json"
        if not manifest_path.is_file():
            raise DenseIndexError("Dense index manifest is missing")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise DenseIndexError("Dense index manifest must be an object")
        _validate_declared_hashes(root, manifest)
        ids_path = resolve_dense_artifact_path(
            root, manifest.get("ids_file", "embedding_ids.json"), label="IDs"
        )
        matrix_path = resolve_dense_artifact_path(
            root,
            manifest.get("embeddings_file", "embeddings.f16.npy"),
            label="embeddings",
        )
        model_dir = resolve_dense_artifact_path(
            root, manifest.get("model_dir", "model"), label="model"
        )
        raw_ids = json.loads(ids_path.read_text(encoding="utf-8"))
        if (
            not isinstance(raw_ids, list)
            or not raw_ids
            or not all(isinstance(item, str) and item for item in raw_ids)
            or len(raw_ids) != len(set(raw_ids))
        ):
            raise DenseIndexError("Dense index IDs are invalid")
        matrix = np.load(matrix_path, mmap_mode="r", allow_pickle=False)
        if matrix.ndim != 2 or matrix.shape[0] != len(raw_ids):
            raise DenseIndexError("Dense matrix shape does not match IDs")
        try:
            declared_count = int(
                manifest["count"] if "count" in manifest else manifest["embedding_count"]
            )
            declared_dimension = int(
                manifest["dimension"]
                if "dimension" in manifest
                else manifest["embedding_dimension"]
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DenseIndexError("Dense index count/dimension metadata is invalid") from exc
        if declared_count != len(raw_ids) or declared_dimension != int(matrix.shape[1]):
            raise DenseIndexError("Dense matrix shape does not match its manifest")
        if not np.isfinite(matrix).all():
            raise DenseIndexError("Dense matrix contains non-finite values")
        encoder = OnnxTextEncoder(model_dir, max_length=int(manifest.get("max_length", 512)))
        return cls(
            ids=tuple(raw_ids),
            matrix=matrix,
            encoder=encoder,
            query_prefix=str(manifest.get("query_prefix", "query: ")),
        )

    def search(self, query: str, *, top_k: int = 50) -> list[tuple[str, float]]:
        if not self.ids:
            return []
        vector = self.encoder.encode([query], prefix=self.query_prefix)[0]
        if vector.shape[0] != self.matrix.shape[1]:
            raise DenseIndexError("Query embedding dimension does not match corpus index")
        scores = np.asarray(self.matrix, dtype=np.float32) @ vector
        count = max(1, min(int(top_k), len(self.ids)))
        if count == len(self.ids):
            indices = np.argsort(-scores)
        else:
            pool = np.argpartition(-scores, count - 1)[:count]
            indices = pool[np.argsort(-scores[pool])]
        return [(self.ids[int(index)], float(scores[int(index)])) for index in indices]


def build_dense_artifacts(
    *,
    model_dir: str | Path,
    output_dir: str | Path,
    chunk_ids: list[str],
    texts: list[str],
    passage_prefix: str = "passage: ",
    query_prefix: str = "query: ",
    batch_size: int = 16,
    max_length: int = 512,
) -> dict[str, Any]:
    """Build local dense artifacts; intended for an offline release-build step."""

    if len(chunk_ids) != len(texts) or not chunk_ids:
        raise ValueError("chunk_ids and texts must have the same non-zero length")
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    encoder = OnnxTextEncoder(model_dir, max_length=max_length)
    vectors: list[np.ndarray] = []
    for start in range(0, len(texts), max(1, batch_size)):
        vectors.append(encoder.encode(texts[start : start + batch_size], prefix=passage_prefix))
    matrix = np.concatenate(vectors, axis=0).astype(np.float16)
    np.save(root / "embeddings.f16.npy", matrix)
    (root / "embedding_ids.json").write_text(
        json.dumps(chunk_ids, ensure_ascii=False), encoding="utf-8"
    )
    manifest = {
        "schema_version": 1,
        "ids_file": "embedding_ids.json",
        "embeddings_file": "embeddings.f16.npy",
        "model_dir": "model",
        "query_prefix": query_prefix,
        "passage_prefix": passage_prefix,
        "max_length": max_length,
        "dimension": int(matrix.shape[1]),
        "count": int(matrix.shape[0]),
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest
