"""Verify and atomically install the pinned Prewise Qwen 3.5 LoRA bundle.

The source ZIP is never modified or deleted. The installer intentionally
extracts only the four adapter packages required by the runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

EXPECTED_SIZE = 385_630_295
EXPECTED_SHA256 = "0B20066CABD11DA1E3FF1FF90032B8CCF9E34AEDEACD007C88BA2819DCCFBAC5"
EXPECTED_BASE_MODEL = "Qwen/Qwen3.5-9B"
MIN_FREE_BYTES = 1_000_000_000
ADAPTERS = (
    "message-context-adapter",
    "web-context-adapter",
    "explanation-adapter",
    "legal-rag-adapter",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _safe_member(info: zipfile.ZipInfo) -> PurePosixPath:
    path = PurePosixPath(info.filename)
    if path.is_absolute() or ".." in path.parts or "\\" in info.filename:
        raise ValueError(f"unsafe ZIP member path: {info.filename!r}")
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        raise ValueError(f"symbolic links are not allowed in adapter ZIP: {info.filename!r}")
    return path


def _verify_checksum_file(path: Path) -> None:
    text = path.read_text(encoding="utf-8").strip()
    fields = text.split()
    if not fields or fields[0].upper() != EXPECTED_SHA256:
        raise ValueError("checksum file does not contain the pinned SHA256")


def _validate_installed(root: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for adapter in ADAPTERS:
        package = root / adapter / "current"
        config_path = package / "adapter_config.json"
        weights_path = package / "adapter_model.safetensors"
        if not config_path.is_file() or not weights_path.is_file():
            raise ValueError(f"incomplete installed adapter: {adapter}")
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if config.get("base_model_name_or_path") != EXPECTED_BASE_MODEL:
            raise ValueError(f"{adapter} declares an unexpected base model")
        if int(config.get("r", 0)) != 16:
            raise ValueError(f"{adapter} declares an unexpected LoRA rank")
        result[adapter] = {
            "path": str(package.resolve()),
            "weights_bytes": weights_path.stat().st_size,
            "base_model": EXPECTED_BASE_MODEL,
            "lora_rank": 16,
        }
    return result


def install(zip_path: Path, checksum_path: Path, target: Path) -> dict[str, object]:
    zip_path = zip_path.resolve()
    checksum_path = checksum_path.resolve()
    target = target.resolve()
    if not zip_path.is_file() or not checksum_path.is_file():
        raise FileNotFoundError("both ZIP and .sha256 files are required")
    if zip_path.stat().st_size != EXPECTED_SIZE:
        raise ValueError(
            f"ZIP size mismatch: got {zip_path.stat().st_size}, expected {EXPECTED_SIZE}"
        )
    actual_hash = sha256_file(zip_path)
    if actual_hash != EXPECTED_SHA256:
        raise ValueError(f"ZIP SHA256 mismatch: got {actual_hash}")
    _verify_checksum_file(checksum_path)

    target.parent.mkdir(parents=True, exist_ok=True)
    free_bytes = shutil.disk_usage(target.parent).free
    if free_bytes < MIN_FREE_BYTES:
        raise OSError(
            f"insufficient free space: {free_bytes} bytes available, "
            f"{MIN_FREE_BYTES} required"
        )
    if target.exists():
        installed = _validate_installed(target)
        return {
            "status": "already_installed",
            "zip": str(zip_path),
            "checksum_file": str(checksum_path),
            "zip_bytes": EXPECTED_SIZE,
            "sha256": actual_hash,
            "zip_test": "passed",
            "free_bytes_before": free_bytes,
            "target": str(target),
            "adapters": installed,
        }

    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}-", dir=target.parent))
    try:
        with zipfile.ZipFile(zip_path) as archive:
            bad_member = archive.testzip()
            if bad_member:
                raise ValueError(f"ZIP CRC test failed at {bad_member!r}")
            required_weights = {
                f"{adapter}/current/adapter_model.safetensors" for adapter in ADAPTERS
            }
            names = {info.filename for info in archive.infolist()}
            missing = sorted(required_weights - names)
            if missing:
                raise ValueError(f"ZIP is missing required adapter weights: {missing}")
            for info in archive.infolist():
                member = _safe_member(info)
                if len(member.parts) < 2 or member.parts[0] not in ADAPTERS:
                    continue
                destination = staging.joinpath(*member.parts)
                if info.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, destination.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
        installed = _validate_installed(staging)
        os.replace(staging, target)
        installed = _validate_installed(target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    report = {
        "status": "installed",
        "zip": str(zip_path),
        "checksum_file": str(checksum_path),
        "zip_bytes": EXPECTED_SIZE,
        "sha256": actual_hash,
        "zip_test": "passed",
        "free_bytes_before": free_bytes,
        "target": str(target),
        "adapters": installed,
    }
    report_path = target / "install-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True, type=Path)
    parser.add_argument("--checksum", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    args = parser.parse_args()
    report = install(args.zip, args.checksum, args.target)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
