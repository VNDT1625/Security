from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path

import pytest

from scripts import install_qwen35_adapters as installer


def _bundle(tmp_path: Path, *, unsafe: bool = False) -> tuple[Path, Path]:
    archive_path = tmp_path / "adapters.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in installer.ADAPTERS:
            root = f"{name}/current"
            archive.writestr(
                f"{root}/adapter_config.json",
                json.dumps(
                    {
                        "base_model_name_or_path": installer.EXPECTED_BASE_MODEL,
                        "r": 16,
                    }
                ),
            )
            archive.writestr(f"{root}/adapter_model.safetensors", b"test-weights")
        if unsafe:
            archive.writestr("../escape.txt", "blocked")
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest().upper()
    checksum_path = tmp_path / "adapters.zip.sha256"
    checksum_path.write_text(f"{digest}  adapters.zip\n", encoding="utf-8")
    return archive_path, checksum_path


def _patch_bundle_constants(monkeypatch, archive_path: Path) -> None:
    monkeypatch.setattr(installer, "EXPECTED_SIZE", archive_path.stat().st_size)
    monkeypatch.setattr(
        installer,
        "EXPECTED_SHA256",
        hashlib.sha256(archive_path.read_bytes()).hexdigest().upper(),
    )
    monkeypatch.setattr(installer, "MIN_FREE_BYTES", 1)


def test_installer_verifies_and_atomically_extracts_four_adapters(
    tmp_path: Path, monkeypatch
) -> None:
    archive_path, checksum_path = _bundle(tmp_path)
    _patch_bundle_constants(monkeypatch, archive_path)

    report = installer.install(archive_path, checksum_path, tmp_path / "runtime")

    assert report["status"] == "installed"
    assert set(report["adapters"]) == set(installer.ADAPTERS)
    assert (tmp_path / "runtime" / "install-report.json").is_file()
    assert not list(tmp_path.glob(".runtime-*"))
    if os.name != "nt":
        assert (tmp_path / "runtime").stat().st_mode & 0o777 == 0o755
        assert (
            tmp_path
            / "runtime"
            / "message-context-adapter"
            / "current"
            / "adapter_model.safetensors"
        ).stat().st_mode & 0o777 == 0o444


def test_installer_rejects_zip_slip_without_creating_target(
    tmp_path: Path, monkeypatch
) -> None:
    archive_path, checksum_path = _bundle(tmp_path, unsafe=True)
    _patch_bundle_constants(monkeypatch, archive_path)

    with pytest.raises(ValueError, match="unsafe ZIP member"):
        installer.install(archive_path, checksum_path, tmp_path / "runtime")

    assert not (tmp_path / "runtime").exists()
    assert not (tmp_path.parent / "escape.txt").exists()
