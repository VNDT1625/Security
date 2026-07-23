import json
from pathlib import Path

import pytest

from ai_server.launcher import build_command, detect_model_package


def _base_env(model_dir: Path) -> dict[str, str]:
    return {
        "LLM_MODEL_PATH": str(model_dir),
        "LLM_API_KEY": "test-secret",
        "LLM_SERVED_MODEL_NAME": "prewise-security-v1",
    }


def test_builds_vllm_command_for_merged_model(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")
    (tmp_path / "model.safetensors").write_bytes(b"placeholder")
    (tmp_path / "model-manifest.json").write_text(
        json.dumps({"context_length": 2048}), encoding="utf-8"
    )

    command = build_command(_base_env(tmp_path))

    assert command[:3] == ["vllm", "serve", str(tmp_path.resolve())]
    assert command[command.index("--served-model-name") + 1] == "prewise-security-v1"
    assert command[command.index("--max-model-len") + 1] == "2048"
    assert command[command.index("--api-key") + 1] == "test-secret"


def test_builds_vllm_command_for_lora_model(tmp_path: Path) -> None:
    (tmp_path / "adapter_model.safetensors").write_bytes(b"placeholder")
    (tmp_path / "adapter_config.json").write_text(
        json.dumps({"base_model_name_or_path": "org/base-model"}), encoding="utf-8"
    )

    command = build_command(_base_env(tmp_path))

    assert command[2] == "org/base-model"
    assert "--enable-lora" in command
    assert f"prewise-security-v1={tmp_path.resolve()}" in command


def test_refuses_public_server_without_api_key(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")
    (tmp_path / "model.safetensors").write_bytes(b"placeholder")

    with pytest.raises(ValueError, match="LLM_API_KEY"):
        build_command({"LLM_MODEL_PATH": str(tmp_path), "LLM_SERVER_HOST": "0.0.0.0"})


def test_rejects_incomplete_adapter_package(tmp_path: Path) -> None:
    (tmp_path / "adapter_config.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="adapter_model"):
        detect_model_package(tmp_path)


def test_builds_one_vllm_server_with_four_loras(tmp_path: Path) -> None:
    adapters = []
    for name in ("message", "web", "explanation", "legal"):
        path = tmp_path / name
        path.mkdir()
        (path / "adapter_config.json").write_text(
            json.dumps({"base_model_name_or_path": "Qwen/Qwen3.5-4B"}),
            encoding="utf-8",
        )
        (path / "adapter_model.safetensors").write_bytes(b"placeholder")
        adapters.append(
            {
                "adapter_id": name,
                "task": f"{name}-context-adapter" if name != "explanation" else "explanation-adapter",
                "path": name,
                "served_model_name": f"{name}-adapter",
                "enabled": True,
            }
        )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "base_model": "Qwen/Qwen3.5-4B",
                "adapters": adapters,
            }
        ),
        encoding="utf-8",
    )

    command = build_command(
        {
            "ADAPTER_MANIFEST_PATH": str(manifest),
            "LLM_API_KEY": "test-secret",
        }
    )

    assert command[:3] == ["vllm", "serve", "Qwen/Qwen3.5-4B"]
    assert "--enable-lora" in command
    assert command[command.index("--max-lora-rank") + 1] == "16"
    assert command[command.index("--max-loras") + 1] == "4"
    assert sum("adapter=" in item for item in command) == 4
