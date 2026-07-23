"""Validate a drop-in model package and launch vLLM's OpenAI-compatible server.

The container deliberately delegates inference to vLLM.  This module owns the
stable environment contract, model-package validation, and safe defaults so a
new trained model can be deployed without changing application code.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from collections.abc import Mapping
from pathlib import Path


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _positive_int(env: Mapping[str, str], key: str, default: int) -> int:
    value = int(env.get(key, str(default)))
    if value < 1:
        raise ValueError(f"{key} must be at least 1")
    return value


def _ratio(env: Mapping[str, str], key: str, default: float) -> float:
    value = float(env.get(key, str(default)))
    if not 0 < value <= 1:
        raise ValueError(f"{key} must be greater than 0 and at most 1")
    return value


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON file: {path}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return data


def detect_model_package(model_path: Path) -> tuple[str, dict]:
    """Return (merged|lora, metadata) or raise with an actionable message."""
    if not model_path.is_dir():
        raise ValueError(f"Model directory does not exist: {model_path}")

    manifest = _load_json(model_path / "model-manifest.json")
    adapter_config = model_path / "adapter_config.json"
    if adapter_config.exists():
        has_adapter = any(
            (model_path / filename).exists()
            for filename in ("adapter_model.safetensors", "adapter_model.bin")
        )
        if not has_adapter:
            raise ValueError(
                "LoRA package is missing adapter_model.safetensors or adapter_model.bin"
            )
        config = _load_json(adapter_config)
        base_model = (
            manifest.get("base_model")
            or config.get("base_model_name_or_path")
            or ""
        )
        if not base_model:
            raise ValueError(
                "LoRA package must declare base_model in model-manifest.json "
                "or base_model_name_or_path in adapter_config.json"
            )
        return "lora", {**manifest, "base_model": str(base_model)}

    if not (model_path / "config.json").exists():
        raise ValueError(
            "Merged model package is missing config.json. "
            "Put a Hugging Face CausalLM model or a PEFT LoRA package in this directory."
        )
    weight_patterns = ("*.safetensors", "pytorch_model*.bin", "*.gguf")
    if not any(any(model_path.glob(pattern)) for pattern in weight_patterns):
        raise ValueError("Merged model package contains no supported model weights")
    return "merged", manifest


def _build_multi_lora_command(env: Mapping[str, str], manifest_path: Path) -> list[str]:
    manifest = _load_json(manifest_path)
    if str(manifest.get("schema_version", "")) != "1":
        raise ValueError("adapter manifest schema_version must be 1")
    base_model = env.get("LLM_BASE_MODEL", "").strip() or str(
        manifest.get("base_model", "")
    ).strip()
    if not base_model:
        raise ValueError("adapter manifest must declare base_model")
    rows = manifest.get("adapters")
    if not isinstance(rows, list):
        raise ValueError("adapter manifest adapters must be an array")
    modules: list[str] = []
    names: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not row.get("enabled", True):
            continue
        if row.get("runtime", "openai_lora") != "openai_lora":
            continue
        name = str(row.get("served_model_name", "")).strip()
        relative_path = str(row.get("path", "")).strip()
        if not name or not relative_path:
            raise ValueError("enabled LoRA adapters require served_model_name and path")
        if name in names:
            raise ValueError(f"duplicate served_model_name: {name}")
        names.add(name)
        adapter_path = Path(relative_path)
        if not adapter_path.is_absolute():
            adapter_path = manifest_path.parent / adapter_path
        adapter_path = adapter_path.resolve()
        package_type, metadata = detect_model_package(adapter_path)
        if package_type != "lora":
            raise ValueError(f"adapter path is not a LoRA package: {adapter_path}")
        declared_base = str(metadata.get("base_model", "")).strip()
        if declared_base and declared_base != base_model:
            raise ValueError(
                f"adapter {name} base_model {declared_base!r} does not match "
                f"manifest base_model {base_model!r}"
            )
        modules.append(f"{name}={adapter_path}")
    if not modules:
        raise ValueError("adapter manifest contains no enabled LoRA adapters")

    host = env.get("LLM_SERVER_HOST", "0.0.0.0")
    port = _positive_int(env, "LLM_SERVER_PORT", 8000)
    api_key = env.get("LLM_API_KEY", "").strip()
    if not api_key and host not in {"127.0.0.1", "localhost", "::1"}:
        if not _truthy(env.get("LLM_ALLOW_UNAUTHENTICATED")):
            raise ValueError("LLM_API_KEY is required when binding beyond localhost")
    command = [
        "vllm",
        "serve",
        base_model,
        "--host",
        host,
        "--port",
        str(port),
        "--max-model-len",
        str(
            _positive_int(
                env,
                "LLM_MAX_MODEL_LEN",
                int(manifest.get("context_length", 4096)),
            )
        ),
        "--tensor-parallel-size",
        str(_positive_int(env, "LLM_TENSOR_PARALLEL_SIZE", 1)),
        "--gpu-memory-utilization",
        str(_ratio(env, "LLM_GPU_MEMORY_UTILIZATION", 0.9)),
        "--dtype",
        env.get("LLM_DTYPE", "auto"),
        "--enable-lora",
        "--max-lora-rank",
        str(_positive_int(env, "LLM_MAX_LORA_RANK", 16)),
        "--max-loras",
        str(_positive_int(env, "LLM_MAX_LORAS", len(modules))),
        "--lora-modules",
        *modules,
    ]
    if api_key:
        command.extend(["--api-key", api_key])
    revision = env.get("LLM_BASE_REVISION", "").strip() or str(
        manifest.get("base_revision", "")
    ).strip()
    if revision:
        command.extend(["--revision", revision])
    quantization = env.get("LLM_QUANTIZATION", "").strip()
    if quantization:
        command.extend(["--quantization", quantization])
    if _truthy(env.get("LLM_TRUST_REMOTE_CODE")):
        command.append("--trust-remote-code")
    extra_args = env.get("LLM_VLLM_EXTRA_ARGS", "").strip()
    if extra_args:
        command.extend(shlex.split(extra_args))
    return command


def build_command(env: Mapping[str, str] | None = None) -> list[str]:
    env = os.environ if env is None else env
    adapter_manifest = env.get("ADAPTER_MANIFEST_PATH", "").strip()
    if adapter_manifest:
        manifest_path = Path(adapter_manifest).resolve()
        if manifest_path.exists():
            return _build_multi_lora_command(env, manifest_path)
    model_path = Path(env.get("LLM_MODEL_PATH", "/models/current")).resolve()
    package_type, metadata = detect_model_package(model_path)
    served_name = env.get("LLM_SERVED_MODEL_NAME", "prewise-security-v1").strip()
    if not served_name:
        raise ValueError("LLM_SERVED_MODEL_NAME cannot be empty")

    host = env.get("LLM_SERVER_HOST", "0.0.0.0")
    port = _positive_int(env, "LLM_SERVER_PORT", 8000)
    max_model_len = _positive_int(
        env, "LLM_MAX_MODEL_LEN", int(metadata.get("context_length", 4096))
    )
    tensor_parallel = _positive_int(env, "LLM_TENSOR_PARALLEL_SIZE", 1)
    gpu_utilization = _ratio(env, "LLM_GPU_MEMORY_UTILIZATION", 0.9)
    api_key = env.get("LLM_API_KEY", "").strip()
    if not api_key and host not in {"127.0.0.1", "localhost", "::1"}:
        if not _truthy(env.get("LLM_ALLOW_UNAUTHENTICATED")):
            raise ValueError(
                "LLM_API_KEY is required when binding beyond localhost. "
                "Set LLM_ALLOW_UNAUTHENTICATED=true only behind a trusted private ingress."
            )

    model_source = str(model_path)
    command = [
        "vllm", "serve", model_source,
        "--host", host,
        "--port", str(port),
        "--served-model-name", served_name,
        "--max-model-len", str(max_model_len),
        "--tensor-parallel-size", str(tensor_parallel),
        "--gpu-memory-utilization", str(gpu_utilization),
        "--dtype", env.get("LLM_DTYPE", "auto"),
    ]
    if api_key:
        command.extend(["--api-key", api_key])
    quantization = env.get("LLM_QUANTIZATION", "").strip()
    if quantization:
        command.extend(["--quantization", quantization])
    if _truthy(env.get("LLM_TRUST_REMOTE_CODE")):
        command.append("--trust-remote-code")

    if package_type == "lora":
        base_model = env.get("LLM_BASE_MODEL", "").strip() or str(metadata["base_model"])
        command[2] = base_model
        command.extend([
            "--enable-lora",
            "--lora-modules",
            f"{served_name}={model_path}",
        ])

    extra_args = env.get("LLM_VLLM_EXTRA_ARGS", "").strip()
    if extra_args:
        command.extend(shlex.split(extra_args))
    return command


def main() -> int:
    try:
        command = build_command()
    except (TypeError, ValueError) as exc:
        print(f"[prewise-ai] configuration error: {exc}", file=sys.stderr)
        return 2
    safe_command = [
        "***" if previous == "--api-key" else item
        for previous, item in zip([""] + command, command, strict=False)
    ]
    print(f"[prewise-ai] launching: {shlex.join(safe_command)}", flush=True)
    os.execvp(command[0], command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
