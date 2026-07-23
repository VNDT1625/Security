from pathlib import Path


SCRIPT = Path("scripts/codespaces-demo-up.sh")


def test_codespaces_mounts_verified_adapter_runtime() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "/workspaces/prewise-qwen35-9b-four-adapters/runtime" in text
    assert "/app/server/adapters/qwen35-backend-manifest.json" in text


def test_gateway_is_recreated_before_health_wait() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    recreate = text.index("up -d --force-recreate --no-deps api-gateway")
    health_wait = text.index('echo "Waiting for the Prewise API..."')
    assert recreate < health_wait
