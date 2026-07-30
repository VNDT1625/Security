from pathlib import Path

SCRIPT = Path("scripts/codespaces-demo-up.sh")
PREPARE_SCRIPT = Path("scripts/codespaces-demo-prepare.sh")


def test_codespaces_mounts_verified_adapter_runtime() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "/workspaces/prewise-qwen35-9b-four-adapters/runtime" in text
    assert "/app/server/adapters/qwen35-backend-manifest.json" in text


def test_gateway_is_recreated_before_health_wait() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    recreate = text.index("up -d --force-recreate --no-deps api-gateway")
    health_wait = text.index('echo "Waiting for the Prewise API..."')
    assert recreate < health_wait


def test_codespaces_refreshes_gmail_oauth_secrets_on_every_start() -> None:
    start_text = SCRIPT.read_text(encoding="utf-8")
    prepare_text = PREPARE_SCRIPT.read_text(encoding="utf-8")

    assert "bash scripts/codespaces-demo-prepare.sh" in start_text
    assert "if [[ ! -f .env.codespaces ]]" not in start_text
    for name in (
        "GMAIL_OAUTH_CLIENT_ID",
        "GMAIL_OAUTH_CLIENT_SECRET",
        "GMAIL_TOKEN_ENCRYPTION_KEYS",
        "GMAIL_OAUTH_REDIRECT_URI",
        "GMAIL_WEB_RETURN_URL",
    ):
        assert name in prepare_text
    assert "sync_codespaces_secret" in prepare_text
    assert "chmod 600" in prepare_text
