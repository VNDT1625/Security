import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_postgresql_alembic_ledger_accepts_all_revision_ids() -> None:
    migration_env = (ROOT / "migrations" / "env.py").read_text(encoding="utf-8")
    revisions = []
    for path in (ROOT / "migrations" / "versions").glob("*.py"):
        match = re.search(
            r'^revision\s*=\s*["\']([^"\']+)["\']',
            path.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        assert match is not None, f"Missing revision identifier in {path.name}"
        revisions.append(match.group(1))

    # Alembic's default VARCHAR(32) is already too narrow for this repository.
    assert any(len(revision) > 32 for revision in revisions)
    assert max(map(len, revisions)) <= 128
    assert "VARCHAR(128)" in migration_env
    assert "_ensure_postgresql_version_capacity(connection)" in migration_env


def test_production_image_uses_runtime_only_dependencies_and_fail_closed_health() -> None:
    dockerfile = (ROOT / "Dockerfile.backend").read_text(encoding="utf-8")
    runtime_requirements = (ROOT / "requirements.runtime.txt").read_text(encoding="utf-8")
    development_requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    backend_ignore = (ROOT / "Dockerfile.backend.dockerignore").read_text(
        encoding="utf-8"
    )

    assert "requirements.runtime.txt" in dockerfile
    assert "requirements.txt ./" not in dockerfile
    assert "pytest" not in runtime_requirements.lower()
    assert "mcp>=1.0.0,<2" in runtime_requirements
    assert "-r requirements.runtime.txt" in development_requirements
    assert "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" in dockerfile
    assert "--only-shell chromium" in dockerfile
    assert 'chmod -R a+rX "${PLAYWRIGHT_BROWSERS_PATH}"' in dockerfile
    assert "chromium.launch(headless=True)" in dockerfile
    assert "http://localhost:8000/v1/ready" in dockerfile
    assert "frontend" in backend_ignore.splitlines()
    assert not (ROOT / ".dockerignore").exists()


def test_ci_production_gate_covers_migrations_and_runtime_readiness() -> None:
    workflow_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    workflow = yaml.safe_load(workflow_text)
    production_gate = workflow["jobs"]["production-gate"]
    rendered_steps = "\n".join(
        str(value)
        for step in production_gate["steps"]
        for value in step.values()
    )

    assert set(production_gate["needs"]) == {"backend", "web"}
    assert "alembic downgrade base" in rendered_steps
    assert "alembic upgrade head" in rendered_steps
    assert "/v1/ready" in rendered_steps
    assert "down -v --remove-orphans" in rendered_steps


def test_production_compose_backs_up_before_migration_and_passes_release_email_env() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.production.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert services["migrate"]["depends_on"]["database-backup"]["condition"] == "service_completed_successfully"
    assert "pg_dump" in " ".join(services["database-backup"]["command"])
    backend_env = services["backend"]["environment"]
    for name in ("CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN", "PREWISE_EMAIL_FROM"):
        assert name in backend_env
