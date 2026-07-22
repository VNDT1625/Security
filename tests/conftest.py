"""Shared test isolation for settings backed by persistent local storage."""

import os
import tempfile
from pathlib import Path

import pytest

# Select a process-owned database before any test module imports backend.db.
# This prevents test quota/history writes from touching the developer database.
_TEST_DATABASE_PATH = (
    Path(tempfile.gettempdir()) / f"aisec-pytest-{os.getpid()}.db"
).resolve()
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DATABASE_PATH.as_posix()}"

# Local OAuth credentials must not leak into tests that exercise the
# unconfigured integration and production-default validation paths.
for _name in (
    "GMAIL_OAUTH_CLIENT_ID",
    "GMAIL_OAUTH_CLIENT_SECRET",
    "GMAIL_OAUTH_REDIRECT_URI",
    "GMAIL_TOKEN_ENCRYPTION_KEYS",
    "GMAIL_WEB_RETURN_URL",
):
    os.environ[_name] = ""

from backend.config import settings  # noqa: E402  # env must be set before import


@pytest.fixture(autouse=True)
def isolate_runtime_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent repeated local test runs from exhausting the production-like quota DB."""

    monkeypatch.setattr(settings, "anonymous_daily_scan_limit", 1_000_000)
    monkeypatch.setattr(settings, "anonymous_daily_ai_credit_limit", 1_000_000)
    monkeypatch.setattr(settings, "anonymous_daily_deep_scan_limit", 1_000_000)
    monkeypatch.setattr(settings, "local_testing_unlimited", False)
    # Assessments must exercise the current model/policy, not a persistent result
    # left in .aisec-data/armor.db by an earlier local test run.
    monkeypatch.setattr(settings, "shared_assessment_cache_enabled", False)
    yield

    # Starlette keeps middleware instances for the lifetime of the imported app.
    # Clearing the in-memory bucket between tests prevents unrelated integration
    # cases from consuming one another's per-IP production allowance.
    from backend.main import app
    from backend.middleware import RateLimiterMiddleware

    current = app.middleware_stack
    while current is not None:
        if isinstance(current, RateLimiterMiddleware):
            current._buckets.clear()
            break
        current = getattr(current, "app", None)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Dispose SQLite handles, then remove only this pytest process's database."""

    from backend.db import engine

    engine.dispose()
    if (
        _TEST_DATABASE_PATH.parent == Path(tempfile.gettempdir()).resolve()
        and _TEST_DATABASE_PATH.name == f"aisec-pytest-{os.getpid()}.db"
    ):
        _TEST_DATABASE_PATH.unlink(missing_ok=True)
