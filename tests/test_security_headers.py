from fastapi.testclient import TestClient

from backend.config import settings
from backend.main import app

client = TestClient(app)


def test_sensitive_auth_responses_are_not_cacheable() -> None:
    response = client.post(
        "/v1/auth/login",
        json={"email": "nobody@example.test", "password": "not-a-real-password"},
    )

    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "camera=()" in response.headers["permissions-policy"]


def test_hsts_is_only_emitted_in_production(monkeypatch) -> None:
    monkeypatch.setattr(settings, "app_env", "production")
    response = client.get("/v1/health")
    assert response.headers["strict-transport-security"] == (
        "max-age=31536000; includeSubDomains"
    )

    monkeypatch.setattr(settings, "app_env", "development")
    response = client.get("/v1/health")
    assert "strict-transport-security" not in response.headers
