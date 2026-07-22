import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.db import SessionLocal
from backend.main import app
from backend.models import Subscription
from backend.routers import auth

client = TestClient(app)


def _register(label: str, plan_tier: str | None = None) -> str:
    suffix = uuid.uuid4().hex
    email = f"{label}-{suffix}@example.com"
    response = client.post(
        "/v1/auth/register",
        json={
            "email": email,
            "displayName": label,
            "password": "SecurePassword123",
        },
    )
    assert response.status_code == 200, response.text
    if plan_tier is not None:
        with SessionLocal() as db:
            user = auth.verify_user(db, email, "SecurePassword123")
            subscription = db.execute(
                select(Subscription)
                .where(Subscription.user_id == user.id, Subscription.status == "active")
                .order_by(Subscription.created_at.desc())
            ).scalars().first()
            assert subscription is not None
            subscription.plan_tier = plan_tier
            db.commit()
    return response.json()["token"]


def test_ai_settings_require_a_signed_in_user() -> None:
    assert client.get("/v1/account/ai-settings").status_code == 401
    assert client.put(
        "/v1/account/ai-settings",
        json={"provider": "auto", "baseUrl": "", "model": ""},
    ).status_code == 401


def test_each_user_owns_an_independent_ai_model_selection() -> None:
    first = _register("first-ai-user")
    second = _register("second-ai-user")
    first_headers = {"Authorization": f"Bearer {first}"}
    second_headers = {"Authorization": f"Bearer {second}"}

    first_saved = client.put(
        "/v1/account/ai-settings",
        headers=first_headers,
        json={
            "provider": "local",
            "baseUrl": "http://127.0.0.1:11434/v1",
            "model": "first-user-model",
        },
    )
    second_saved = client.put(
        "/v1/account/ai-settings",
        headers=second_headers,
        json={
            "provider": "local",
            "baseUrl": "http://127.0.0.1:11435/v1",
            "model": "second-user-model",
        },
    )
    assert first_saved.status_code == 200, first_saved.text
    assert second_saved.status_code == 200, second_saved.text

    first_value = client.get("/v1/account/ai-settings", headers=first_headers).json()
    second_value = client.get("/v1/account/ai-settings", headers=second_headers).json()
    assert first_value["model"] == "first-user-model"
    assert second_value["model"] == "second-user-model"
    assert first_value["baseUrl"] != second_value["baseUrl"]
    assert first_value["source"] == second_value["source"] == "account"


def test_user_api_key_is_encrypted_and_never_returned() -> None:
    token = _register("encrypted-ai-user")
    headers = {"Authorization": f"Bearer {token}"}
    secret = "sk-user-owned-secret"
    response = client.put(
        "/v1/account/ai-settings",
        headers=headers,
        json={
            "provider": "endpoint",
            "baseUrl": "https://api.example.com/v1",
            "model": "private-model",
            "apiKey": secret,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["apiKeyConfigured"] is True
    assert secret not in response.text
    assert secret not in client.get("/v1/account/ai-settings", headers=headers).text


def test_ai_weight_is_pro_only_and_a_rejected_request_does_not_save_provider() -> None:
    token = _register("free-weight-user")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.put(
        "/v1/account/ai-settings",
        headers=headers,
        json={
            "provider": "local",
            "baseUrl": "http://127.0.0.1:11434/v1",
            "model": "must-not-be-saved",
            "weightPercent": 10,
        },
    )
    assert response.status_code == 403
    current = client.get("/v1/account/ai-settings", headers=headers).json()
    assert current["weightEligible"] is False
    assert current["model"] != "must-not-be-saved"
    assert current["source"] != "account"


def test_pro_users_have_independent_ai_weights_within_admin_bounds() -> None:
    first_headers = {"Authorization": f"Bearer {_register('pro-weight-first', 'pro')}"}
    second_headers = {"Authorization": f"Bearer {_register('pro-weight-second', 'pro')}"}
    for headers, model, weight in (
        (first_headers, "first-pro-model", 10),
        (second_headers, "second-pro-model", 30),
    ):
        response = client.put(
            "/v1/account/ai-settings",
            headers=headers,
            json={
                "provider": "local",
                "baseUrl": "http://127.0.0.1:11434/v1",
                "model": model,
                "weightPercent": weight,
            },
        )
        assert response.status_code == 200, response.text
    first_value = client.get("/v1/account/ai-settings", headers=first_headers).json()
    second_value = client.get("/v1/account/ai-settings", headers=second_headers).json()
    assert first_value["weightEligible"] is second_value["weightEligible"] is True
    assert first_value["weightPercent"] == 10
    assert second_value["weightPercent"] == 30
    assert first_value["weightSource"] == second_value["weightSource"] == "account"


def test_auto_clears_the_personal_provider_override() -> None:
    headers = {"Authorization": f"Bearer {_register('reset-ai-user')}"}
    saved = client.put(
        "/v1/account/ai-settings",
        headers=headers,
        json={
            "provider": "local",
            "baseUrl": "http://127.0.0.1:11434/v1",
            "model": "temporary-personal-model",
        },
    )
    assert saved.status_code == 200, saved.text
    reset = client.put(
        "/v1/account/ai-settings",
        headers=headers,
        json={"provider": "auto", "baseUrl": "", "model": ""},
    )
    assert reset.status_code == 200, reset.text
    current = client.get("/v1/account/ai-settings", headers=headers).json()
    assert current["source"] != "account"
    assert current["model"] != "temporary-personal-model"
