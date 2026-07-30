import secrets
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.db import SessionLocal
from backend.main import app
from backend.models import (
    ApiKey,
    ReportShare,
    ScanEvent,
    ScanEvidence,
    SessionRecord,
    Subscription,
    User,
    UserFeedback,
)
from backend.routers import auth
from backend.routers.sandbox_cloud import account_tier
from backend.security_utils import utcnow

client = TestClient(app)


def login_demo() -> dict:
    response = client.post(
        "/v1/auth/login",
        json={"email": "demo@aisec.local", "password": "Demo@123456"},
    )
    assert response.status_code == 200
    return response.json()


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def set_active_plan(email: str, plan_tier: str) -> None:
    with SessionLocal() as db:
        user = auth.verify_user(db, email, "StrongPass!123")
        subscription = db.execute(
            select(Subscription)
            .where(Subscription.user_id == user.id, Subscription.status == "active")
            .order_by(Subscription.created_at.desc())
        ).scalars().first()
        assert subscription is not None
        subscription.plan_tier = plan_tier
        db.commit()


def test_account_endpoints_require_bearer_session() -> None:
    for method, path in (
        ("GET", "/v1/account/plan"),
        ("GET", "/v1/account/history"),
        ("GET", "/v1/account/api-key"),
        ("POST", "/v1/account/api-key/rotate"),
        ("POST", "/v1/auth/logout"),
    ):
        response = client.request(method, path)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"


def test_login_allows_account_access_and_logout_revokes_token() -> None:
    session = login_demo()
    headers = bearer(session["token"])

    plan = client.get("/v1/account/plan", headers=headers)
    assert plan.status_code == 200
    assert plan.json()["tier"] == "free"

    logout = client.post("/v1/auth/logout", headers=headers)
    assert logout.status_code == 200
    assert client.get("/v1/account/plan", headers=headers).status_code == 401


def test_authenticated_scan_persists_to_history_and_quota() -> None:
    session = login_demo()
    headers = bearer(session["token"])
    before_quota = client.get("/v1/account/quota", headers=headers).json()

    scan = client.post(
        "/v1/assess/url",
        headers=headers,
        json={"url": "https://quota-scan.example.test", "force_rescan": True},
    )
    assert scan.status_code == 200
    request_id = scan.json()["request_id"]

    history = client.get("/v1/account/history", headers=headers)
    after_quota = client.get("/v1/account/quota", headers=headers).json()

    assert history.status_code == 200
    saved = next(item for item in history.json() if item["id"] == request_id)
    assert saved["type"] == "URL"
    assert saved["target"] == "https://quota-scan.example.test"
    assert saved["decision"]
    assert 0 <= saved["confidence"] <= 100
    assert isinstance(saved["evidence"], list)
    assert after_quota["usedToday"] == before_quota["usedToday"] + 1


def test_history_detail_is_owner_only_and_privacy_minimised() -> None:
    owner_email = f"history-owner-{secrets.token_hex(4)}@example.com"
    other_email = f"history-other-{secrets.token_hex(4)}@example.com"
    owner = client.post(
        "/v1/auth/register",
        json={"email": owner_email, "password": "StrongPass!123", "displayName": "Owner"},
    ).json()
    other = client.post(
        "/v1/auth/register",
        json={"email": other_email, "password": "StrongPass!123", "displayName": "Other"},
    ).json()
    request_id = f"history-{secrets.token_hex(8)}"
    with SessionLocal() as db:
        user = auth.verify_user(db, owner_email, "StrongPass!123")
        event = ScanEvent(
            request_id=request_id,
            user_id=user.id,
            channel="web",
            modality="url",
            normalized_url="https://user:pass@example.test/private/reset?token=super-secret#otp",
            input_preview="password: hunter2 admin@example.test +84901234567",
            risk_score=0.73,
            risk_level="high",
            decision="block",
            confidence=0.91,
            model_version="test-model",
            latency_ms=12.5,
            risk_core_trace={"raw_score": 73, "url": "https://secret.test/a", "token": "secret"},
            extra_metadata={},
        )
        db.add(event)
        db.flush()
        db.add(ScanEvidence(
            scan_event_id=event.id,
            source="scanner",
            message="Liên hệ admin@example.test hoặc +84901234567 qua https://secret.test",
            severity="high",
            feature="credential",
        ))
        db.commit()

    detail = client.get(f"/v1/account/history/{request_id}", headers=bearer(owner["token"]))
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["target"] == "https://example.test/…"
    assert payload["riskCore"] == {"raw_score": 73}
    serialized = detail.text
    assert "super-secret" not in serialized
    assert "admin@example.test" not in serialized
    assert "+84901234567" not in serialized
    assert "secret.test" not in serialized

    assert client.get(
        f"/v1/account/history/{request_id}", headers=bearer(other["token"])
    ).status_code == 404
    assert client.delete(
        f"/v1/account/history/{request_id}", headers=bearer(other["token"])
    ).status_code == 404


def test_history_delete_removes_owned_evidence_and_feedback_only() -> None:
    email = f"history-delete-{secrets.token_hex(4)}@example.com"
    session = client.post(
        "/v1/auth/register",
        json={"email": email, "password": "StrongPass!123", "displayName": "Delete"},
    ).json()
    request_id = f"delete-{secrets.token_hex(8)}"
    with SessionLocal() as db:
        user = auth.verify_user(db, email, "StrongPass!123")
        event = ScanEvent(
            request_id=request_id, user_id=user.id, channel="web", modality="email",
            input_preview="masked preview", risk_score=0.2, risk_level="low", decision="allow",
            confidence=0.8, model_version="test-model", latency_ms=1, extra_metadata={},
        )
        db.add(event)
        db.flush()
        evidence = ScanEvidence(
            scan_event_id=event.id, source="test", message="test", severity="low"
        )
        feedback = UserFeedback(
            scan_event_id=event.id, user_id=user.id, label="false_positive", reason="other"
        )
        share = ReportShare(
            user_id=user.id,
            scan_event_id=event.id,
            token_hash=secrets.token_hex(32),
            snapshot={"score": 20},
            expires_at=utcnow() + timedelta(days=1),
        )
        db.add_all([evidence, feedback, share])
        db.commit()
        event_id, evidence_id, feedback_id, share_id = event.id, evidence.id, feedback.id, share.id

    response = client.delete(
        f"/v1/account/history/{request_id}", headers=bearer(session["token"])
    )
    assert response.status_code == 200
    assert response.json() == {"deleted": 1}
    with SessionLocal() as db:
        assert db.get(ScanEvent, event_id) is None
        assert db.get(ScanEvidence, evidence_id) is None
        assert db.get(UserFeedback, feedback_id) is None
        assert db.get(ReportShare, share_id) is None
    assert client.get(
        f"/v1/account/history/{request_id}", headers=bearer(session["token"])
    ).status_code == 404


def test_api_keys_are_scoped_per_user_and_rotate_independently() -> None:
    first_email = f"team-first-{secrets.token_hex(4)}@example.com"
    first = client.post(
        "/v1/auth/register",
        json={"email": first_email, "password": "StrongPass!123", "displayName": "First"},
    ).json()
    second_email = f"team-second-{secrets.token_hex(4)}@example.com"
    second = client.post(
        "/v1/auth/register",
        json={"email": second_email, "password": "StrongPass!123", "displayName": "Second"},
    ).json()
    set_active_plan(first_email, "team")
    set_active_plan(second_email, "team")
    first_headers = bearer(first["token"])
    second_headers = bearer(second["token"])
    first_key = client.get("/v1/account/api-key", headers=first_headers).json()["key"]
    second_key = client.get("/v1/account/api-key", headers=second_headers).json()["key"]
    assert second_key != first_key

    rotated_key = client.post("/v1/account/api-key/rotate", headers=second_headers).json()["key"]
    assert rotated_key != second_key
    unchanged_first_key = client.get(
        "/v1/account/api-key", headers=first_headers
    ).json()["key"]
    assert unchanged_first_key == first_key


def test_api_key_requires_team_entitlement_server_side() -> None:
    free = login_demo()
    assert client.get("/v1/account/api-key", headers=bearer(free["token"])).status_code == 403
    assert client.post("/v1/account/api-key/rotate", headers=bearer(free["token"])).status_code == 403


def test_expired_subscription_loses_plan_and_sandbox_entitlements() -> None:
    email = f"pro-expired-{secrets.token_hex(4)}@example.com"
    registration = client.post(
        "/v1/auth/register",
        json={"email": email, "password": "StrongPass!123", "displayName": "Expired"},
    ).json()
    with SessionLocal() as db:
        user = auth.verify_user(db, email, "StrongPass!123")
        subscription = db.execute(
            select(Subscription)
            .where(Subscription.user_id == user.id, Subscription.status == "active")
            .order_by(Subscription.created_at.desc())
        ).scalars().first()
        assert subscription is not None
        subscription.plan_tier = "pro"
        subscription.renews_at = utcnow() - timedelta(seconds=1)
        db.commit()
        assert account_tier(db, user.id) == "free"

    plan = client.get("/v1/account/plan", headers=bearer(registration["token"]))
    assert plan.status_code == 200
    assert plan.json()["tier"] == "free"


def test_invalid_bearer_token_is_rejected() -> None:
    response = client.get("/v1/account/api-key", headers=bearer("invalid-token"))
    assert response.status_code == 401


def test_public_registration_cannot_self_assign_paid_plan_or_api_key() -> None:
    for paid_hint in ("pro", "team"):
        email = f"{paid_hint}-self-upgrade-{secrets.token_hex(4)}@example.com"
        response = client.post(
            "/v1/auth/register",
            json={"email": email, "password": "StrongPass!123", "displayName": "Free User"},
        )
        assert response.status_code == 200
        assert response.json()["plan"]["tier"] == "free"
        with SessionLocal() as db:
            user = auth.verify_user(db, email, "StrongPass!123")
            assert db.execute(
                select(ApiKey).where(ApiKey.user_id == user.id)
            ).scalar_one_or_none() is None


def test_profile_update_and_password_change() -> None:
    email = f"profile-{secrets.token_hex(4)}@example.com"
    old_password = "StrongPass!123"
    new_password = "NewStrongPass!456"
    registration = client.post(
        "/v1/auth/register",
        json={"email": email, "password": old_password, "displayName": "Before"},
    )
    token = registration.json()["token"]
    headers = bearer(token)

    profile = client.patch(
        "/v1/account/profile",
        headers=headers,
        json={
            "displayName": "  After   Name  ",
            "organizationName": "  Prewise   Security  ",
            "jobTitle": "  Security   Analyst ",
            "countryCode": "VN",
            "locale": "vi",
            "timezone": "Asia/Ho_Chi_Minh",
        },
    )
    assert profile.status_code == 200
    body = profile.json()
    assert body["displayName"] == "After Name"
    assert body["organizationName"] == "Prewise Security"
    assert body["jobTitle"] == "Security Analyst"
    assert body["countryCode"] == "VN"
    assert body["locale"] == "vi"
    assert body["timezone"] == "Asia/Ho_Chi_Minh"
    assert body["emailVerified"] is False
    assert body["status"] == "active"
    assert body["createdAt"]
    assert body["updatedAt"]
    assert body["lastLoginAt"]

    persisted = client.get("/v1/account/profile", headers=headers)
    assert persisted.status_code == 200
    assert persisted.json() == body
    with SessionLocal() as db:
        account = db.execute(select(User).where(User.email == email)).scalar_one()
        assert account.organization_name == "Prewise Security"
        assert account.job_title == "Security Analyst"
        assert account.country_code == "VN"
        assert account.preferred_locale == "vi"
        assert account.timezone == "Asia/Ho_Chi_Minh"

    invalid = client.patch(
        "/v1/account/profile",
        headers=headers,
        json={**{
            "displayName": "After Name",
            "organizationName": None,
            "jobTitle": None,
            "countryCode": "VN",
            "locale": "vi",
        }, "timezone": "Invalid/Zone"},
    )
    assert invalid.status_code == 422

    wrong = client.post(
        "/v1/account/password",
        headers=headers,
        json={"currentPassword": "incorrect", "newPassword": new_password},
    )
    assert wrong.status_code == 400

    changed = client.post(
        "/v1/account/password",
        headers=headers,
        json={"currentPassword": old_password, "newPassword": new_password},
    )
    assert changed.status_code == 200
    assert client.post("/v1/auth/login", json={"email": email, "password": old_password}).status_code == 401
    assert client.post("/v1/auth/login", json={"email": email, "password": new_password}).status_code == 200


def test_production_password_reset_sends_link_without_exposing_token(monkeypatch) -> None:
    from backend.services import release_email_service

    email = f"password-reset-{secrets.token_hex(4)}@example.com"
    registration = client.post(
        "/v1/auth/register",
        json={"email": email, "password": "StrongPass!123", "displayName": "Reset User"},
    )
    assert registration.status_code == 200

    sent: dict[str, str] = {}
    monkeypatch.setattr(auth.settings, "app_env", "production")
    monkeypatch.setattr(release_email_service, "email_configured", lambda: True)
    monkeypatch.setattr(
        release_email_service,
        "send_password_reset_email",
        lambda *, recipient, reset_url: sent.update(recipient=recipient, reset_url=reset_url) or True,
    )

    response = client.post("/v1/auth/password/forgot", json={"email": email})

    assert response.status_code == 200
    assert "resetToken" not in response.json()
    assert sent["recipient"] == email
    assert sent["reset_url"].startswith("https://www.prewise.site/auth?mode=reset&token=")


def test_production_password_reset_fails_closed_without_email_provider(monkeypatch) -> None:
    from backend.services import release_email_service

    monkeypatch.setattr(auth.settings, "app_env", "production")
    monkeypatch.setattr(release_email_service, "email_configured", lambda: False)

    response = client.post(
        "/v1/auth/password/forgot",
        json={"email": f"unknown-{secrets.token_hex(4)}@example.com"},
    )

    assert response.status_code == 503


def test_paid_subscription_can_be_canceled() -> None:
    email = f"pro-{secrets.token_hex(4)}@example.com"
    registration = client.post(
        "/v1/auth/register",
        json={"email": email, "password": "StrongPass!123", "displayName": "Pro Member"},
    )
    assert registration.status_code == 200
    assert registration.json()["plan"]["tier"] == "free"
    set_active_plan(email, "pro")
    headers = bearer(registration.json()["token"])
    response = client.post("/v1/account/subscription/cancel", headers=headers)
    assert response.status_code == 200
    assert response.json()["tier"] == "free"


def test_expired_session_is_rejected_and_removed() -> None:
    session = login_demo()
    key = auth.session_key(session["token"])
    with SessionLocal() as db:
        record = db.execute(
            select(SessionRecord).where(SessionRecord.token_hash == key)
        ).scalar_one()
        record.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()

    response = client.get("/v1/account/plan", headers=bearer(session["token"]))

    assert response.status_code == 401
    with SessionLocal() as db:
        assert (
            db.execute(select(SessionRecord).where(SessionRecord.token_hash == key)).scalar_one_or_none()
            is None
        )
