from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from backend.db import Base
from backend.models import ApiKey, Plan, Subscription, User
from backend.security_utils import (
    create_api_key_value,
    create_password_salt,
    hash_api_key,
    hash_password,
)
from mcp_server import auth as mcp_auth
from mcp_server import oauth as mcp_oauth
from mcp_server.auth import MCPApiKeyMiddleware
from mcp_server.server import build_server


def _app(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(mcp_auth, "SessionLocal", factory)
    monkeypatch.setattr(mcp_auth, "initialize_database", lambda: None)
    monkeypatch.setattr(mcp_oauth, "SessionLocal", factory)
    salt = create_password_salt()
    raw_key = create_api_key_value()
    with factory() as db:
        db.add(Plan(tier="team", label="TEAM", features={}))
        user = User(
                email="oauth@test.local",
                display_name="OAuth User",
                password_salt=salt,
                password_hash=hash_password("SecurePassword123", salt),
            )
        db.add(user)
        db.flush()
        db.add(Subscription(user_id=user.id, plan_tier="team", status="active"))
        db.add(ApiKey(user_id=user.id, key_prefix=raw_key[:16], key_tail=raw_key[-4:], key_hash=hash_api_key(raw_key), scopes=["mcp:invoke"]))
        db.commit()
    return MCPApiKeyMiddleware(build_server().streamable_http_app()), raw_key


def test_oauth_discovery_authorization_pkce_and_refresh_rotation(monkeypatch) -> None:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")

    app, raw_key = _app(monkeypatch)
    with TestClient(app) as client:
        metadata = client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        assert metadata.json()["resource"] == "https://api.prewise.site/mcp"

        registration = client.post(
            "/register",
            json={
                "redirect_uris": ["https://example.com/callback"],
                "client_name": "ChatGPT test",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": "mcp:invoke",
            },
        )
        assert registration.status_code == 201
        client_id = registration.json()["client_id"]

        authorize = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://example.com/callback",
                "scope": "mcp:invoke",
                "state": "state-value",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": "https://api.prewise.site/mcp",
            },
            follow_redirects=False,
        )
        request_id = parse_qs(urlparse(authorize.headers["location"]).query)["request"][0]

        consent = client.post(
            "/oauth/consent",
            data={
                "request": request_id,
                "api_key": raw_key,
            },
            follow_redirects=False,
        )
        assert consent.status_code == 303
        callback = parse_qs(urlparse(consent.headers["location"]).query)
        assert callback["state"] == ["state-value"]

        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": callback["code"][0],
                "redirect_uri": "https://example.com/callback",
                "code_verifier": verifier,
                "resource": "https://api.prewise.site/mcp",
            },
        )
        assert token.status_code == 200
        first = token.json()
        assert first["access_token"].startswith("pw_oauth_at_")
        assert first["refresh_token"].startswith("pw_oauth_rt_")

        refreshed = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": first["refresh_token"],
                "scope": "mcp:invoke",
                "resource": "https://api.prewise.site/mcp",
            },
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["refresh_token"] != first["refresh_token"]

        replay = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": first["refresh_token"],
            },
        )
        assert replay.status_code == 400


def test_protected_mcp_returns_oauth_discovery_challenge(monkeypatch) -> None:
    app, _ = _app(monkeypatch)
    with TestClient(app) as client:
        response = client.post("/mcp", json={})
        assert response.status_code == 401
        challenge = response.headers["www-authenticate"]
        assert "resource_metadata=" in challenge
        assert "/.well-known/oauth-protected-resource/mcp" in challenge
