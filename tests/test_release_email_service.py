from __future__ import annotations

import httpx

from backend.config import settings
from backend.services import release_email_service as service


def _configure(monkeypatch) -> None:
    monkeypatch.setattr(settings, "cloudflare_account_id", "account-id")
    monkeypatch.setattr(settings, "cloudflare_api_token", "secret-token")
    monkeypatch.setattr(settings, "prewise_email_from", "release@prewise.site")
    monkeypatch.setattr(settings, "release_email_max_attempts", 3)
    monkeypatch.setattr(service.time, "sleep", lambda _: None)


def test_cloudflare_email_payload_and_retry_are_bounded(monkeypatch) -> None:
    _configure(monkeypatch)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(429, json={"success": False})
        return httpx.Response(200, json={"success": True, "result": {"delivered": ["user@example.com"]}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = service.send_release_email(
            recipient="user@example.com",
            product_name="Prewise Windows",
            version="1.0.0",
            download_url="https://downloads.prewise.site/app.exe",
            checksum="a" * 64,
            unsubscribe_url="https://api.prewise.site/v1/waitlist/unsubscribe?token=opaque",
            client=client,
        )
    assert result.sent is True
    assert len(requests) == 2
    payload = __import__("json").loads(requests[-1].content)
    assert payload["from"]["address"] == "release@prewise.site"
    assert payload["text"] and payload["html"]
    assert "List-Unsubscribe" in payload["headers"]
    assert requests[-1].headers["authorization"] == "Bearer secret-token"


def test_cloudflare_email_does_not_retry_validation_errors(monkeypatch) -> None:
    _configure(monkeypatch)
    attempts = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(400, json={"success": False})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = service.send_release_email(
            recipient="user@example.com",
            product_name="Prewise",
            version="1.0.0",
            download_url="https://downloads.prewise.site/app.exe",
            checksum="a" * 64,
            unsubscribe_url="https://api.prewise.site/unsubscribe?token=opaque",
            client=client,
        )
    assert result.sent is False
    assert attempts == 1


def test_cloudflare_email_reports_unconfigured_without_request(monkeypatch) -> None:
    monkeypatch.setattr(settings, "cloudflare_account_id", "")
    monkeypatch.setattr(settings, "cloudflare_api_token", "")
    monkeypatch.setattr(settings, "prewise_email_from", "")
    result = service.send_release_email(
        recipient="user@example.com",
        product_name="Prewise",
        version="1.0.0",
        download_url="https://downloads.prewise.site/app.exe",
        checksum="a" * 64,
        unsubscribe_url="https://api.prewise.site/unsubscribe?token=opaque",
    )
    assert result.sent is False
    assert "chưa được cấu hình" in (result.error or "")


def test_password_reset_email_contains_only_short_lived_link(monkeypatch) -> None:
    _configure(monkeypatch)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"success": True})

    reset_url = "https://www.prewise.site/auth?mode=reset&token=opaque-token"
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = service.send_password_reset_email(
            recipient="user@example.com",
            reset_url=reset_url,
            client=client,
        )

    assert result.sent is True
    payload = __import__("json").loads(requests[0].content)
    assert payload["subject"] == "Đặt lại mật khẩu Prewise"
    assert reset_url in payload["text"]
    assert "opaque-token" in payload["html"]
    assert "List-Unsubscribe" not in payload.get("headers", {})
