"""Bounded Cloudflare Email Sending client for transactional release notices."""

from __future__ import annotations

import html
import time
from dataclasses import dataclass

import httpx

from backend.config import settings


@dataclass(frozen=True)
class DeliveryResult:
    sent: bool
    error: str | None = None


def email_configured() -> bool:
    return bool(
        settings.cloudflare_account_id.strip()
        and settings.cloudflare_api_token.strip()
        and settings.prewise_email_from.strip()
    )


def send_release_email(
    *,
    recipient: str,
    product_name: str,
    version: str,
    download_url: str,
    checksum: str,
    unsubscribe_url: str,
    client: httpx.Client | None = None,
) -> DeliveryResult:
    """Send one notice, retrying only rate limits and transient server errors."""
    if not email_configured():
        return DeliveryResult(False, "Cloudflare Email Sending chưa được cấu hình.")
    safe_product = html.escape(product_name)
    safe_version = html.escape(version)
    safe_url = html.escape(download_url, quote=True)
    safe_checksum = html.escape(checksum)
    safe_unsubscribe = html.escape(unsubscribe_url, quote=True)
    payload = {
        "to": recipient,
        "from": {"address": settings.prewise_email_from, "name": "Prewise"},
        "subject": f"{product_name} {version} đã sẵn sàng",
        "text": (
            f"{product_name} {version} đã sẵn sàng.\n"
            f"Tải xuống: {download_url}\nSHA-256: {checksum}\n"
            f"Hủy nhận thông báo: {unsubscribe_url}"
        ),
        "html": (
            f"<h1>{safe_product} {safe_version} đã sẵn sàng</h1>"
            f'<p><a href="{safe_url}">Tải xuống từ Prewise</a></p>'
            f"<p>SHA-256: <code>{safe_checksum}</code></p>"
            f'<p><a href="{safe_unsubscribe}">Hủy nhận thông báo</a></p>'
        ),
        "headers": {"List-Unsubscribe": f"<{unsubscribe_url}>"},
    }
    endpoint = (
        "https://api.cloudflare.com/client/v4/accounts/"
        f"{settings.cloudflare_account_id}/email/sending/send"
    )
    own_client = client is None
    http = client or httpx.Client(timeout=settings.release_email_timeout_seconds)
    attempts = max(1, min(settings.release_email_max_attempts, 5))
    try:
        for attempt in range(attempts):
            try:
                response = http.post(
                    endpoint,
                    headers={
                        "Authorization": f"Bearer {settings.cloudflare_api_token}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
            except httpx.RequestError:
                # Network failures are ambiguous and are not retried to avoid duplicates.
                return DeliveryResult(False, "Không thể kết nối dịch vụ gửi email.")
            retryable = response.status_code == 429 or response.status_code >= 500
            if 200 <= response.status_code < 300:
                try:
                    if response.json().get("success") is False:
                        return DeliveryResult(False, "Cloudflare từ chối yêu cầu gửi email.")
                except ValueError:
                    pass
                return DeliveryResult(True)
            if not retryable or attempt == attempts - 1:
                return DeliveryResult(False, f"Cloudflare Email trả HTTP {response.status_code}.")
            time.sleep(min(0.25 * (2**attempt), 1.0))
    finally:
        if own_client:
            http.close()
    return DeliveryResult(False, "Không thể gửi email.")


def send_password_reset_email(
    *, recipient: str, reset_url: str, client: httpx.Client | None = None
) -> DeliveryResult:
    """Send a short-lived password-reset link without exposing its token."""
    if not email_configured():
        return DeliveryResult(False, "Cloudflare Email Sending chưa được cấu hình.")
    safe_url = html.escape(reset_url, quote=True)
    payload = {
        "to": recipient,
        "from": {"address": settings.prewise_email_from, "name": "Prewise"},
        "subject": "Đặt lại mật khẩu Prewise",
        "text": (
            "Có yêu cầu đặt lại mật khẩu cho tài khoản Prewise của bạn.\n"
            f"Liên kết có hiệu lực trong 30 phút: {reset_url}\n"
            "Nếu bạn không yêu cầu, hãy bỏ qua email này."
        ),
        "html": (
            "<h1>Đặt lại mật khẩu Prewise</h1>"
            "<p>Liên kết này có hiệu lực trong 30 phút.</p>"
            f'<p><a href="{safe_url}">Đặt mật khẩu mới</a></p>'
            "<p>Nếu bạn không yêu cầu, hãy bỏ qua email này.</p>"
        ),
    }
    endpoint = (
        "https://api.cloudflare.com/client/v4/accounts/"
        f"{settings.cloudflare_account_id}/email/sending/send"
    )
    own_client = client is None
    http = client or httpx.Client(timeout=settings.release_email_timeout_seconds)
    attempts = max(1, min(settings.release_email_max_attempts, 5))
    try:
        for attempt in range(attempts):
            try:
                response = http.post(
                    endpoint,
                    headers={
                        "Authorization": f"Bearer {settings.cloudflare_api_token}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
            except httpx.RequestError:
                return DeliveryResult(False, "Không thể kết nối dịch vụ gửi email.")
            if 200 <= response.status_code < 300:
                try:
                    if response.json().get("success") is False:
                        return DeliveryResult(False, "Cloudflare từ chối yêu cầu gửi email.")
                except ValueError:
                    pass
                return DeliveryResult(True)
            retryable = response.status_code == 429 or response.status_code >= 500
            if not retryable or attempt == attempts - 1:
                return DeliveryResult(False, f"Cloudflare Email trả HTTP {response.status_code}.")
            time.sleep(min(0.25 * (2**attempt), 1.0))
    finally:
        if own_client:
            http.close()
    return DeliveryResult(False, "Không thể gửi email.")
