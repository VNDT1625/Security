from __future__ import annotations

import hashlib
import hmac

import pytest

from backend.routers.sandbox_cloud import (
    PRO_MONTHLY_PRICE_VND,
    PRO_YEARLY_PRICE_VND,
    TEAM_MONTHLY_PRICE_VND,
    TEAM_YEARLY_PRICE_VND,
    is_incoming_sepay_transaction,
    make_sepay_qr_url,
    sepay_transfer_content,
    subscription_amount_vnd,
    verify_sepay_webhook_hmac,
)


def _signature(secret: str, timestamp: int, body: bytes) -> str:
    digest = hmac.new(
        secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


def test_sepay_hmac_accepts_current_signed_raw_body() -> None:
    secret = "test-secret"
    body = b'{"id":1,"content":"PPABCDEF123456"}'
    timestamp = 1_700_000_000

    assert verify_sepay_webhook_hmac(
        body, _signature(secret, timestamp, body), str(timestamp), secret, now=timestamp,
    )


def test_sepay_hmac_rejects_modified_body_and_stale_timestamp() -> None:
    secret = "test-secret"
    timestamp = 1_700_000_000
    body = b'{"id":1}'
    signature = _signature(secret, timestamp, body)

    assert not verify_sepay_webhook_hmac(
        b'{"id":2}', signature, str(timestamp), secret, now=timestamp,
    )
    assert not verify_sepay_webhook_hmac(
        body, signature, str(timestamp), secret, now=timestamp + 301,
    )


def test_only_incoming_transactions_can_settle_a_payment() -> None:
    assert is_incoming_sepay_transaction("in")
    assert not is_incoming_sepay_transaction("out")
    assert not is_incoming_sepay_transaction("")


def test_vietinbank_payment_content_starts_with_sevqr() -> None:
    reference = "PPABCDEF123456"
    assert sepay_transfer_content(reference) == "SEVQR PPABCDEF123456"
    assert "des=SEVQR%20PPABCDEF123456" in make_sepay_qr_url(5_000, reference)


def test_pro_prices_match_the_public_monthly_and_yearly_offer() -> None:
    assert PRO_MONTHLY_PRICE_VND == 5_000
    assert PRO_YEARLY_PRICE_VND == 50_000
    assert subscription_amount_vnd("pro", "monthly") == 5_000
    assert subscription_amount_vnd("pro", "yearly") == 50_000


def test_team_payment_unlocks_the_max_sandbox_package() -> None:
    assert TEAM_MONTHLY_PRICE_VND == 29_000
    assert TEAM_YEARLY_PRICE_VND == 290_000
    assert subscription_amount_vnd("team", "monthly") == 29_000
    assert subscription_amount_vnd("team", "yearly") == 290_000


def test_subscription_price_rejects_unknown_plan_or_period() -> None:
    with pytest.raises(ValueError):
        subscription_amount_vnd("max", "monthly")
    with pytest.raises(ValueError):
        subscription_amount_vnd("pro", "weekly")
