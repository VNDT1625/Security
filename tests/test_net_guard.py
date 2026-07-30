"""SSRF guards for outbound HTTP built from user or operator input."""

from __future__ import annotations

import pytest

from backend.services.llm_provider_config_service import (
    normalize_provider_url,
    target_keeps_data_local,
)
from shared.net_guard import (
    SSRFBlocked,
    assert_global_target,
    is_loopback_target,
    reject_private_target,
)

PRIVATE_TARGETS = [
    "https://169.254.169.254/latest/meta-data/",  # cloud instance metadata
    "https://10.0.0.5:6379/v1",
    "https://192.168.1.10/v1",
    "https://172.16.4.4/v1",
    "https://127.0.0.1/v1",
    "https://[::1]/v1",
]


@pytest.mark.parametrize("url", PRIVATE_TARGETS)
def test_private_literals_are_rejected(url: str) -> None:
    with pytest.raises(SSRFBlocked):
        assert_global_target(url)
    with pytest.raises(SSRFBlocked):
        reject_private_target(url)


def test_public_literal_is_allowed() -> None:
    assert assert_global_target("https://8.8.8.8/v1") == ["8.8.8.8"]


def test_unresolvable_host_blocks_a_request_but_not_a_saved_setting() -> None:
    """Saving config must tolerate DNS failure; making a request must not.

    A hostname that does not resolve cannot be an SSRF primitive, and refusing
    to store it would break setups where DNS has not propagated yet. The strict
    check still applies at request time.
    """
    unresolvable = "https://prewise-guard-does-not-exist.invalid/v1"
    with pytest.raises(SSRFBlocked):
        assert_global_target(unresolvable)
    reject_private_target(unresolvable)  # must not raise


@pytest.mark.parametrize("url", PRIVATE_TARGETS[:4])
def test_provider_url_rejects_internal_endpoints(url: str) -> None:
    with pytest.raises(ValueError):
        normalize_provider_url(url, provider="endpoint")


def test_provider_url_still_accepts_loopback_and_public() -> None:
    assert normalize_provider_url("http://127.0.0.1:11434/v1", provider="local") == (
        "http://127.0.0.1:11434/v1"
    )
    assert normalize_provider_url("https://api.openai.com/v1", provider="endpoint") == (
        "https://api.openai.com/v1"
    )


def test_data_egress_decision_follows_the_url_not_the_label() -> None:
    """A provider labelled "local" pointing off-box must not receive user content."""
    assert target_keeps_data_local("http://127.0.0.1:11434/v1") is True
    assert target_keeps_data_local("http://localhost:11434/v1") is True
    assert target_keeps_data_local("https://collector.example.com/v1") is False
    assert target_keeps_data_local("") is False


def test_is_loopback_target_is_false_for_unresolvable_hosts() -> None:
    assert is_loopback_target("https://prewise-guard-does-not-exist.invalid/v1") is False
