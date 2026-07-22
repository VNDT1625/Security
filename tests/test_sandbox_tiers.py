from __future__ import annotations

from backend.routers.sandbox_cloud import (
    FREE_DAILY_SESSION_LIMIT,
    TIER_CAPABILITIES,
    TIER_RANK,
)


def test_tier_capabilities_are_ordered_and_safe() -> None:
    assert TIER_RANK == {"free": 0, "pro": 1, "max": 2}
    assert TIER_CAPABILITIES["free"] == {
        "web": True,
        "exe": False,
        "gpu": False,
        "minutes": 10,
        "provider": "local",
        "creditCost": 0,
    }
    assert TIER_CAPABILITIES["pro"]["exe"] is True
    assert TIER_CAPABILITIES["pro"]["gpu"] is False
    assert TIER_CAPABILITIES["pro"]["creditCost"] == 1
    assert TIER_CAPABILITIES["max"]["exe"] is True
    assert TIER_CAPABILITIES["max"]["gpu"] is True
    assert TIER_CAPABILITIES["max"]["creditCost"] == 3


def test_account_plan_can_only_open_equal_or_lower_sandbox_tier() -> None:
    assert TIER_RANK["free"] < TIER_RANK["pro"] < TIER_RANK["max"]
    assert TIER_RANK["free"] < TIER_RANK["max"]


def test_free_tier_allows_ten_sessions_per_day() -> None:
    assert FREE_DAILY_SESSION_LIMIT == 10
