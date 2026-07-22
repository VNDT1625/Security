from datetime import date

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from starlette.requests import Request

from backend.config import settings
from backend.db import Base
from backend.models import DailyQuotaUsage
from backend.routers.auth import ActorContext
from backend.services.quota_service import (
    refund_ai_credits,
    reserve_ai_credits,
    reserve_deep_scan_quota,
)


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/test",
            "headers": [],
            "client": ("127.0.0.55", 12345),
        }
    )


def test_ai_quota_tracks_evaluation_and_explanation_separately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "anonymous_daily_ai_credit_limit", 5)
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    actor = ActorContext(anonymous_id="quota-test")
    request = _request()

    with Session(engine) as db:
        reserve_ai_credits(db, actor, request, 2, kind="evaluation")
        reserve_ai_credits(db, actor, request, 3, kind="explanation")
        usage = db.execute(
            select(DailyQuotaUsage).where(
                DailyQuotaUsage.usage_day == date.today()
            )
        ).scalar_one()
        assert usage.ai_credit_count == 5
        assert usage.ai_evaluation_count == 2
        assert usage.ai_explanation_count == 3

        with pytest.raises(HTTPException) as exhausted:
            reserve_ai_credits(db, actor, request, kind="evaluation")
        assert exhausted.value.status_code == 429

        refund_ai_credits(db, actor, request, kind="explanation")
        db.refresh(usage)
        assert usage.ai_credit_count == 4
        assert usage.ai_explanation_count == 2


def test_deep_quota_allows_100_scans_per_day(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "anonymous_daily_deep_scan_limit", 100)
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    actor = ActorContext(anonymous_id="deep-test")
    request = _request()

    with Session(engine) as db:
        for _ in range(100):
            reserve_deep_scan_quota(db, actor, request)
        with pytest.raises(HTTPException) as exhausted:
            reserve_deep_scan_quota(db, actor, request)

    assert exhausted.value.status_code == 429
