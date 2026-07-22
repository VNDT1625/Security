from datetime import date

import pytest
from fastapi import HTTPException, Request
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.db import Base
from backend.models import DailyQuotaUsage, User
from backend.routers.auth import ActorContext
from backend.services.quota_service import reserve_scan_quota


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "headers": [],
            "client": ("127.0.0.1", 0),
        }
    )


def test_free_oauth_user_can_scan_1000_times_per_day() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        user = User(
            email="oauth-quota@test.local",
            display_name="OAuth Quota",
            password_salt="00" * 16,
            password_hash="x",
        )
        db.add(user)
        db.flush()
        db.add(
            DailyQuotaUsage(
                user_id=user.id,
                usage_day=date.today(),
                scan_count=999,
                limit_snapshot=1000,
            )
        )
        db.commit()

        actor = ActorContext(user=user, channel="mcp")
        reserve_scan_quota(db, actor, _request())

        usage = db.query(DailyQuotaUsage).filter_by(user_id=user.id).one()
        assert usage.scan_count == 1000
        assert usage.limit_snapshot == 1000

        with pytest.raises(HTTPException) as exhausted:
            reserve_scan_quota(db, actor, _request())

        assert exhausted.value.status_code == 429
        assert exhausted.value.detail == "Bạn đã hết lượt quét hôm nay."
