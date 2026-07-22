"""Server-side scan quota enforcement backed by the database."""

from __future__ import annotations

from datetime import date

from fastapi import HTTPException, Request, status
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.config import settings
from backend.models import DailyQuotaUsage, uuid_str
from backend.routers.auth import ActorContext, build_plan_info
from backend.security_utils import hash_metadata, utcnow


def _identity(actor: ActorContext, request: Request) -> tuple[str | None, str | None, str | None]:
    # External scans retain both ownership and credential attribution. Quota is
    # enforced per account (user_id), while api_key_id identifies which key,
    # Extension, MCP client, or integration consumed the scan.
    if actor.api_key is not None and actor.user is not None:
        return actor.user.id, actor.api_key.id, None
    if actor.user is not None:
        return actor.user.id, None, None
    source = actor.anonymous_id
    if not source:
        source = hash_metadata(request.client.host if request.client else "anonymous")
    return None, None, f"ip:{source}"


def _daily_limit(db: Session, actor: ActorContext) -> int | None:
    if actor.user is None:
        return settings.anonymous_daily_scan_limit
    plan = build_plan_info(db, actor.user.id)
    return None if plan.dailyScanLimit >= 999_999 else plan.dailyScanLimit


def _feature_limit(db: Session, actor: ActorContext, feature: str) -> int | None:
    plan = build_plan_info(db, actor.user.id) if actor.user is not None else None
    raw_limit = {
        "ai": (
            plan.aiCreditDailyLimit
            if plan is not None
            else settings.anonymous_daily_ai_credit_limit
        ),
        "deep": (
            plan.deepScanDailyLimit
            if plan is not None
            else settings.anonymous_daily_deep_scan_limit
        ),
    }[feature]
    return None if raw_limit >= 999_999 else raw_limit


def _usage_query(
    user_id: str | None,
    api_key_id: str | None,
    anonymous_id: str | None,
    today: date,
) -> object:
    query = select(DailyQuotaUsage).where(DailyQuotaUsage.usage_day == today)
    if user_id is not None:
        return query.where(DailyQuotaUsage.user_id == user_id)
    if api_key_id is not None:
        return query.where(DailyQuotaUsage.api_key_id == api_key_id)
    return query.where(DailyQuotaUsage.anonymous_id == anonymous_id)


def reserve_scan_quota(db: Session, actor: ActorContext, request: Request) -> None:
    """Atomically consume one scan unit, including under concurrent PostgreSQL traffic."""

    if settings.app_env == "development" and settings.local_testing_unlimited:
        return

    user_id, api_key_id, anonymous_id = _identity(actor, request)
    limit = _daily_limit(db, actor)
    today = date.today()

    if db.bind is not None and db.bind.dialect.name == "postgresql":
        identity_column = (
            "user_id" if user_id is not None else "api_key_id" if api_key_id is not None else "anonymous_id"
        )
        identity_value = user_id or api_key_id or anonymous_id
        result = db.execute(
            text(
                f"""
                INSERT INTO daily_quota_usage
                    (id, user_id, api_key_id, anonymous_id, usage_day,
                     scan_count, ai_credit_count, ai_evaluation_count,
                     ai_explanation_count, deep_scan_count,
                     limit_snapshot, last_scan_at, created_at, updated_at)
                VALUES
                    (:id, :user_id, :api_key_id, :anonymous_id, :usage_day,
                     1, 0, 0, 0, 0,
                     :limit, :now, :now, :now)
                ON CONFLICT ({identity_column}, usage_day)
                    WHERE {identity_column} IS NOT NULL
                DO UPDATE SET
                    scan_count = daily_quota_usage.scan_count + 1,
                    limit_snapshot = EXCLUDED.limit_snapshot,
                    last_scan_at = EXCLUDED.last_scan_at,
                    updated_at = EXCLUDED.updated_at
                WHERE :limit IS NULL OR daily_quota_usage.scan_count < :limit
                RETURNING scan_count
                """
            ),
            {
                "id": uuid_str(),
                "user_id": user_id,
                "api_key_id": api_key_id,
                "anonymous_id": anonymous_id,
                "identity": identity_value,
                "usage_day": today,
                "limit": limit,
                "now": utcnow(),
            },
        ).scalar_one_or_none()
        if result is None:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Bạn đã hết lượt quét hôm nay.",
            )
        db.commit()
        return

    # SQLite fallback for local development and tests. SQLite serializes writers;
    # the unique constraint plus retry handles a competing first insert.
    for _ in range(2):
        try:
            # A user's web, Extension, MCP and API traffic shares one plan quota;
            # api_key_id remains on the row for external attribution.
            query = _usage_query(user_id, api_key_id, anonymous_id, today)
            row = db.execute(query).scalar_one_or_none()
            if row is None:
                row = DailyQuotaUsage(
                    user_id=user_id,
                    api_key_id=api_key_id,
                    anonymous_id=anonymous_id,
                    usage_day=today,
                    scan_count=1,
                    limit_snapshot=limit,
                    last_scan_at=utcnow(),
                )
                db.add(row)
            else:
                if api_key_id is not None:
                    row.api_key_id = api_key_id
                if limit is not None and row.scan_count >= limit:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Bạn đã hết lượt quét hôm nay.",
                    )
                row.scan_count += 1
                row.limit_snapshot = limit
                row.last_scan_at = utcnow()
            db.commit()
            return
        except IntegrityError:
            db.rollback()

    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Không thể cập nhật quota, vui lòng thử lại.",
    )


def _reserve_feature_quota(
    db: Session,
    actor: ActorContext,
    request: Request,
    *,
    feature: str,
    amount: int,
    ai_kind: str | None = None,
) -> None:
    if settings.app_env == "development" and settings.local_testing_unlimited:
        return
    if amount <= 0:
        return

    config = {
        "ai": (
            "ai_credit_count",
            "ai_limit_snapshot",
            "last_ai_at",
            "Bạn đã hết lượt AI hôm nay.",
        ),
        "deep": (
            "deep_scan_count",
            "deep_limit_snapshot",
            "last_deep_at",
            "Bạn đã hết lượt phân tích chuyên sâu hôm nay.",
        ),
    }
    counter_column, snapshot_column, timestamp_column, error_detail = config[feature]
    if feature == "ai" and ai_kind not in {"evaluation", "explanation"}:
        raise ValueError("AI quota requires kind='evaluation' or kind='explanation'")
    subcounter_column = f"ai_{ai_kind}_count" if feature == "ai" else None
    user_id, api_key_id, anonymous_id = _identity(actor, request)
    limit = _feature_limit(db, actor, feature)
    if limit is not None and amount > limit:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=error_detail)

    today = date.today()
    now = utcnow()
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        identity_column = (
            "user_id" if user_id is not None else "api_key_id" if api_key_id is not None else "anonymous_id"
        )
        initial_ai = amount if feature == "ai" else 0
        initial_ai_evaluation = amount if ai_kind == "evaluation" else 0
        initial_ai_explanation = amount if ai_kind == "explanation" else 0
        initial_deep = amount if feature == "deep" else 0
        subcounter_update = (
            f", {subcounter_column} = daily_quota_usage.{subcounter_column} + :amount"
            if subcounter_column
            else ""
        )
        result = db.execute(
            text(
                f"""
                INSERT INTO daily_quota_usage
                    (id, user_id, api_key_id, anonymous_id, usage_day,
                     scan_count, ai_credit_count, ai_evaluation_count,
                     ai_explanation_count, deep_scan_count,
                     {snapshot_column}, {timestamp_column}, created_at, updated_at)
                VALUES
                    (:id, :user_id, :api_key_id, :anonymous_id, :usage_day,
                     0, :initial_ai, :initial_ai_evaluation,
                     :initial_ai_explanation, :initial_deep,
                     :limit, :now, :now, :now)
                ON CONFLICT ({identity_column}, usage_day)
                    WHERE {identity_column} IS NOT NULL
                DO UPDATE SET
                    {counter_column} = daily_quota_usage.{counter_column} + :amount
                    {subcounter_update},
                    {snapshot_column} = EXCLUDED.{snapshot_column},
                    {timestamp_column} = EXCLUDED.{timestamp_column},
                    updated_at = EXCLUDED.updated_at
                WHERE :limit IS NULL
                   OR daily_quota_usage.{counter_column} + :amount <= :limit
                RETURNING {counter_column}
                """
            ),
            {
                "id": uuid_str(),
                "user_id": user_id,
                "api_key_id": api_key_id,
                "anonymous_id": anonymous_id,
                "usage_day": today,
                "amount": amount,
                "initial_ai": initial_ai,
                "initial_ai_evaluation": initial_ai_evaluation,
                "initial_ai_explanation": initial_ai_explanation,
                "initial_deep": initial_deep,
                "limit": limit,
                "now": now,
            },
        ).scalar_one_or_none()
        if result is None:
            db.rollback()
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=error_detail)
        db.commit()
        return

    for _ in range(2):
        try:
            row = db.execute(_usage_query(user_id, api_key_id, anonymous_id, today)).scalar_one_or_none()
            if row is None:
                row = DailyQuotaUsage(
                    user_id=user_id,
                    api_key_id=api_key_id,
                    anonymous_id=anonymous_id,
                    usage_day=today,
                    scan_count=0,
                    ai_credit_count=amount if feature == "ai" else 0,
                    ai_evaluation_count=amount if ai_kind == "evaluation" else 0,
                    ai_explanation_count=amount if ai_kind == "explanation" else 0,
                    deep_scan_count=amount if feature == "deep" else 0,
                )
                db.add(row)
            else:
                if api_key_id is not None:
                    row.api_key_id = api_key_id
                current = int(getattr(row, counter_column))
                if limit is not None and current + amount > limit:
                    raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=error_detail)
                setattr(row, counter_column, current + amount)
                if subcounter_column:
                    setattr(row, subcounter_column, int(getattr(row, subcounter_column)) + amount)
            setattr(row, snapshot_column, limit)
            setattr(row, timestamp_column, now)
            db.commit()
            return
        except IntegrityError:
            db.rollback()

    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Không thể cập nhật quota, vui lòng thử lại.",
    )


def reserve_ai_credits(
    db: Session,
    actor: ActorContext,
    request: Request,
    credits: int = 1,
    *,
    kind: str,
) -> None:
    """Reserve AI work before invoking a contextual or generative model."""

    _reserve_feature_quota(
        db,
        actor,
        request,
        feature="ai",
        amount=credits,
        ai_kind=kind,
    )


def refund_ai_credits(
    db: Session,
    actor: ActorContext,
    request: Request,
    credits: int = 1,
    *,
    kind: str,
) -> None:
    """Release a reservation when the remote LLM did not complete successfully."""

    if credits <= 0:
        return
    if kind not in {"evaluation", "explanation"}:
        raise ValueError("AI quota refund requires a valid kind")
    user_id, api_key_id, anonymous_id = _identity(actor, request)
    today = date.today()
    kind_column = f"ai_{kind}_count"

    if db.bind is not None and db.bind.dialect.name == "postgresql":
        identity_column = (
            "user_id" if user_id is not None else "api_key_id" if api_key_id is not None else "anonymous_id"
        )
        identity_value = user_id or api_key_id or anonymous_id
        db.execute(
            text(
                f"""
                UPDATE daily_quota_usage
                SET ai_credit_count = GREATEST(0, ai_credit_count - :credits),
                    {kind_column} = GREATEST(0, {kind_column} - :credits),
                    updated_at = :now
                WHERE {identity_column} = :identity AND usage_day = :usage_day
                """
            ),
            {
                "credits": credits,
                "identity": identity_value,
                "usage_day": today,
                "now": utcnow(),
            },
        )
        db.commit()
        return

    row = db.execute(_usage_query(user_id, api_key_id, anonymous_id, today)).scalar_one_or_none()
    if row is None:
        return
    row.ai_credit_count = max(0, int(row.ai_credit_count) - credits)
    setattr(row, kind_column, max(0, int(getattr(row, kind_column)) - credits))
    db.commit()


def reserve_deep_scan_quota(db: Session, actor: ActorContext, request: Request) -> None:
    """Reserve one browser/network deep-analysis run."""

    _reserve_feature_quota(db, actor, request, feature="deep", amount=1)
