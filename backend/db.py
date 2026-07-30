"""Database engine, session lifecycle, and local bootstrap helpers."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from threading import Lock

from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.config import settings


class Base(DeclarativeBase):
    pass


def _connect_args() -> dict:
    if settings.database_url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def _ensure_sqlite_parent() -> None:
    if not settings.database_url.startswith("sqlite:///"):
        return
    raw_path = settings.database_url.removeprefix("sqlite:///")
    if raw_path and raw_path != ":memory:":
        Path(raw_path).parent.mkdir(parents=True, exist_ok=True)


_ensure_sqlite_parent()


def _engine_options() -> dict:
    if settings.database_url.startswith("sqlite"):
        return {"connect_args": _connect_args()}
    return {
        "pool_pre_ping": True,
        "pool_size": settings.database_pool_size,
        "max_overflow": settings.database_max_overflow,
        "pool_timeout": settings.database_pool_timeout,
        "pool_recycle": settings.database_pool_recycle,
    }


engine = create_engine(
    settings.database_url,
    echo=settings.database_echo,
    future=True,
    **_engine_options(),
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
_init_lock = Lock()
_database_initialized = False


def _ensure_sqlite_development_columns() -> None:
    """Keep persistent local/demo SQLite databases compatible without Alembic.

    Production deployments still use the versioned migration. ``create_all``
    cannot add columns to an existing SQLite table, so local upgrades need this
    small idempotent bridge before ORM queries select the new quota fields.
    """

    if engine.dialect.name != "sqlite":
        return
    columns = {
        column["name"]
        for column in inspect(engine).get_columns("daily_quota_usage")
    }
    additions = {
        "ai_credit_count": "INTEGER NOT NULL DEFAULT 0",
        "ai_evaluation_count": "INTEGER NOT NULL DEFAULT 0",
        "ai_explanation_count": "INTEGER NOT NULL DEFAULT 0",
        "deep_scan_count": "INTEGER NOT NULL DEFAULT 0",
        "ai_limit_snapshot": "INTEGER",
        "deep_limit_snapshot": "INTEGER",
        "last_ai_at": "DATETIME",
        "last_deep_at": "DATETIME",
    }
    with engine.begin() as connection:
        for name, definition in additions.items():
            if name not in columns:
                connection.execute(
                    text(f"ALTER TABLE daily_quota_usage ADD COLUMN {name} {definition}")
                )
        sandbox_columns = {
            column["name"] for column in inspect(engine).get_columns("cloud_sandbox_sessions")
        }
        sandbox_additions = {
            "mode": "VARCHAR(16) NOT NULL DEFAULT 'auto'",
            "lease_minutes": "INTEGER NOT NULL DEFAULT 10",
            "agent_token_hash": "VARCHAR(64)",
            "remote_access_token_hash": "VARCHAR(64)",
            "remote_access_token_expires_at": "DATETIME",
            "remote_access_token_used_at": "DATETIME",
            "sample_filename": "VARCHAR(260)",
            "sample_storage_path": "TEXT",
            "sample_sha256": "VARCHAR(64)",
            "sample_size": "INTEGER",
            "sample_status": "VARCHAR(32) NOT NULL DEFAULT 'none'",
            "sample_report": "JSON NOT NULL DEFAULT '{}'",
            "sample_uploaded_at": "DATETIME",
            "sample_completed_at": "DATETIME",
            "ready_at": "DATETIME",
            "lease_expires_at": "DATETIME",
            "termination_reason": "VARCHAR(32)",
            "termination_requested_at": "DATETIME",
            "cleanup_completed_at": "DATETIME",
        }
        for name, definition in sandbox_additions.items():
            if name not in sandbox_columns:
                connection.execute(
                    text(f"ALTER TABLE cloud_sandbox_sessions ADD COLUMN {name} {definition}")
                )
        feedback_columns = {
            column["name"] for column in inspect(engine).get_columns("user_feedback")
        }
        feedback_additions = {
            "reason": "VARCHAR(40) NOT NULL DEFAULT 'other'",
            "comment_sha256": "VARCHAR(64)",
            "idempotency_key": "VARCHAR(64)",
            "status": "VARCHAR(24) NOT NULL DEFAULT 'received'",
            "updated_at": "DATETIME",
        }
        for name, definition in feedback_additions.items():
            if name not in feedback_columns:
                connection.execute(
                    text(f"ALTER TABLE user_feedback ADD COLUMN {name} {definition}")
                )
        connection.execute(
            text("UPDATE user_feedback SET updated_at = created_at WHERE updated_at IS NULL")
        )
        llm_columns = {
            column["name"] for column in inspect(engine).get_columns("llm_provider_settings")
        }
        llm_additions = {
            "allowed_user_providers": "JSON NOT NULL DEFAULT '[\"adapter\",\"local\",\"endpoint\"]'",
            "allowed_user_models": "JSON NOT NULL DEFAULT '[]'",
        }
        for name, definition in llm_additions.items():
            if name not in llm_columns:
                connection.execute(
                    text(f"ALTER TABLE llm_provider_settings ADD COLUMN {name} {definition}")
                )


def get_db() -> Iterator[Session]:
    initialize_database()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def initialize_database() -> None:
    """Create local/dev tables and seed reference data.

    Production should run Alembic migrations before app startup. The auto-create
    path keeps tests and local demos self-contained when PostgreSQL is not running.
    """

    global _database_initialized

    if _database_initialized:
        return

    with _init_lock:
        if _database_initialized:
            return

        if not settings.database_auto_create:
            _database_initialized = True
            return

        from backend import models  # noqa: F401  # register metadata
        from backend.models import ApiKey, Plan, Subscription, User
        from backend.security_utils import (
            create_api_key_value,
            create_password_salt,
            hash_api_key,
            hash_password,
            utcnow,
        )

        Base.metadata.create_all(bind=engine)
        _ensure_sqlite_development_columns()

        with SessionLocal() as db:
            plans = {
                "free": ("FREE", 1000, 0, 0, {"api_key": False, "history_days": 7, "ai_credit_daily_limit": 5, "deep_scan_daily_limit": 100, "chat_followup_limit": 3, "auto_message_context": False, "auto_web_context": False}),
                "pro": ("PRO", None, 99000, 990000, {"api_key": True, "history_days": 90, "ai_credit_daily_limit": 50, "deep_scan_daily_limit": 100, "chat_followup_limit": 20, "auto_message_context": True, "auto_web_context": True}),
                "team": (
                    "TEAM",
                    None,
                    299000,
                    2990000,
                    {"api_key": True, "history_days": 365, "mcp": True, "ai_credit_daily_limit": 100, "deep_scan_daily_limit": 100, "chat_followup_limit": 50, "auto_message_context": True, "auto_web_context": True},
                ),
                "enterprise": (
                    "ENTERPRISE",
                    None,
                    None,
                    None,
                    {"api_key": True, "history_days": 730, "mcp": True, "sso": True, "ai_credit_daily_limit": 999999, "deep_scan_daily_limit": 999999, "chat_followup_limit": 999999, "auto_message_context": True, "auto_web_context": True},
                ),
            }
            for tier, (label, limit, monthly, yearly, features) in plans.items():
                current_plan = db.get(Plan, tier)
                if current_plan is None:
                    db.add(
                        Plan(
                            tier=tier,
                            label=label,
                            daily_scan_limit=limit,
                            monthly_price_vnd=monthly,
                            yearly_price_vnd=yearly,
                            features=features,
                        )
                    )
                else:
                    if tier == "free":
                        current_plan.daily_scan_limit = limit
                    merged_features = dict(features)
                    merged_features.update(current_plan.features or {})
                    # Upgrade legacy Free/Pro deep-analysis quotas in existing
                    # databases while preserving any other administrator edits.
                    if merged_features.get("deep_scan_daily_limit") in {1, 10}:
                        merged_features["deep_scan_daily_limit"] = 100
                    current_plan.features = merged_features

            # Upgrade legacy development keys to the explicit Agent Shield scopes.
            default_scopes = [
                "assess:url", "assess:content", "assess:prompt", "assess:file",
                "assess:action", "mcp:invoke",
            ]
            for legacy_key in db.execute(select(ApiKey)).scalars():
                if not legacy_key.scopes or legacy_key.scopes == ["scan"]:
                    legacy_key.scopes = default_scopes

            # Every account owns at least one active integration credential.
            # Existing databases are backfilled idempotently during local/dev startup.
            for user in db.execute(select(User)).scalars():
                active_key = db.execute(
                    select(ApiKey).where(ApiKey.user_id == user.id, ApiKey.status == "active")
                ).scalar_one_or_none()
                if active_key is None:
                    key = create_api_key_value()
                    db.add(
                        ApiKey(
                            user_id=user.id,
                            key_prefix=key[:16],
                            key_tail=key[-4:],
                            key_hash=hash_api_key(key),
                            scopes=default_scopes,
                            created_at=utcnow(),
                        )
                    )

            demo = db.execute(select(User).where(User.email == "demo@aisec.local")).scalar_one_or_none()
            # The demo account is an end-user account.  It must never grant
            # access to system administration merely because it is convenient
            # for local development.
            if settings.seed_demo_user and demo is not None:
                if demo.role != "user":
                    demo.role = "user"
                demo_subscription = db.execute(
                    select(Subscription)
                    .where(
                        Subscription.user_id == demo.id,
                        Subscription.status.in_(("trialing", "active")),
                    )
                    .order_by(Subscription.created_at.desc())
                ).scalars().first()
                if demo_subscription is None:
                    db.add(Subscription(user_id=demo.id, plan_tier="free", status="active"))
                elif demo_subscription.plan_tier != "free":
                    demo_subscription.plan_tier = "free"
                    demo_subscription.trial_ends_at = None
                    demo_subscription.renews_at = None
            if settings.seed_demo_user and demo is None:
                salt = create_password_salt()
                demo = User(
                    email="demo@aisec.local",
                    display_name="Demo User",
                    password_salt=salt,
                    password_hash=hash_password("Demo@123456", salt),
                    role="user",
                )
                db.add(demo)
                db.flush()
                db.add(Subscription(user_id=demo.id, plan_tier="free", status="active"))
                key = create_api_key_value()
                db.add(
                    ApiKey(
                        user_id=demo.id,
                        key_prefix=key[:16],
                        key_tail=key[-4:],
                        key_hash=hash_api_key(key),
                        created_at=utcnow(),
                    )
                )
            db.commit()

        _database_initialized = True


def check_database() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            plan_count = conn.execute(
                text(
                    "SELECT COUNT(*) FROM plans "
                    "WHERE tier IN ('free', 'pro', 'team', 'enterprise')"
                )
            ).scalar_one()
        return plan_count == 4
    except Exception:
        return False
