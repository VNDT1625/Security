"""seed the required subscription plan catalog

Revision ID: 0024_seed_plan_catalog
Revises: 0023_quota_api_key_attribution
Create Date: 2026-07-30
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0024_seed_plan_catalog"
down_revision = "0023_quota_api_key_attribution"
branch_labels = None
depends_on = None


_PLANS = (
    (
        "free",
        "FREE",
        1000,
        0,
        0,
        {
            "api_key": False,
            "history_days": 7,
            "ai_credit_daily_limit": 5,
            "deep_scan_daily_limit": 100,
            "chat_followup_limit": 3,
            "auto_message_context": False,
            "auto_web_context": False,
        },
    ),
    (
        "pro",
        "PRO",
        None,
        99000,
        990000,
        {
            "api_key": True,
            "history_days": 90,
            "ai_credit_daily_limit": 50,
            "deep_scan_daily_limit": 100,
            "chat_followup_limit": 20,
            "auto_message_context": True,
            "auto_web_context": True,
        },
    ),
    (
        "team",
        "TEAM",
        None,
        299000,
        2990000,
        {
            "api_key": True,
            "history_days": 365,
            "mcp": True,
            "ai_credit_daily_limit": 100,
            "deep_scan_daily_limit": 100,
            "chat_followup_limit": 50,
            "auto_message_context": True,
            "auto_web_context": True,
        },
    ),
    (
        "enterprise",
        "ENTERPRISE",
        None,
        None,
        None,
        {
            "api_key": True,
            "history_days": 730,
            "mcp": True,
            "sso": True,
            "ai_credit_daily_limit": 999999,
            "deep_scan_daily_limit": 999999,
            "chat_followup_limit": 999999,
            "auto_message_context": True,
            "auto_web_context": True,
        },
    ),
)


def upgrade() -> None:
    plans = sa.table(
        "plans",
        sa.column("tier", sa.String(32)),
        sa.column("label", sa.String(40)),
        sa.column("daily_scan_limit", sa.Integer()),
        sa.column("monthly_price_vnd", sa.Integer()),
        sa.column("yearly_price_vnd", sa.Integer()),
        sa.column("features", sa.JSON()),
        sa.column("created_at", sa.DateTime()),
        sa.column("updated_at", sa.DateTime()),
    )
    bind = op.get_bind()
    now = datetime.now(UTC).replace(tzinfo=None)

    for tier, label, daily_limit, monthly, yearly, features in _PLANS:
        exists = bind.execute(
            sa.select(plans.c.tier).where(plans.c.tier == tier)
        ).scalar_one_or_none()
        if exists is None:
            bind.execute(
                plans.insert().values(
                    tier=tier,
                    label=label,
                    daily_scan_limit=daily_limit,
                    monthly_price_vnd=monthly,
                    yearly_price_vnd=yearly,
                    features=features,
                    created_at=now,
                    updated_at=now,
                )
            )


def downgrade() -> None:
    # Plans may already be referenced by subscriptions. Removing reference
    # catalog rows during rollback would either fail or destroy valid access.
    pass
