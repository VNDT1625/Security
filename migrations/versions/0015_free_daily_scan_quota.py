"""Increase the Free daily Risk Core quota to 1000.

Revision ID: 0015_free_daily_scan_quota
Revises: 0014_user_llm_provider_settings
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0015_free_daily_scan_quota"
down_revision = "0014_user_llm_provider_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    plans = sa.table(
        "plans",
        sa.column("tier", sa.String()),
        sa.column("daily_scan_limit", sa.Integer()),
    )
    op.execute(
        plans.update()
        .where(plans.c.tier == "free")
        .values(daily_scan_limit=1000)
    )


def downgrade() -> None:
    plans = sa.table(
        "plans",
        sa.column("tier", sa.String()),
        sa.column("daily_scan_limit", sa.Integer()),
    )
    op.execute(
        plans.update()
        .where(plans.c.tier == "free")
        .values(daily_scan_limit=50)
    )
