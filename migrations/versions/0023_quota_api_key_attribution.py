"""allow API-key attribution on user-owned daily quota rows

Revision ID: 0023_quota_api_key_attribution
Revises: 0022_llm_user_policy
Create Date: 2026-07-23
"""

from __future__ import annotations

from alembic import op

revision = "0023_quota_api_key_attribution"
down_revision = "0022_llm_user_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_daily_quota_exactly_one_identity",
        "daily_quota_usage",
        type_="check",
    )
    op.create_check_constraint(
        "ck_daily_quota_valid_identity",
        "daily_quota_usage",
        "(anonymous_id IS NOT NULL AND user_id IS NULL AND api_key_id IS NULL) OR "
        "(anonymous_id IS NULL AND (user_id IS NOT NULL OR api_key_id IS NOT NULL))",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_daily_quota_valid_identity",
        "daily_quota_usage",
        type_="check",
    )
    op.create_check_constraint(
        "ck_daily_quota_exactly_one_identity",
        "daily_quota_usage",
        "(CASE WHEN user_id IS NULL THEN 0 ELSE 1 END + "
        "CASE WHEN api_key_id IS NULL THEN 0 ELSE 1 END + "
        "CASE WHEN anonymous_id IS NULL THEN 0 ELSE 1 END) = 1",
    )
