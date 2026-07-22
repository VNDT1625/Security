"""Add per-user AI context weights constrained by the global admin policy.

Revision ID: 0021_user_ai_context_settings
Revises: 0020_report_shares
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021_user_ai_context_settings"
down_revision = "0020_report_shares"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "user_ai_context_settings" in inspector.get_table_names():
        return
    op.create_table(
        "user_ai_context_settings",
        sa.Column("user_id", sa.String(length=36), primary_key=True),
        sa.Column("weight_percent", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "weight_percent >= 0 AND weight_percent <= 100",
            name="ck_user_ai_context_weight_percent",
        ),
    )


def downgrade() -> None:
    if "user_ai_context_settings" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("user_ai_context_settings")
