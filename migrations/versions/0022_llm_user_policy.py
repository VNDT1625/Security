"""Add admin allowlists for per-user AI provider and model choices.

Revision ID: 0022_llm_user_policy
Revises: 0021_user_ai_context_settings
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022_llm_user_policy"
down_revision = "0021_user_ai_context_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("llm_provider_settings")}
    if "allowed_user_providers" not in columns:
        op.add_column(
            "llm_provider_settings",
            sa.Column(
                "allowed_user_providers",
                sa.JSON(),
                nullable=False,
                server_default='["auto","adapter","local","endpoint"]',
            ),
        )
    if "allowed_user_models" not in columns:
        op.add_column(
            "llm_provider_settings",
            sa.Column("allowed_user_models", sa.JSON(), nullable=False, server_default="[]"),
        )


def downgrade() -> None:
    columns = {
        column["name"]
        for column in sa.inspect(op.get_bind()).get_columns("llm_provider_settings")
    }
    if "allowed_user_models" in columns:
        op.drop_column("llm_provider_settings", "allowed_user_models")
    if "allowed_user_providers" in columns:
        op.drop_column("llm_provider_settings", "allowed_user_providers")
