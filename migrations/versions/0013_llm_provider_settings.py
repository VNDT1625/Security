"""Add encrypted admin-managed LLM provider settings.

Revision ID: 0013_llm_provider_settings
Revises: 0012_cloud_sandbox_sample_delivery
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0013_llm_provider_settings"
down_revision = "0012_cloud_sandbox_sample_delivery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "llm_provider_settings" in inspector.get_table_names():
        return
    op.create_table(
        "llm_provider_settings",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("base_url", sa.String(length=1000), nullable=False),
        sa.Column("model", sa.String(length=300), nullable=False),
        sa.Column("api_key_ciphertext", sa.Text(), nullable=False),
        sa.Column("updated_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["updated_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
    )
    op.create_index(
        "ix_llm_provider_settings_updated_by_user_id",
        "llm_provider_settings",
        ["updated_by_user_id"],
    )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "llm_provider_settings" not in inspector.get_table_names():
        return
    op.drop_index(
        "ix_llm_provider_settings_updated_by_user_id",
        table_name="llm_provider_settings",
    )
    op.drop_table("llm_provider_settings")
