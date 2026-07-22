"""Add per-user encrypted AI provider settings.

Revision ID: 0014_user_llm_provider_settings
Revises: 0013_llm_provider_settings
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014_user_llm_provider_settings"
down_revision = "0013_llm_provider_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "user_llm_provider_settings" in inspector.get_table_names():
        return
    op.create_table(
        "user_llm_provider_settings",
        sa.Column("user_id", sa.String(length=36), primary_key=True),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("base_url", sa.String(length=1000), nullable=False),
        sa.Column("model", sa.String(length=300), nullable=False),
        sa.Column("api_key_ciphertext", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )


def downgrade() -> None:
    if "user_llm_provider_settings" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("user_llm_provider_settings")
