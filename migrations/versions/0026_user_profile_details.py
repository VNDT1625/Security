"""Add persisted professional profile and locale preferences.

Revision ID: 0026_user_profile_details
Revises: 0025_remove_auto_user_provider
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0026_user_profile_details"
down_revision = "0025_remove_auto_user_provider"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("organization_name", sa.String(200), nullable=True))
    op.add_column("users", sa.Column("job_title", sa.String(160), nullable=True))
    op.add_column(
        "users",
        sa.Column("country_code", sa.String(2), nullable=False, server_default="VN"),
    )
    op.add_column(
        "users",
        sa.Column("preferred_locale", sa.String(10), nullable=False, server_default="vi"),
    )
    op.add_column(
        "users",
        sa.Column(
            "timezone",
            sa.String(64),
            nullable=False,
            server_default="Asia/Ho_Chi_Minh",
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "timezone")
    op.drop_column("users", "preferred_locale")
    op.drop_column("users", "country_code")
    op.drop_column("users", "job_title")
    op.drop_column("users", "organization_name")
