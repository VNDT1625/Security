"""Add admin feedback notes and product release workflow.

Revision ID: 0019_admin_operations
Revises: 0018_product_waitlist
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019_admin_operations"
down_revision = "0018_product_waitlist"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    feedback_columns = {c["name"] for c in inspector.get_columns("user_feedback")}
    if "admin_note" not in feedback_columns:
        op.add_column("user_feedback", sa.Column("admin_note", sa.Text(), nullable=True))

    waitlist_columns = {c["name"] for c in inspector.get_columns("product_waitlist_entries")}
    if "unsubscribed_at" not in waitlist_columns:
        op.add_column("product_waitlist_entries", sa.Column("unsubscribed_at", sa.DateTime()))
    if "notified_at" not in waitlist_columns:
        op.add_column("product_waitlist_entries", sa.Column("notified_at", sa.DateTime()))

    if "product_releases" not in inspector.get_table_names():
        op.create_table(
            "product_releases",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("product", sa.String(32), nullable=False),
            sa.Column("version", sa.String(64), nullable=False),
            sa.Column("download_url", sa.String(2000), nullable=False),
            sa.Column("checksum_sha256", sa.String(64), nullable=False),
            sa.Column("signature_note", sa.String(500)),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("published_by_user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.Column("published_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_product_releases_product", "product_releases", ["product"])
        op.create_index("ix_product_releases_active", "product_releases", ["active"])


def downgrade() -> None:
    op.drop_table("product_releases")
    op.drop_column("product_waitlist_entries", "notified_at")
    op.drop_column("product_waitlist_entries", "unsubscribed_at")
    op.drop_column("user_feedback", "admin_note")
