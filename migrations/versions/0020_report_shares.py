"""Add expiring, revocable redacted report shares.

Revision ID: 0020_report_shares
Revises: 0019_admin_operations
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020_report_shares"
down_revision = "0019_admin_operations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "report_shares" in inspector.get_table_names():
        return
    op.create_table(
        "report_shares",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("scan_event_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["scan_event_id"], ["scan_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    for column in ("user_id", "scan_event_id", "token_hash", "expires_at", "revoked_at", "created_at"):
        op.create_index(f"ix_report_shares_{column}", "report_shares", [column])


def downgrade() -> None:
    op.drop_table("report_shares")
