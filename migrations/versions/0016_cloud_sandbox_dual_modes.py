"""Add automatic and interactive cloud sandbox lease state.

Revision ID: 0016_cloud_sandbox_dual_modes
Revises: 0015_free_daily_scan_quota
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0016_cloud_sandbox_dual_modes"
down_revision = "0015_free_daily_scan_quota"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {
        column["name"]
        for column in inspector.get_columns("cloud_sandbox_sessions")
    }
    additions = [
        (
            "mode",
            sa.Column(
                "mode",
                sa.String(length=16),
                nullable=False,
                server_default=sa.text("'auto'"),
            ),
        ),
        (
            "lease_minutes",
            sa.Column(
                "lease_minutes",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("10"),
            ),
        ),
        ("ready_at", sa.Column("ready_at", sa.DateTime())),
        ("lease_expires_at", sa.Column("lease_expires_at", sa.DateTime())),
        (
            "remote_access_token_hash",
            sa.Column("remote_access_token_hash", sa.String(length=64)),
        ),
        (
            "remote_access_token_expires_at",
            sa.Column("remote_access_token_expires_at", sa.DateTime()),
        ),
        (
            "remote_access_token_used_at",
            sa.Column("remote_access_token_used_at", sa.DateTime()),
        ),
        (
            "termination_reason",
            sa.Column("termination_reason", sa.String(length=32)),
        ),
        (
            "termination_requested_at",
            sa.Column("termination_requested_at", sa.DateTime()),
        ),
        ("cleanup_completed_at", sa.Column("cleanup_completed_at", sa.DateTime())),
    ]
    for name, column in additions:
        if name not in existing:
            op.add_column("cloud_sandbox_sessions", column)

    sessions = sa.table(
        "cloud_sandbox_sessions",
        sa.column("status", sa.String()),
        sa.column("mode", sa.String()),
        sa.column("ready_at", sa.DateTime()),
        sa.column("lease_expires_at", sa.DateTime()),
        sa.column("expires_at", sa.DateTime()),
        sa.column("updated_at", sa.DateTime()),
        sa.column("remote_url", sa.Text()),
    )
    # Existing rows predate explicit readiness. Preserve their old expiry while
    # treating already-ready rows as automatic sessions. Legacy remote URLs were
    # public-host guesses and must never survive this security boundary upgrade.
    op.execute(
        sessions.update()
        .where(sessions.c.status == "ready")
        .values(
            ready_at=sessions.c.updated_at,
            lease_expires_at=sessions.c.expires_at,
        )
    )
    op.execute(sessions.update().values(remote_url=None))

    indexes = {
        index["name"]
        for index in sa.inspect(op.get_bind()).get_indexes("cloud_sandbox_sessions")
    }
    if "ix_cloud_sandbox_sessions_mode" not in indexes:
        op.create_index(
            "ix_cloud_sandbox_sessions_mode",
            "cloud_sandbox_sessions",
            ["mode"],
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    indexes = {
        index["name"]
        for index in inspector.get_indexes("cloud_sandbox_sessions")
    }
    if "ix_cloud_sandbox_sessions_mode" in indexes:
        op.drop_index(
            "ix_cloud_sandbox_sessions_mode",
            table_name="cloud_sandbox_sessions",
        )
    existing = {
        column["name"]
        for column in sa.inspect(op.get_bind()).get_columns("cloud_sandbox_sessions")
    }
    for name in (
        "cleanup_completed_at",
        "termination_requested_at",
        "termination_reason",
        "remote_access_token_used_at",
        "remote_access_token_expires_at",
        "remote_access_token_hash",
        "lease_expires_at",
        "ready_at",
        "lease_minutes",
        "mode",
    ):
        if name in existing:
            op.drop_column("cloud_sandbox_sessions", name)
