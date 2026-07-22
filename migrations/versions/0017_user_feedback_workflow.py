"""Complete the user feedback workflow.

Revision ID: 0017_user_feedback_workflow
Revises: 0016_cloud_sandbox_dual_modes
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017_user_feedback_workflow"
down_revision = "0016_cloud_sandbox_dual_modes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "user_feedback" not in inspector.get_table_names():
        op.create_table(
            "user_feedback",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("scan_event_id", sa.String(36), sa.ForeignKey("scan_events.id", ondelete="CASCADE"), nullable=False),
            sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.Column("label", sa.String(40), nullable=False),
            sa.Column("reason", sa.String(40), nullable=False, server_default="other"),
            sa.Column("corrected_risk_level", sa.String(32)),
            sa.Column("comment", sa.Text()),
            sa.Column("comment_sha256", sa.String(64)),
            sa.Column("idempotency_key", sa.String(64)),
            sa.Column("status", sa.String(24), nullable=False, server_default="received"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("user_id", "idempotency_key", name="uq_user_feedback_idempotency"),
        )
        return

    columns = {column["name"] for column in inspector.get_columns("user_feedback")}
    additions = {
        "reason": sa.Column("reason", sa.String(40), nullable=False, server_default="other"),
        "comment_sha256": sa.Column("comment_sha256", sa.String(64)),
        "idempotency_key": sa.Column("idempotency_key", sa.String(64)),
        "status": sa.Column("status", sa.String(24), nullable=False, server_default="received"),
        "updated_at": sa.Column("updated_at", sa.DateTime(), nullable=True),
    }
    for name, column in additions.items():
        if name not in columns:
            op.add_column("user_feedback", column)
    op.execute("UPDATE user_feedback SET updated_at = created_at WHERE updated_at IS NULL")
    unique_names = {
        constraint.get("name")
        for constraint in inspector.get_unique_constraints("user_feedback")
    }
    if inspector.bind.dialect.name == "sqlite":
        # Legacy local databases are created with SQLAlchemy create_all and may
        # already contain this table. SQLite needs batch mode for constraints.
        with op.batch_alter_table("user_feedback", recreate="always") as batch:
            batch.alter_column("updated_at", existing_type=sa.DateTime(), nullable=False)
            if "uq_user_feedback_idempotency" not in unique_names:
                batch.create_unique_constraint(
                    "uq_user_feedback_idempotency", ["user_id", "idempotency_key"]
                )
    else:
        op.alter_column("user_feedback", "updated_at", nullable=False)
        if "uq_user_feedback_idempotency" not in unique_names:
            op.create_unique_constraint(
                "uq_user_feedback_idempotency",
                "user_feedback",
                ["user_id", "idempotency_key"],
            )


def downgrade() -> None:
    op.drop_table("user_feedback")
