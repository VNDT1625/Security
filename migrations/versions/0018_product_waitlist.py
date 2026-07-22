"""Add the public product release waitlist.

Revision ID: 0018_product_waitlist
Revises: 0017_user_feedback_workflow
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018_product_waitlist"
down_revision = "0017_user_feedback_workflow"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "product_waitlist_entries" not in inspector.get_table_names():
        op.create_table(
            "product_waitlist_entries",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("email", sa.String(length=320), nullable=False),
            sa.Column("product", sa.String(length=32), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("email", "product", name="uq_waitlist_email_product"),
        )
        op.create_index(
            "ix_product_waitlist_entries_email",
            "product_waitlist_entries",
            ["email"],
        )
        op.create_index(
            "ix_product_waitlist_entries_product",
            "product_waitlist_entries",
            ["product"],
        )
        return

    # The application historically used create_all on startup, so an
    # unversioned database can already have the final table. Only add missing
    # indexes/constraints in that case.
    index_names = {index["name"] for index in inspector.get_indexes("product_waitlist_entries")}
    if "ix_product_waitlist_entries_email" not in index_names:
        op.create_index("ix_product_waitlist_entries_email", "product_waitlist_entries", ["email"])
    if "ix_product_waitlist_entries_product" not in index_names:
        op.create_index("ix_product_waitlist_entries_product", "product_waitlist_entries", ["product"])

    unique_columns = {
        tuple(constraint.get("column_names") or [])
        for constraint in inspector.get_unique_constraints("product_waitlist_entries")
    }
    if ("email", "product") not in unique_columns:
        if inspector.bind.dialect.name == "sqlite":
            op.create_index(
                "uq_waitlist_email_product",
                "product_waitlist_entries",
                ["email", "product"],
                unique=True,
            )
        else:
            op.create_unique_constraint(
                "uq_waitlist_email_product",
                "product_waitlist_entries",
                ["email", "product"],
            )


def downgrade() -> None:
    op.drop_index(
        "ix_product_waitlist_entries_product",
        table_name="product_waitlist_entries",
    )
    op.drop_index(
        "ix_product_waitlist_entries_email",
        table_name="product_waitlist_entries",
    )
    op.drop_table("product_waitlist_entries")
