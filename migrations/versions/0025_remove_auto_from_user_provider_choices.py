"""Keep internal auto fallback out of user-selectable AI provider choices.

Revision ID: 0025_remove_auto_user_provider
Revises: 0024_seed_plan_catalog
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0025_remove_auto_user_provider"
down_revision = "0024_seed_plan_catalog"
branch_labels = None
depends_on = None

USER_PROVIDERS = ("adapter", "local", "endpoint")


def _provider_table() -> sa.TableClause:
    return sa.table(
        "llm_provider_settings",
        sa.column("id", sa.String()),
        sa.column("allowed_user_providers", sa.JSON()),
    )


def _set_server_default(value: str) -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.alter_column(
            "llm_provider_settings",
            "allowed_user_providers",
            existing_type=sa.JSON(),
            server_default=sa.text(f"'{value}'::json"),
        )


def upgrade() -> None:
    bind = op.get_bind()
    table = _provider_table()
    rows = list(
        bind.execute(
            sa.select(table.c.id, table.c.allowed_user_providers)
        ).mappings()
    )
    for row in rows:
        current = row["allowed_user_providers"]
        providers = current if isinstance(current, list) else []
        normalized = list(
            dict.fromkeys(item for item in providers if item in USER_PROVIDERS)
        )
        if normalized != providers:
            bind.execute(
                sa.update(table)
                .where(table.c.id == row["id"])
                .values(allowed_user_providers=normalized)
            )
    _set_server_default('["adapter","local","endpoint"]')


def downgrade() -> None:
    bind = op.get_bind()
    table = _provider_table()
    rows = list(
        bind.execute(
            sa.select(table.c.id, table.c.allowed_user_providers)
        ).mappings()
    )
    for row in rows:
        current = row["allowed_user_providers"]
        providers = current if isinstance(current, list) else []
        restored = ["auto", *providers] if "auto" not in providers else providers
        bind.execute(
            sa.update(table)
            .where(table.c.id == row["id"])
            .values(allowed_user_providers=restored)
        )
    _set_server_default('["auto","adapter","local","endpoint"]')
