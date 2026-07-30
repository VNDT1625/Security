from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = ROOT / "migrations" / "versions" / "0024_seed_plan_catalog.py"


def load_migration():
    spec = importlib.util.spec_from_file_location("seed_plan_catalog", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_plan_catalog_migration_seeds_all_required_tiers_idempotently(monkeypatch) -> None:
    migration = load_migration()
    engine = sa.create_engine("sqlite://")
    metadata = sa.MetaData()
    plans = sa.Table(
        "plans",
        metadata,
        sa.Column("tier", sa.String(32), primary_key=True),
        sa.Column("label", sa.String(40), nullable=False),
        sa.Column("daily_scan_limit", sa.Integer()),
        sa.Column("monthly_price_vnd", sa.Integer()),
        sa.Column("yearly_price_vnd", sa.Integer()),
        sa.Column("features", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    with engine.begin() as connection:
        metadata.create_all(connection)
        monkeypatch.setattr(migration.op, "get_bind", lambda: connection)

        migration.upgrade()
        migration.upgrade()

        rows = connection.execute(
            sa.select(plans.c.tier, plans.c.daily_scan_limit).order_by(plans.c.tier)
        ).all()

    assert rows == [
        ("enterprise", None),
        ("free", 1000),
        ("pro", None),
        ("team", None),
    ]
