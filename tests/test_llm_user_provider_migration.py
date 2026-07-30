import importlib.util
from pathlib import Path

import sqlalchemy as sa

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = (
    ROOT
    / "migrations"
    / "versions"
    / "0025_remove_auto_from_user_provider_choices.py"
)


def load_migration():
    spec = importlib.util.spec_from_file_location("migration_0025", MIGRATION_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_removes_internal_auto_and_preserves_admin_order(monkeypatch) -> None:
    migration = load_migration()
    engine = sa.create_engine("sqlite://")
    metadata = sa.MetaData()
    table = sa.Table(
        "llm_provider_settings",
        metadata,
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("allowed_user_providers", sa.JSON(), nullable=False),
    )
    metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(
            table.insert(),
            [
                {
                    "id": "default",
                    "allowed_user_providers": [
                        "auto",
                        "endpoint",
                        "adapter",
                        "endpoint",
                        "local",
                    ],
                },
                {"id": "disabled", "allowed_user_providers": ["auto"]},
            ],
        )
        monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
        migration.upgrade()
        values = dict(
            connection.execute(
                sa.select(table.c.id, table.c.allowed_user_providers)
            ).all()
        )

    assert values["default"] == ["endpoint", "adapter", "local"]
    assert values["disabled"] == []
