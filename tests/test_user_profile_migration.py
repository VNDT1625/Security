from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = ROOT / "migrations" / "versions" / "0026_user_profile_details.py"


def load_migration():
    spec = importlib.util.spec_from_file_location("user_profile_details", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_profile_migration_backfills_existing_accounts() -> None:
    migration = load_migration()
    engine = sa.create_engine("sqlite://")
    metadata = sa.MetaData()
    users = sa.Table(
        "users",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
    )

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(
            users.insert().values(
                id="existing-user",
                email="existing@example.com",
                display_name="Existing",
            )
        )
        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()

        columns = {item["name"] for item in sa.inspect(connection).get_columns("users")}
        row = connection.execute(
            sa.text(
                "SELECT organization_name, job_title, country_code, "
                "preferred_locale, timezone FROM users WHERE id = 'existing-user'"
            )
        ).mappings().one()

    assert {
        "organization_name",
        "job_title",
        "country_code",
        "preferred_locale",
        "timezone",
    } <= columns
    assert dict(row) == {
        "organization_name": None,
        "job_title": None,
        "country_code": "VN",
        "preferred_locale": "vi",
        "timezone": "Asia/Ho_Chi_Minh",
    }
