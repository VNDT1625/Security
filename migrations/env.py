from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from backend import models  # noqa: F401
from backend.config import settings
from backend.db import Base

config = context.config
config.set_main_option("sqlalchemy.url", settings.database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _ensure_postgresql_version_capacity(connection) -> None:
    """Keep Alembic's revision ledger wide enough for descriptive revision IDs.

    Alembic defaults ``version_num`` to VARCHAR(32). Several established
    revisions are longer than that, which SQLite tolerates but PostgreSQL
    correctly rejects. Creating/widening the ledger before migration makes a
    clean PostgreSQL deployment and an upgrade from a partial deployment safe.
    """
    if connection.dialect.name != "postgresql":
        return
    connection.exec_driver_sql(
        "CREATE TABLE IF NOT EXISTS alembic_version "
        "(version_num VARCHAR(128) NOT NULL PRIMARY KEY)"
    )
    connection.exec_driver_sql(
        "ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR(128)"
    )
    connection.commit()


def run_migrations_offline() -> None:
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = settings.database_url
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        _ensure_postgresql_version_capacity(connection)
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
