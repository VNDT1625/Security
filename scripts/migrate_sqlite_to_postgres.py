"""Copy a Prewise runtime SQLite database into an empty PostgreSQL database.

The destination URL is read from an environment variable so credentials do not
appear in the process command line.  The copy is atomic: any failed insert or
count verification rolls the destination transaction back.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import MetaData, create_engine, func, inspect, select, update
from sqlalchemy.engine import Connection, Engine, make_url

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = REPOSITORY_ROOT / ".aisec-data" / "armor.db"
DEFAULT_TARGET_ENV = "POSTGRES_MIGRATION_URL"
LEDGER_TABLE = "alembic_version"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--target-env", default=DEFAULT_TARGET_ENV)
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument(
        "--source-only-check",
        action="store_true",
        help="Check SQLite integrity/revision/counts without requiring PostgreSQL.",
    )
    parser.add_argument(
        "--upgrade-target-schema",
        action="store_true",
        help="Run `alembic upgrade head` on the target before copying data.",
    )
    return parser.parse_args()


def _quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _source_inventory(source: Path) -> tuple[str, dict[str, int]]:
    if not source.is_file():
        raise RuntimeError(f"SQLite source does not exist: {source}")
    uri = f"{source.resolve().as_uri()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise RuntimeError(f"SQLite integrity_check failed: {integrity!r}")
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        if LEDGER_TABLE not in tables:
            raise RuntimeError("SQLite source has no Alembic revision ledger")
        revision_row = connection.execute(
            f"SELECT version_num FROM {_quote_sqlite_identifier(LEDGER_TABLE)}"
        ).fetchone()
        if not revision_row:
            raise RuntimeError("SQLite Alembic revision ledger is empty")
        counts = {
            table: connection.execute(
                f"SELECT count(*) FROM {_quote_sqlite_identifier(table)}"
            ).fetchone()[0]
            for table in tables
            if table != LEDGER_TABLE
        }
    return str(revision_row[0]), counts


def _normalize_postgres_url(raw_url: str) -> str:
    value = raw_url.strip()
    if value.startswith("postgres://"):
        value = "postgresql+psycopg://" + value.removeprefix("postgres://")
    elif value.startswith("postgresql://"):
        value = "postgresql+psycopg://" + value.removeprefix("postgresql://")
    url = make_url(value)
    if url.get_backend_name() != "postgresql":
        raise RuntimeError("Destination must be PostgreSQL")
    return value


def _upgrade_target_schema(target_url: str) -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "APP_ENV": "development",
            "DATABASE_AUTO_CREATE": "false",
            "DATABASE_URL": target_url,
        }
    )
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=True,
    )


def _local_alembic_head() -> str:
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory
    except ImportError as exc:
        raise RuntimeError('Install the project "postgres" dependencies (Alembic is missing)') from exc
    config = Config(str(REPOSITORY_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPOSITORY_ROOT / "migrations"))
    head = ScriptDirectory.from_config(config).get_current_head()
    if not head:
        raise RuntimeError("The local Alembic migration tree has no single head")
    return head


def _sqlite_engine(source: Path) -> Engine:
    uri = f"{source.resolve().as_uri()}?mode=ro"
    return create_engine(
        "sqlite://",
        creator=lambda: sqlite3.connect(uri, uri=True),
        future=True,
    )


def _chunks(rows: Iterator[dict], size: int) -> Iterator[list[dict]]:
    batch: list[dict] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def _revision(connection: Connection) -> str:
    inspector = inspect(connection)
    if LEDGER_TABLE not in inspector.get_table_names():
        raise RuntimeError("PostgreSQL target has not been migrated by Alembic")
    value = connection.exec_driver_sql(
        f"SELECT version_num FROM {LEDGER_TABLE}"
    ).scalar_one_or_none()
    if not value:
        raise RuntimeError("PostgreSQL Alembic revision ledger is empty")
    return str(value)


def _assert_empty_target(connection: Connection, metadata: MetaData) -> None:
    occupied = []
    for table in metadata.sorted_tables:
        if table.name == LEDGER_TABLE:
            continue
        count = connection.execute(select(func.count()).select_from(table)).scalar_one()
        if count:
            occupied.append(f"{table.name}={count}")
    if occupied:
        raise RuntimeError(
            "PostgreSQL target is not empty; refusing to merge or overwrite data: "
            + ", ".join(occupied)
        )


def _copy_data(
    source_engine: Engine,
    target_engine: Engine,
    expected_counts: dict[str, int],
    batch_size: int,
    expected_target_revision: str,
) -> tuple[str, int]:
    source_metadata = MetaData()
    source_metadata.reflect(bind=source_engine)
    target_metadata = MetaData()
    target_metadata.reflect(bind=target_engine)

    missing = sorted(set(expected_counts) - set(target_metadata.tables))
    if missing:
        raise RuntimeError("Target schema is missing source tables: " + ", ".join(missing))

    copied_rows = 0
    with source_engine.connect() as source, target_engine.begin() as target:
        # Keep all table reads on one SQLite snapshot, even if a local backend
        # is still running. Stopping writes remains required for final cutover.
        source.exec_driver_sql("BEGIN")
        snapshot_counts = {
            name: source.execute(
                select(func.count()).select_from(source_metadata.tables[name])
            ).scalar_one()
            for name in expected_counts
        }
        target_revision = _revision(target)
        if target_revision != expected_target_revision:
            raise RuntimeError(
                "PostgreSQL schema is not at the local Alembic head: "
                f"target={target_revision}, expected={expected_target_revision}"
            )
        _assert_empty_target(target, target_metadata)

        for target_table in target_metadata.sorted_tables:
            name = target_table.name
            if name == LEDGER_TABLE or name not in source_metadata.tables:
                continue
            source_table = source_metadata.tables[name]
            common_columns = [
                column.name for column in target_table.columns if column.name in source_table.c
            ]
            self_references = {
                element.parent.name
                for constraint in target_table.foreign_key_constraints
                for element in constraint.elements
                if element.column.table.name == name
            }
            if any(not target_table.c[column].nullable for column in self_references):
                raise RuntimeError(f"Cannot safely defer a required self-reference in {name}")

            deferred: list[tuple[dict, dict]] = []
            statement = select(*(source_table.c[column] for column in common_columns))
            rows = (dict(row._mapping) for row in source.execute(statement))
            for batch in _chunks(rows, batch_size):
                if self_references:
                    for row in batch:
                        values = {
                            column: row[column]
                            for column in self_references
                            if row.get(column) is not None
                        }
                        if values:
                            identity = {
                                column.name: row[column.name]
                                for column in target_table.primary_key.columns
                            }
                            deferred.append((identity, values))
                            row.update(dict.fromkeys(values))
                target.execute(target_table.insert(), batch)
                copied_rows += len(batch)

            for identity, values in deferred:
                predicate = [target_table.c[key] == value for key, value in identity.items()]
                target.execute(update(target_table).where(*predicate).values(**values))

        for table_name, source_count in snapshot_counts.items():
            target_table = target_metadata.tables[table_name]
            target_count = target.execute(
                select(func.count()).select_from(target_table)
            ).scalar_one()
            if target_count != source_count:
                raise RuntimeError(
                    f"Count verification failed for {table_name}: "
                    f"source={source_count}, target={target_count}"
                )
    return target_revision, copied_rows


def main() -> int:
    args = _arguments()
    if args.batch_size < 1:
        raise RuntimeError("--batch-size must be positive")
    source = args.source.resolve()
    source_revision, counts = _source_inventory(source)
    total = sum(counts.values())
    print(
        f"SQLite OK: revision={source_revision}, tables={len(counts)}, rows={total}, "
        f"bytes={source.stat().st_size}"
    )
    if args.source_only_check:
        return 0

    raw_target_url = os.environ.get(args.target_env, "")
    if not raw_target_url:
        raise RuntimeError(
            f"Set {args.target_env} to the PostgreSQL/Neon connection URL. "
            "The URL is intentionally not accepted as a command-line argument."
        )
    target_url = _normalize_postgres_url(raw_target_url)
    if args.upgrade_target_schema:
        _upgrade_target_schema(target_url)
    local_head = _local_alembic_head()

    source_engine = _sqlite_engine(source)
    target_engine = create_engine(target_url, pool_pre_ping=True, future=True)
    try:
        target_revision, copied_rows = _copy_data(
            source_engine, target_engine, counts, args.batch_size, local_head
        )
    finally:
        source_engine.dispose()
        target_engine.dispose()
    print(
        f"PostgreSQL copy committed: revision={target_revision}, "
        f"tables={len(counts)}, rows={copied_rows}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
