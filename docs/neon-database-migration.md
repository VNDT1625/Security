# Move the existing Prewise database to Neon PostgreSQL

The repository includes `scripts/migrate_sqlite_to_postgres.py` for a one-time,
transactional copy from the local runtime database to an **empty** PostgreSQL
database. It never accepts the destination URL on the command line and never
prints it.

## Preconditions

- Create a Neon project/database and copy its PostgreSQL connection URL from
  Neon's **Connect** dialog. Prefer the direct connection for schema migration;
  keep `sslmode=require` in the URL.
- Stop backend writes during the final copy.
- Install the PostgreSQL dependencies: `python -m pip install -e ".[postgres]"`.
- Back up `.aisec-data/armor.db` before starting. Do not upload this backup to a
  public repository or source bundle.

The current local database can be checked without a network connection:

```powershell
python scripts/migrate_sqlite_to_postgres.py --source-only-check
```

## Migrate schema and data

Put the Neon URL in the process environment through the deployment platform's
secret manager. For a one-off interactive PowerShell session, assign it to
`POSTGRES_MIGRATION_URL`; do not paste it into a committed `.env` file.

```powershell
python scripts/migrate_sqlite_to_postgres.py --upgrade-target-schema
```

The helper performs these safety checks before committing:

1. SQLite `PRAGMA integrity_check` must pass.
2. The PostgreSQL Alembic ledger must exist.
3. PostgreSQL must be at the single current head of the repository's migration
   tree.
4. Every source table must exist in the target schema.
5. Every target application table must be empty; existing data is never merged,
   truncated, or overwritten.
6. Every copied table's source and target row counts must match within one
   consistent SQLite read snapshot.

The target transaction is rolled back if any insert or verification fails. A
source at an older Alembic revision is supported when the target has newer
columns with server defaults; only columns common to both schemas are copied.

## Switch the application

After a successful copy, configure the hosted backend with the same URL under
`DATABASE_URL`, plus:

```dotenv
APP_ENV=production
DATABASE_AUTO_CREATE=false
DATABASE_REQUIRE_TLS=true
```

Run `alembic current`, start the backend, and require `/v1/ready` to return HTTP
200 before moving Cloudflare traffic. Keep the original SQLite database and its
backup read-only until the hosted application has passed sign-in, scan history,
report, payment, feedback, and waitlist smoke tests.
