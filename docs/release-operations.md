# Production release operations

## Preflight

1. Copy `.env.production.example` to an untracked secret store and replace every
   `CHANGE_ME` value. Never commit the resulting file.
2. Render the deployment config with `docker compose --env-file <secret-file>
   -f docker-compose.production.yml config --quiet`.
3. Confirm `/v1/ready` returns HTTP 200. Optional providers are visible through
   `/v1/health`; neither endpoint returns tokens or account identifiers.

## Security and quality gate

Every public release must satisfy all of these checks against the exact source
commit and lockfiles that will be packaged:

```sh
python -m pip_audit -r requirements.runtime.txt
ruff check backend migrations tests
pytest -q
npm --prefix frontend/web audit --omit=dev --audit-level=high
npm --prefix frontend/web run typecheck
npm --prefix frontend/web test -- --run
npm --prefix frontend/web run build
npm --prefix frontend/desktop audit --omit=dev --audit-level=high
npm --prefix frontend/desktop run typecheck
```

- The tracked tree must contain no `.env`, private key, cloud credential, or
  production token. Scan the full Git history before publishing a repository;
  deleting a secret only from the latest commit does not revoke it.
- Keep `APP_ENV=production`, demo seeding and schema auto-create disabled, and
  use unique 32-byte-or-longer values for the API and telemetry peppers.
- Limit `CORS_ALLOW_ORIGINS` to the deployed Web origins plus the packaged
  desktop origin only when that client is shipped. Do not use `*`.
- Terminate TLS at the public proxy, preserve the backend security headers, and
  expose the Web/API containers only through that proxy. The Compose defaults
  bind application ports to loopback for this reason.
- Treat any non-zero dependency-audit result as a release blocker. Do not use a
  forced major downgrade merely to silence an advisory; upgrade or explicitly
  pin a compatible patched transitive dependency and rebuild.

After deployment, smoke-test sign-up/sign-in/logout, one assessment, report
export/share/revoke, account history deletion, feedback submission, waitlist
subscribe/unsubscribe, and an administrator release publish. Verify that auth
and account responses use `Cache-Control: no-store` and public HTTPS responses
include HSTS. Sending a real release email is required only when the Cloudflare
integration is enabled, but a partially configured integration must fail the
production configuration check.

## Public ingress and desktop signing

The Cloudflare Tunnel public hostname for `api.prewise.site` must target the
production backend listener (the Compose default is
`http://127.0.0.1:18080`), not the Next.js listener. Keep the tunnel token in
the deployment secret manager, confirm the connector is healthy in Cloudflare,
and require `https://api.prewise.site/v1/health` and `/v1/ready` to return HTTP
200 before publishing desktop or extension downloads. Cloudflare error 1033 or
HTTP 530 is a hard release blocker; a Quick Tunnel URL is not a production
fallback.

Windows installers must be signed with the verified Prewise publisher identity
and a trusted timestamp. Supply the certificate and password through protected
`CSC_LINK` and `CSC_KEY_PASSWORD` secrets, rebuild the Setup and Portable
artifacts, and verify `Get-AuthenticodeSignature` reports `Valid` before
regenerating `SHA256SUMS.txt`. Never publish an unsigned replacement under an
existing checksum manifest.

## Database migration and backup

`migrate` depends on `database-backup`. The backup service writes a PostgreSQL
custom-format snapshot into the ignored `.aisec-backups/` directory and Alembic
does not start if `pg_dump` fails. Copy snapshots to encrypted off-host storage
and apply an explicit retention policy.

Before a release, test downgrade/upgrade against a restored copy. Do not test a
downgrade against the live database.

## Rollback

Stop application writes before restore. Select the snapshot created immediately
before the failed migration, restore into a new empty database, verify it, then
switch the application connection string. A representative restore command is:

```sh
pg_restore --clean --if-exists --no-owner --no-acl \
  --dbname="$RESTORE_DATABASE_URL" .aisec-backups/prewise-YYYYMMDDTHHMMSSZ.dump
```

Never place a password in the command line. Supply it through the deployment
secret manager or `PGPASSFILE`. Run `alembic current`, database integrity checks,
and `/v1/ready` before reopening traffic.
