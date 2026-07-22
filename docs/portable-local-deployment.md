# Portable Local Deployment

This is the recommended mode when Prewise is shipped to a customer
machine or demo laptop and must run with the least setup.

## Decision

The portable build does not need a PostgreSQL server.

Use embedded SQLite for small local state:

- local users and sessions
- API key metadata
- account scan history
- daily quota counters
- admin job status

The app stores this in:

```env
DATABASE_URL=sqlite:///./.aisec-data/armor.db
DATABASE_AUTO_CREATE=true
```

The file is created automatically on first start. To reset the local product
state, stop the app and delete `.aisec-data/armor.db`.

## Docker run

```bash
docker compose up -d --build
```

This starts:

- backend: `http://localhost:8000`
- web: `http://localhost:3000`
- ollama: `http://localhost:11434` for optional explanations

No database container is started. Docker keeps the SQLite file in the
`armor-data` volume.

## Local developer run

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
```

In another terminal:

```bash
cd frontend/web
npm install
npm run dev
```

## Moving to another machine

For the simplest clean install, copy the source folder without `.aisec-data/`.
The new machine will create a fresh local database on first start.

If you want to preserve local accounts and history, copy `.aisec-data/armor.db`
with the project.

## When PostgreSQL is useful

Keep PostgreSQL only for a hosted SaaS or larger production system where many
users share the same backend, you need centralized backups, multiple backend
instances, analytics, or strict audit retention.

Install optional PostgreSQL tooling only for that path:

```bash
pip install -e ".[postgres]"
alembic upgrade head
```
