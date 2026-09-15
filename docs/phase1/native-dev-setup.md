# Phase 1 — Native Development Setup

Native development is the canonical dev environment. Docker is optional for reproducibility.

## Prerequisites

| Tool       | Version               | Notes                                    |
| ---------- | --------------------- | ---------------------------------------- |
| Node.js    | ≥20 (tested: v26.7.0) | LTS recommended                          |
| npm        | ≥10                   | Used for workspace management            |
| PostgreSQL | ≥16 (tested: 18.4)    | Native install; runs on `127.0.0.1:5432` |
| Git        | ≥2.40                 | Standard                                 |

Optional:

- Docker + Docker Compose (alternative Postgres/MinIO; uses port 5433 to avoid clashes with native)
- Dart SDK (for running `packages/dart_core` tests independently)

## Database setup (native Postgres)

```bash
# Create the enclave role and databases
scripts/db-bootstrap.sh

# Verify
PGPASSWORD=enclave_dev psql -h localhost -p 5432 -U enclave -d enclave_dev -c "SELECT 1;"
```

This creates:

- Role: `enclave` (password: `enclave_dev`, CREATEDB)
- Databases: `enclave_dev`, `enclave_test`

Both databases receive the same migration on startup (idempotent `drizzle-kit` migrations run on app boot).

## Running the API

```bash
# Install dependencies
npm install

# Start API (connects to native Postgres at 127.0.0.1:5432)
npm run dev -w apps/api
```

Default env:

- `DATABASE_URL=postgres://enclave:enclave_dev@localhost:5432/enclave_dev`
- `TEST_DATABASE_URL=postgres://enclave:enclave_dev@localhost:5432/enclave_test`

## Running tests

```bash
# All tests (contracts + API, sequential)
npm test

# API only (with Postgres integration tests)
npm test -w apps/api

# Contracts only (no DB required)
npm test -w packages/contracts
```

Tests use `enclave_test` database; tables are truncated between tests (not dropped/migrated per test to save time).

## Dart crypto core tests (packages/dart_core)

```bash
cd packages/dart_core
dart pub get
dart test
```

Requires Dart SDK ≥3.3.0 installed separately (not part of npm workspace).

## Troubleshooting

| Issue                                    | Fix                                                                                       |
| ---------------------------------------- | ----------------------------------------------------------------------------------------- |
| `Connection refused` on `127.0.0.1:5432` | Ensure native Postgres is running: `pg_isready -h 127.0.0.1`                              |
| `FATAL: password authentication failed`  | Role `enclave` with password `enclave_dev` exists: run `scripts/db-bootstrap.sh`          |
| Port 5432 clash with Docker compose      | Docker compose uses 5433 by default; native uses 5432. Both can run simultaneously.       |
| `npm test` hangs                         | Run with `npm test -- --run` if using vitest watch; ensure no other test runner is active |
