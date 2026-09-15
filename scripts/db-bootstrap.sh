#!/usr/bin/env bash
# Enclave — native development database bootstrap (PostgreSQL).
# This is the canonical local dev setup. Docker compose is OPTIONAL and not required.
set -euo pipefail

DB_USER="${POSTGRES_USER:-enclave}"
DB_PASS="${POSTGRES_PASSWORD:-enclave_dev}"
DB_DEV="${POSTGRES_DB:-enclave_dev}"
DB_TEST="${POSTGRES_TEST_DB:-enclave_test}"
SUPERUSER="${POSTGRES_SUPERUSER:-postgres}"

if ! command -v psql >/dev/null 2>&1; then
  echo "error: psql not found. Install PostgreSQL first." >&2
  exit 1
fi

apply_sql() {
  local sql="$1"
  psql -v ON_ERROR_STOP=1 -U "$SUPERUSER" -d postgres -c "$sql"
}

apply_sql "DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}') THEN
    CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}' CREATEDB;
  END IF;
END
\$\$;"

for db in "$DB_DEV" "$DB_TEST"; do
  if psql -tAc "SELECT 1 FROM pg_database WHERE datname = '${db}'" -U "$SUPERUSER" -d postgres | grep -q 1; then
    echo "database ${db} already exists"
  else
    createdb -U "$SUPERUSER" -O "$DB_USER" "$db"
    echo "database ${db} created (owner ${DB_USER})"
  fi
done

echo
echo "Enclave native database bootstrap complete."
echo "  dev : postgres://${DB_USER}:***@localhost:5432/${DB_DEV}"
echo "  test: postgres://${DB_USER}:***@localhost:5432/${DB_TEST}"