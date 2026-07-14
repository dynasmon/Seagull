#!/bin/sh
set -eu

: "${POSTGRES_REPLICATION_USER:?POSTGRES_REPLICATION_USER is required}"
: "${POSTGRES_REPLICATION_PASSWORD:?POSTGRES_REPLICATION_PASSWORD is required}"

psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -v repl_user="$POSTGRES_REPLICATION_USER" -v repl_password="$POSTGRES_REPLICATION_PASSWORD" <<'EOSQL'
SELECT format('CREATE ROLE %I WITH REPLICATION LOGIN PASSWORD %L', :'repl_user', :'repl_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'repl_user')
\gexec
SELECT format('ALTER ROLE %I WITH REPLICATION LOGIN PASSWORD %L', :'repl_user', :'repl_password')
WHERE EXISTS (SELECT FROM pg_roles WHERE rolname = :'repl_user')
\gexec
EOSQL

IFS=','
for slot in ${POSTGRES_REPLICATION_SLOTS:-}; do
  slot=$(printf '%s' "$slot" | tr -d '[:space:]')
  [ -n "$slot" ] || continue
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v slot="$slot" <<'EOSQL'
SELECT pg_create_physical_replication_slot(:'slot', true)
WHERE NOT EXISTS (SELECT FROM pg_replication_slots WHERE slot_name = :'slot');
EOSQL
done
unset IFS

echo "host replication $POSTGRES_REPLICATION_USER all scram-sha-256" >> "$PGDATA/pg_hba.conf"
