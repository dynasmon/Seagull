#!/bin/sh
set -eu

: "${PGDATA:?PGDATA is required}"
: "${POSTGRES_REPLICATION_USER:?POSTGRES_REPLICATION_USER is required}"
: "${POSTGRES_REPLICATION_PASSWORD:?POSTGRES_REPLICATION_PASSWORD is required}"
: "${SEAGULL_PG_REPLICATION_SLOT:?SEAGULL_PG_REPLICATION_SLOT is required}"

PRIMARY_HOST="${SEAGULL_PG_PRIMARY_HOST:-postgres}"
PRIMARY_PORT="${SEAGULL_PG_PRIMARY_PORT:-5432}"

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  until pg_isready -h "$PRIMARY_HOST" -p "$PRIMARY_PORT" -U "$POSTGRES_REPLICATION_USER" >/dev/null 2>&1; do
    echo "waiting for primary at $PRIMARY_HOST:$PRIMARY_PORT"
    sleep 1
  done
  rm -rf "$PGDATA"/* "$PGDATA"/.[!.]* 2>/dev/null || true
  PGPASSWORD="$POSTGRES_REPLICATION_PASSWORD" pg_basebackup \
    -h "$PRIMARY_HOST" -p "$PRIMARY_PORT" -U "$POSTGRES_REPLICATION_USER" \
    -D "$PGDATA" -X stream -S "$SEAGULL_PG_REPLICATION_SLOT" --checkpoint=fast --no-password
  {
    echo "primary_conninfo = 'host=$PRIMARY_HOST port=$PRIMARY_PORT user=$POSTGRES_REPLICATION_USER password=$POSTGRES_REPLICATION_PASSWORD application_name=$SEAGULL_PG_REPLICATION_SLOT'"
    echo "primary_slot_name = '$SEAGULL_PG_REPLICATION_SLOT'"
  } >> "$PGDATA/postgresql.auto.conf"
  touch "$PGDATA/standby.signal"
  chmod 0700 "$PGDATA"
fi

exec postgres \
  -c hot_standby=on \
  -c hot_standby_feedback=on \
  -c shared_preload_libraries=pg_stat_statements \
  -c shared_buffers="${SEAGULL_PG_SHARED_BUFFERS:-128MB}" \
  -c max_connections="${SEAGULL_PG_MAX_CONNECTIONS:-300}"
