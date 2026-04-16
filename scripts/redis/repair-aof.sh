#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT_DIR"

PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$(basename "$ROOT_DIR" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-*//; s/-*$//')}"
VOLUME_NAME="${1:-${REDIS_VOLUME_NAME:-${PROJECT_NAME}_redis-data}}"
REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"
REDIS_CONTAINER_NAME="${REDIS_CONTAINER_NAME:-seagull-redis}"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"

if ! command -v docker >/dev/null 2>&1; then
  echo "[redis-repair-aof] docker is required" >&2
  exit 1
fi

if docker ps --format '{{.Names}}' | grep -Fx "$REDIS_CONTAINER_NAME" >/dev/null 2>&1; then
  echo "[redis-repair-aof] stop ${REDIS_CONTAINER_NAME} before repairing AOF state" >&2
  exit 1
fi

if ! docker volume inspect "$VOLUME_NAME" >/dev/null 2>&1; then
  echo "[redis-repair-aof] volume not found: ${VOLUME_NAME}" >&2
  echo "[redis-repair-aof] the repair flow only applies to persistent Redis modes" >&2
  exit 1
fi

MOUNTPOINT="$(docker volume inspect "$VOLUME_NAME" --format '{{ .Mountpoint }}')"
TARGET_FILE="$(mktemp)"
cleanup() {
  rm -f "$TARGET_FILE"
}
trap cleanup EXIT INT TERM

if docker run --rm -v "${VOLUME_NAME}:/data" "$REDIS_IMAGE" sh -eu -c '
  if [ -f /data/appendonlydir/appendonly.aof.manifest ]; then
    printf "%s" /data/appendonlydir/appendonly.aof.manifest
    exit 0
  fi
  if [ -f /data/appendonly.aof.manifest ]; then
    printf "%s" /data/appendonly.aof.manifest
    exit 0
  fi
  if [ -f /data/appendonly.aof ]; then
    printf "%s" /data/appendonly.aof
    exit 0
  fi
  exit 12
' >"$TARGET_FILE"; then
  TARGET_PATH="$(cat "$TARGET_FILE")"
else
  status="$?"
  if [ "$status" -eq 12 ]; then
    TARGET_PATH=""
  else
    exit "$status"
  fi
fi

if [ -z "$TARGET_PATH" ]; then
  echo "[redis-repair-aof] no AOF manifest or legacy AOF file found under ${VOLUME_NAME}" >&2
  exit 1
fi

BACKUP_DIR="$(
  docker run --rm -v "${VOLUME_NAME}:/data" "$REDIS_IMAGE" sh -eu -c '
    timestamp="$1"
    backup_dir="/data/seagull-repair-backups/${timestamp}"
    mkdir -p "$backup_dir"
    for path in /data/appendonlydir /data/appendonly.aof /data/appendonly.aof.manifest /data/dump.rdb; do
      [ -e "$path" ] || continue
      cp -a "$path" "$backup_dir"/
    done
    printf "%s" "$backup_dir"
  ' sh "$TIMESTAMP"
)"

echo "[redis-repair-aof] volume: ${VOLUME_NAME}"
echo "[redis-repair-aof] mountpoint: ${MOUNTPOINT}"
echo "[redis-repair-aof] target: ${TARGET_PATH}"
echo "[redis-repair-aof] backup: ${BACKUP_DIR}"

docker run --rm -i -v "${VOLUME_NAME}:/data" "$REDIS_IMAGE" sh -eu -c '
  target="$1"
  printf "y\n" | redis-check-aof --fix "$target"
' sh "$TARGET_PATH"

echo "[redis-repair-aof] completed; inspect Redis logs before restarting the stack"
