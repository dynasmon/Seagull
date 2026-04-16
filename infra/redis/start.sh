#!/bin/sh
set -eu

resolve_secret() {
  value_var="$1"
  file_var="$2"
  strict="$3"

  value="$(eval "printf '%s' \"\${${value_var}:-}\"")"
  file_path="$(eval "printf '%s' \"\${${file_var}:-}\"")"

  if [ -n "$value" ] && [ -n "$file_path" ]; then
    echo "[redis-start] ${value_var} and ${file_var} cannot both be set" >&2
    exit 1
  fi

  if [ -n "$file_path" ]; then
    if [ ! -r "$file_path" ]; then
      echo "[redis-start] secret file not readable: ${file_path}" >&2
      exit 1
    fi
    value="$(cat "$file_path")"
  fi

  if [ "$strict" = "true" ] && [ -z "$value" ]; then
    echo "[redis-start] Redis password is required in strict mode" >&2
    exit 1
  fi

  printf '%s' "$value"
}

CONFIG_FILE="${SEAGULL_REDIS_CONFIG_FILE:-}"
STRICT_PASSWORD="${SEAGULL_REDIS_STRICT_PASSWORD:-false}"

if [ -z "$CONFIG_FILE" ]; then
  echo "[redis-start] SEAGULL_REDIS_CONFIG_FILE is required" >&2
  exit 1
fi

if [ ! -r "$CONFIG_FILE" ]; then
  echo "[redis-start] Redis config file not readable: ${CONFIG_FILE}" >&2
  exit 1
fi

mkdir -p /data /tmp/redis

REDIS_PASSWORD="$(resolve_secret SEAGULL_REDIS_PASSWORD SEAGULL_REDIS_PASSWORD_FILE "$STRICT_PASSWORD")"

set -- redis-server "$CONFIG_FILE"
if [ -n "$REDIS_PASSWORD" ]; then
  set -- "$@" --requirepass "$REDIS_PASSWORD"
fi

exec "$@"
