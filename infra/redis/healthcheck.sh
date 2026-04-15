#!/bin/sh
set -eu

resolve_secret() {
  value="${NETWATCH_REDIS_PASSWORD:-}"
  file_path="${NETWATCH_REDIS_PASSWORD_FILE:-}"

  if [ -n "$value" ] && [ -n "$file_path" ]; then
    echo "[redis-healthcheck] NETWATCH_REDIS_PASSWORD and NETWATCH_REDIS_PASSWORD_FILE cannot both be set" >&2
    exit 1
  fi

  if [ -n "$file_path" ]; then
    if [ ! -r "$file_path" ]; then
      echo "[redis-healthcheck] secret file not readable: ${file_path}" >&2
      exit 1
    fi
    value="$(cat "$file_path")"
  fi

  printf '%s' "$value"
}

REDIS_PASSWORD="$(resolve_secret)"

if [ -n "$REDIS_PASSWORD" ]; then
  pong="$(redis-cli --no-auth-warning -a "$REDIS_PASSWORD" ping 2>/dev/null || true)"
else
  pong="$(redis-cli ping 2>/dev/null || true)"
fi

[ "$pong" = "PONG" ]
