#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${ENV_FILE:-.env}"

if [ -f "$ENV_FILE" ]; then
  if grep -Eq '^(<<<<<<<|=======|>>>>>>>)' "$ENV_FILE"; then
    echo "[prod-prepare] unresolved merge markers found in ${ENV_FILE}" >&2
    exit 1
  fi
else
  echo "[prod-prepare] ${ENV_FILE} not found; create it from .env.example and set production secrets" >&2
  exit 1
fi

mkdir -p secrets/step-ca secrets/step-ca/data
chmod 700 secrets/step-ca secrets/step-ca/data

make_secret_file() {
  target="$1"
  bytes="$2"
  if [ -s "$target" ]; then
    chmod 600 "$target"
    return 0
  fi

  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "$bytes" > "$target"
  else
    python3 - <<'PY' > "$target"
import secrets
print(secrets.token_urlsafe(64))
PY
  fi
  chmod 600 "$target"
  echo "[prod-prepare] created $target"
}

make_secret_file "secrets/step-ca/ca-password.txt" 48
make_secret_file "secrets/step-ca/provisioner-password.txt" 48

require_env_secret() {
  key="$1"
  min_len="$2"
  value="$(awk -F= -v k="$key" '$1==k{print substr($0, index($0,$2))}' "$ENV_FILE" | tail -n1 | tr -d '\r')"
  if [ -z "$value" ] || [ "${#value}" -lt "$min_len" ]; then
    echo "[prod-prepare] missing or weak ${key} in ${ENV_FILE} (min ${min_len} chars)" >&2
    exit 1
  fi
}

require_env_secret "POSTGRES_PASSWORD" 12
require_env_secret "NETWATCH_REDIS_PASSWORD" 12
require_env_secret "NETWATCH_ES_PASSWORD" 12
require_env_secret "NETWATCH_JWT_SECRET" 32
require_env_secret "NETWATCH_BOOTSTRAP_ADMIN_PASSWORD" 12
