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
fi

mkdir -p secrets/app secrets/step-ca secrets/step-ca/data
chmod 700 secrets/app secrets/step-ca secrets/step-ca/data

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

make_secret_file "secrets/app/jwt-secret.txt" 48
make_secret_file "secrets/app/bootstrap-admin-password.txt" 24
make_secret_file "secrets/app/postgres-password.txt" 48
make_secret_file "secrets/app/redis-password.txt" 48
make_secret_file "secrets/app/es-password.txt" 48
make_secret_file "secrets/step-ca/ca-password.txt" 48
make_secret_file "secrets/step-ca/provisioner-password.txt" 48
