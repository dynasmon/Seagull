#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${ENV_FILE:-.env}"
AUTO_FIX_ENV="${SEAGULL_PROD_AUTO_FIX_ENV:-true}"

if [ -f "$ENV_FILE" ]; then
  if grep -Eq '^(<<<<<<<|=======|>>>>>>>)' "$ENV_FILE"; then
    echo "[prod-prepare] unresolved merge markers found in ${ENV_FILE}" >&2
    exit 1
  fi
else
  echo "[prod-prepare] ${ENV_FILE} not found; create it from .env.example and set production secrets" >&2
  exit 1
fi

if [ -d .git ]; then
  if [ -f .git/MERGE_HEAD ] || [ -d .git/rebase-merge ] || [ -d .git/rebase-apply ]; then
    echo "[prod-prepare] repository is in an unfinished merge/rebase state; run git merge --abort or git rebase --abort before deploy" >&2
    exit 1
  fi
  if command -v git >/dev/null 2>&1; then
    unresolved="$(git diff --name-only --diff-filter=U 2>/dev/null || true)"
    if [ -n "$unresolved" ]; then
      echo "[prod-prepare] repository still has unresolved conflicts in the index" >&2
      printf '%s\n' "$unresolved" >&2
      exit 1
    fi
  fi
fi

mkdir -p secrets/bootstrap secrets/runtime
chmod 700 secrets/bootstrap secrets/runtime
find secrets/bootstrap -type f -name '*.token' -exec chmod 600 {} \; 2>/dev/null || true

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

read_env_value() {
  key="$1"
  awk -F= -v k="$key" '$1==k{line=$0; sub(/^[^=]*=/, "", line); print line}' "$ENV_FILE" | tail -n1 | tr -d '\r'
}

upsert_env_value() {
  key="$1"
  value="$2"
  python3 - "$ENV_FILE" "$key" "$value" <<'PY'
from pathlib import Path
import sys

env_path = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]

lines = env_path.read_text().splitlines()
out = []
found = False

for line in lines:
    if line.startswith(f"{key}="):
        out.append(f"{key}={value}")
        found = True
    else:
        out.append(line)

if not found:
    if out and out[-1].strip() != "":
        out.append("")
    out.append(f"{key}={value}")

env_path.write_text("\n".join(out) + "\n")
PY
}

gen_secret_inline() {
  bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "$bytes" | tr -d '\n'
  else
    python3 - "$bytes" <<'PY'
import secrets
import sys
print(secrets.token_urlsafe(int(sys.argv[1])))
PY
  fi
}

looks_insecure_secret() {
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  if [ -z "$value" ]; then
    return 0
  fi
  case "$value" in
    admin|password|changeme|change_me|change_me_please|secret|seagull|seagull123|deprecated)
      return 0
      ;;
    *change_me*)
      return 0
      ;;
  esac
  return 1
}

require_env_secret() {
  key="$1"
  min_len="$2"
  bytes="$3"
  value="$(read_env_value "$key")"

  if [ -n "$value" ] && [ "${#value}" -ge "$min_len" ] && ! looks_insecure_secret "$value"; then
    return 0
  fi

  if [ "$AUTO_FIX_ENV" = "true" ]; then
    new_value="$(gen_secret_inline "$bytes")"
    upsert_env_value "$key" "$new_value"
    echo "[prod-prepare] auto-generated secure ${key} in ${ENV_FILE}"
    return 0
  fi

  if [ -z "$value" ] || [ "${#value}" -lt "$min_len" ]; then
    echo "[prod-prepare] missing or weak ${key} in ${ENV_FILE} (min ${min_len} chars)" >&2
  else
    echo "[prod-prepare] insecure placeholder detected for ${key} in ${ENV_FILE}" >&2
  fi
  exit 1
}

require_env_secret_or_file() {
  key="$1"
  file_key="$2"
  min_len="$3"
  bytes="$4"
  file_path="$(read_env_value "$file_key")"

  if [ -n "$file_path" ]; then
    if [ ! -r "$file_path" ]; then
      echo "[prod-prepare] ${file_key} points to a missing or unreadable file: ${file_path}" >&2
      exit 1
    fi
    file_value="$(tr -d '\r\n' < "$file_path")"
    if [ -z "$file_value" ] || [ "${#file_value}" -lt "$min_len" ]; then
      echo "[prod-prepare] secret from ${file_key} is too short (min ${min_len} chars)" >&2
      exit 1
    fi
    if looks_insecure_secret "$file_value"; then
      echo "[prod-prepare] insecure placeholder detected in ${file_key}" >&2
      exit 1
    fi
    return 0
  fi

  require_env_secret "$key" "$min_len" "$bytes"
}

reject_env_pair_conflict() {
  left="$1"
  right="$2"
  left_val="$(read_env_value "$left")"
  right_val="$(read_env_value "$right")"
  if [ -n "$left_val" ] && [ -n "$right_val" ]; then
    echo "[prod-prepare] ${left} and ${right} are both set in ${ENV_FILE}; production must use a single source of truth" >&2
    exit 1
  fi
}

require_env_secret "POSTGRES_PASSWORD" 12 36
require_env_secret_or_file "SEAGULL_REDIS_PASSWORD" "SEAGULL_REDIS_PASSWORD_FILE" 12 36
require_env_secret "SEAGULL_ES_PASSWORD" 12 36
require_env_secret "SEAGULL_JWT_SECRET" 32 48
require_env_secret "SEAGULL_BOOTSTRAP_ADMIN_PASSWORD" 12 36
require_env_secret "SEAGULL_AUDIT_HASH_PEPPER" 32 48

reject_env_pair_conflict "POSTGRES_PASSWORD" "POSTGRES_PASSWORD_FILE"
reject_env_pair_conflict "SEAGULL_REDIS_PASSWORD" "SEAGULL_REDIS_PASSWORD_FILE"
reject_env_pair_conflict "SEAGULL_ES_PASSWORD" "SEAGULL_ES_PASSWORD_FILE"
reject_env_pair_conflict "SEAGULL_JWT_SECRET" "SEAGULL_JWT_SECRET_FILE"
reject_env_pair_conflict "SEAGULL_BOOTSTRAP_ADMIN_PASSWORD" "SEAGULL_BOOTSTRAP_ADMIN_PASSWORD_FILE"

if command -v docker >/dev/null 2>&1; then
  if docker compose \
    -f compose.base.yml \
    -f compose.data.yml \
    -f compose.backend.yml \
    -f compose.portal.yml \
    -f compose.observability.yml \
    -f compose.agents.yml \
    -f compose.prod.yml \
    config >/dev/null; then
    echo "[prod-prepare] compose.prod.yml validated successfully"
  else
    echo "[prod-prepare] docker compose config validation failed" >&2
    exit 1
  fi
else
  echo "[prod-prepare] docker not available; skipped docker compose config validation"
fi
