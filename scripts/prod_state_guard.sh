#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

MODE="${1:-check}"
ENV_FILE="${ENV_FILE:-.env}"
STATE_DIR="secrets/runtime"
STATE_FILE="${STATE_DIR}/prod-state.json"
STATE_SCHEMA_VERSION="2"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$(basename "$ROOT_DIR" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-*//; s/-*$//')}"

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

current_fingerprint() {
  python3 - "$ENV_FILE" "$PROJECT_NAME" "$STATE_SCHEMA_VERSION" <<'PY'
from hashlib import sha256
from pathlib import Path
import json
import sys

env_path = Path(sys.argv[1])
project_name = sys.argv[2]
schema_version = sys.argv[3]
keys = [
    "POSTGRES_DB",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "NETWATCH_REDIS_PASSWORD",
    "NETWATCH_ES_USERNAME",
    "NETWATCH_ES_PASSWORD",
    "NETWATCH_JWT_SECRET",
    "NETWATCH_BOOTSTRAP_ADMIN_PASSWORD",
    "NETWATCH_AUDIT_HASH_PEPPER",
    "AGENT_CORE_ID",
    "AGENT_SENSOR_ID",
    "AGENT_LATERAL_ID",
]
values = {}
if env_path.exists():
    for raw_line in env_path.read_text().splitlines():
        if not raw_line or raw_line.startswith("#") or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        values[key] = value
def file_sha(path_str: str) -> str:
    path = Path(path_str)
    if not path.exists():
        return ""
    return sha256(path.read_bytes()).hexdigest()

payload = {
    "schema_version": schema_version,
    "project_name": project_name,
    "keys": {key: values.get(key, "") for key in keys},
    "file_keys": {
        "NETWATCH_REDIS_PASSWORD_FILE": {
            "path": values.get("NETWATCH_REDIS_PASSWORD_FILE", ""),
            "sha256": file_sha(values.get("NETWATCH_REDIS_PASSWORD_FILE", "")),
        },
    },
}
print(sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest())
PY
}

store_state() {
  fingerprint="$1"
  python3 - "$STATE_FILE" "$fingerprint" "$PROJECT_NAME" "$STATE_SCHEMA_VERSION" <<'PY'
from pathlib import Path
import json
import sys
from datetime import datetime, timezone

state_path = Path(sys.argv[1])
fingerprint = sys.argv[2]
project_name = sys.argv[3]
schema_version = sys.argv[4]

state_path.write_text(json.dumps({
    "schema_version": schema_version,
    "project_name": project_name,
    "fingerprint": fingerprint,
    "updated_at": datetime.now(timezone.utc).isoformat(),
}, indent=2) + "\n")
PY
  chmod 600 "$STATE_FILE"
}

load_state_value() {
  key="$1"
  python3 - "$STATE_FILE" "$key" <<'PY'
from pathlib import Path
import json
import sys

state_path = Path(sys.argv[1])
key = sys.argv[2]
if not state_path.exists():
    print("")
    raise SystemExit(0)
try:
    data = json.loads(state_path.read_text())
except Exception:
    print("")
    raise SystemExit(0)
print(data.get(key, ""))
PY
}

managed_volume_names() {
  printf '%s\n' \
    "${PROJECT_NAME}_postgres-data" \
    "${PROJECT_NAME}_redis-data" \
    "${PROJECT_NAME}_elastic-data" \
    "${PROJECT_NAME}_clickhouse-data" \
    "${PROJECT_NAME}_caddy-data" \
    "${PROJECT_NAME}_caddy-config"
}

existing_managed_volumes() {
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi
  existing="$(docker volume ls --format '{{.Name}}' 2>/dev/null || true)"
  if [ -z "$existing" ]; then
    return 0
  fi
  managed_volume_names | while IFS= read -r volume_name; do
    [ -n "$volume_name" ] || continue
    printf '%s\n' "$existing" | grep -Fx "$volume_name" >/dev/null 2>&1 && printf '%s\n' "$volume_name"
  done
}

fingerprint="$(current_fingerprint)"

case "$MODE" in
  check)
    if [ ! -f "$STATE_FILE" ]; then
      adopted_volumes="$(existing_managed_volumes || true)"
      if [ -n "$adopted_volumes" ]; then
        echo "[prod-state] existing runtime volumes found without a state marker; forcing one-time reset for a deterministic first production boot" >&2
        printf '%s\n' "$adopted_volumes" >&2
        exit 10
      fi
      exit 0
    fi

    stored_project="$(load_state_value project_name)"
    stored_fingerprint="$(load_state_value fingerprint)"
    stored_schema="$(load_state_value schema_version)"

    if [ "$stored_schema" != "$STATE_SCHEMA_VERSION" ]; then
      echo "[prod-state] stored runtime schema version changed; reset required" >&2
      exit 10
    fi
    if [ "$stored_project" != "$PROJECT_NAME" ]; then
      echo "[prod-state] compose project name changed from '${stored_project}' to '${PROJECT_NAME}'; reset required" >&2
      exit 10
    fi
    if [ "$stored_fingerprint" != "$fingerprint" ]; then
      echo "[prod-state] critical production secrets/config changed since the last successful boot; reset required" >&2
      exit 10
    fi
    ;;
  commit)
    store_state "$fingerprint"
    echo "[prod-state] recorded runtime state fingerprint"
    ;;
  clear)
    rm -f "$STATE_FILE"
    ;;
  *)
    echo "Usage: $0 [check|commit|clear]" >&2
    exit 1
    ;;
esac
