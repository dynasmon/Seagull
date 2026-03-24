#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing .env at $ENV_FILE" >&2
  exit 1
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need_cmd curl
need_cmd python3

read_env() {
  local key="$1"
  local def="${2:-}"
  local line
  line="$(grep -E "^${key}=" "$ENV_FILE" | tail -n 1 || true)"
  if [[ -z "$line" ]]; then
    printf "%s" "$def"
    return 0
  fi
  printf "%s" "${line#*=}"
}

upsert_env() {
  local key="$1"
  local value="$2"
  if grep -qE "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    printf "\n%s=%s\n" "$key" "$value" >> "$ENV_FILE"
  fi
}

write_token_file() {
  local agent_id="$1"
  local token="$2"
  local out_dir="$3"
  mkdir -p "$out_dir"
  chmod 700 "$out_dir"
  local out_file="${out_dir}/${agent_id}.token"
  printf "%s\n" "$token" > "$out_file"
  chmod 600 "$out_file"
}

EDGE_PORT="$(read_env NETWATCH_EDGE_HTTPS_PORT 8443)"
BACKEND_PORT="$(read_env NETWATCH_BACKEND_PORT 8000)"
ADMIN_USER="$(read_env NETWATCH_BOOTSTRAP_ADMIN_USERNAME admin)"
ADMIN_PASS="$(read_env NETWATCH_BOOTSTRAP_ADMIN_PASSWORD "")"
TTL_SECONDS="$(read_env NETWATCH_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS 900)"

if [[ -z "$ADMIN_PASS" ]]; then
  echo "NETWATCH_BOOTSTRAP_ADMIN_PASSWORD is empty in .env" >&2
  exit 1
fi

EDGE_BASE="https://localhost:${EDGE_PORT}"
BACKEND_BASE="http://localhost:${BACKEND_PORT}"
LOGIN_TIMEOUT_SECONDS="${NETWATCH_MINT_TOKENS_LOGIN_TIMEOUT_SECONDS:-180}"
LOGIN_RETRY_SECONDS="${NETWATCH_MINT_TOKENS_LOGIN_RETRY_SECONDS:-2}"

ACCESS_TOKEN=""
API_BASE=""
API_PREFIX=""
LOGIN_ERR=""

try_login() {
  local base="$1"
  local prefix="$2"
  local body_file
  local code
  body_file="$(mktemp)"
  code="$(curl -ksS -o "$body_file" -w "%{http_code}" \
    "${base}${prefix}/auth/login" \
    -H "content-type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}")"
  if [[ "$code" == "200" ]]; then
    ACCESS_TOKEN="$(python3 - "$body_file" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], 'r', encoding='utf-8') as fh:
        data = json.load(fh)
except Exception:
    print('')
else:
    print(data.get('access_token', '') or '')
PY
)"
    if [[ -n "$ACCESS_TOKEN" ]]; then
      API_BASE="$base"
      API_PREFIX="$prefix"
      rm -f "$body_file"
      return 0
    fi
  fi
  LOGIN_ERR="status=${code} endpoint=${base}${prefix}/auth/login body=$(cat "$body_file")"
  rm -f "$body_file"
  return 1
}

for base in "$EDGE_BASE" "$BACKEND_BASE"; do
  for prefix in "" "/api"; do
    if try_login "$base" "$prefix"; then
      break 2
    fi
  done
done

if [[ -z "$ACCESS_TOKEN" ]]; then
  now_ts="$(date +%s)"
  deadline=$((now_ts + LOGIN_TIMEOUT_SECONDS))
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    for base in "$EDGE_BASE" "$BACKEND_BASE"; do
      for prefix in "" "/api"; do
        if try_login "$base" "$prefix"; then
          break 3
        fi
      done
    done
    sleep "$LOGIN_RETRY_SECONDS"
  done
fi

if [[ -z "$ACCESS_TOKEN" ]]; then
  echo "Failed to login as admin after ${LOGIN_TIMEOUT_SECONDS}s." >&2
  echo "$LOGIN_ERR" >&2
  exit 1
fi

declare -a AGENT_MAP=(
  "AGENT_CORE_ID:AGENT_CORE_BOOTSTRAP_TOKEN"
  "AGENT_SENSOR_ID:AGENT_SENSOR_BOOTSTRAP_TOKEN"
  "AGENT_LATERAL_ID:AGENT_LATERAL_BOOTSTRAP_TOKEN"
)

OUTPUT_DIR="${NETWATCH_MINT_TOKENS_OUTPUT_DIR:-}"
WRITE_ENV="true"
if [[ -n "$OUTPUT_DIR" ]]; then
  WRITE_ENV="false"
fi

if [[ "$WRITE_ENV" == "true" && "${NETWATCH_MINT_TOKENS_BACKUP_ENV:-false}" == "true" ]]; then
  cp "$ENV_FILE" "${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
fi

for pair in "${AGENT_MAP[@]}"; do
  agent_key="${pair%%:*}"
  token_key="${pair##*:}"
  agent_id="$(read_env "$agent_key" "")"
  if [[ -z "$agent_id" ]]; then
    echo "Skipping ${token_key}: missing ${agent_key} in .env" >&2
    continue
  fi

  payload="$(python3 - "${TTL_SECONDS}" "${agent_id}" <<'PY'
import json
import sys

ttl = int(sys.argv[1])
agent_id = sys.argv[2]
print(json.dumps({
    'ttl_seconds': ttl,
    'max_uses': 1,
    'description': f'auto bootstrap for {agent_id}',
}))
PY
)"

  AGENTS_PATH="${API_PREFIX}/agents/${agent_id}/bootstrap-tokens"

  resp="$(curl -ksS -X POST "${API_BASE}${AGENTS_PATH}" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "content-type: application/json" \
    -d "$payload")"

  token="$(printf '%s' "$resp" | python3 - <<'PY'
import json
import sys

raw = sys.stdin.read()
try:
    data = json.loads(raw)
except Exception:
    print('')
else:
    print(data.get('bootstrap_token', '') or '')
PY
)"
  if [[ -z "$token" ]]; then
    echo "Failed to mint token for ${agent_id}. Response:" >&2
    printf "%s\n" "$resp" >&2
    exit 1
  fi

  if [[ -n "$OUTPUT_DIR" ]]; then
    write_token_file "$agent_id" "$token" "$OUTPUT_DIR"
    echo "Minted bootstrap token file for ${agent_id} -> ${OUTPUT_DIR}/${agent_id}.token"
  else
    upsert_env "$token_key" "$token"
    echo "Minted ${token_key} for ${agent_id}"
  fi
done

if [[ -n "$OUTPUT_DIR" ]]; then
  echo "Updated bootstrap token files in ${OUTPUT_DIR}."
else
  echo "Updated .env with AGENT_*_BOOTSTRAP_TOKEN values."
fi
echo "Next: docker compose up -d --force-recreate netwatch-agent-core netwatch-agent-sensor && docker compose --profile extra up -d --force-recreate netwatch-agent-lateral"
