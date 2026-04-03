#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[preflight] missing required command: $1" >&2
    exit 1
  }
}

need_cmd docker
need_cmd openssl
need_cmd curl
need_cmd jq

read_env_or_default() {
  local key="$1"
  local default_val="$2"
  local value
  value="$(awk -F= -v k="$key" '$1==k {print substr($0, index($0, "=")+1)}' "$ROOT_DIR/.env" | tail -n1)"
  if [[ -z "$value" ]]; then
    value="$default_val"
  fi
  printf '%s' "$value"
}

as_abs_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    printf '%s' "$path"
  else
    printf '%s/%s' "$ROOT_DIR" "$path"
  fi
}

is_ipv4() {
  local v="$1"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

ensure_readable_mode() {
  local abs_path="$1"
  local mode ones tens
  mode="$(stat -c '%a' "$abs_path" 2>/dev/null || true)"
  if [[ -z "$mode" ]]; then
    return 1
  fi
  ones=$(( mode % 10 ))
  tens=$(( (mode / 10) % 10 ))
  if (( (ones & 4) == 0 && (tens & 4) == 0 )); then
    chmod 644 "$abs_path"
  fi
}

require_file_mount_source() {
  local label="$1"
  local path="$2"
  local abs_path
  abs_path="$(as_abs_path "$path")"
  if [[ -d "$abs_path" ]]; then
    echo "[preflight] invalid ${label}: expected file, got directory at ${abs_path}" >&2
    exit 1
  fi
  if [[ ! -f "$abs_path" ]]; then
    echo "[preflight] missing ${label} file at ${abs_path}" >&2
    exit 1
  fi
}

require_world_or_group_readable() {
  local label="$1"
  local path="$2"
  local abs_path mode
  abs_path="$(as_abs_path "$path")"
  mode="$(stat -c '%a' "$abs_path" 2>/dev/null || true)"
  if [[ -z "$mode" ]]; then
    echo "[preflight] could not read permissions for ${label} at ${abs_path}" >&2
    exit 1
  fi
  local ones tens
  ones=$(( mode % 10 ))
  tens=$(( (mode / 10) % 10 ))
  if (( (ones & 4) == 0 && (tens & 4) == 0 )); then
    echo "[preflight] ${label} is not readable by group/others at ${abs_path} (mode ${mode}); run: chmod 644 ${abs_path}" >&2
    exit 1
  fi
}

cert_has_required_san() {
  local cert_path="$1"
  local server_name="$2"
  local abs_cert san_text
  abs_cert="$(as_abs_path "$cert_path")"
  san_text="$(openssl x509 -in "$abs_cert" -noout -ext subjectAltName 2>/dev/null || true)"
  if [[ -z "$san_text" ]]; then
    return 1
  fi
  if is_ipv4 "$server_name"; then
    if ! grep -Fq "IP Address:${server_name}" <<< "$san_text"; then
      return 1
    fi
  else
    if ! grep -Fq "DNS:${server_name}" <<< "$san_text"; then
      return 1
    fi
  fi
  return 0
}

generate_dev_tls_cert() {
  local cert_path="$1"
  local key_path="$2"
  local server_name="$3"
  local abs_cert abs_key cert_dir key_dir cfg san_line
  abs_cert="$(as_abs_path "$cert_path")"
  abs_key="$(as_abs_path "$key_path")"
  cert_dir="$(dirname "$abs_cert")"
  key_dir="$(dirname "$abs_key")"
  mkdir -p "$cert_dir" "$key_dir"
  if [[ -d "$abs_cert" || -d "$abs_key" ]]; then
    echo "[preflight] cannot regenerate TLS cert/key because target path is a directory" >&2
    exit 1
  fi
  if is_ipv4 "$server_name"; then
    san_line="IP.2 = ${server_name}"
  else
    san_line="DNS.2 = ${server_name}"
  fi
  cfg="$(mktemp)"
  cat > "$cfg" <<EOF
[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
x509_extensions    = v3_req
prompt             = no

[ req_distinguished_name ]
CN = localhost

[ v3_req ]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
${san_line}
EOF
  openssl req -x509 -nodes -newkey rsa:4096 -days 365 \
    -keyout "$abs_key" \
    -out "$abs_cert" \
    -config "$cfg" >/dev/null 2>&1
  rm -f "$cfg"
  chmod 644 "$abs_cert" "$abs_key"
  echo "[preflight] regenerated dev TLS cert/key with SAN entries"
}

docker compose version >/dev/null 2>&1 || {
  echo "[preflight] docker compose plugin is not available" >&2
  exit 1
}

docker info >/dev/null 2>&1 || {
  echo "[preflight] docker daemon is not reachable (is Docker running?)" >&2
  exit 1
}

"$ROOT_DIR/scripts/bootstrap_env.sh" "$ROOT_DIR/.env" "$ROOT_DIR/.env.example" >/dev/null

tls_cert_file="$(read_env_or_default NETWATCH_TLS_CERT_FILE ./secrets/tls/tls.crt)"
tls_key_file="$(read_env_or_default NETWATCH_TLS_KEY_FILE ./secrets/tls/tls.key)"
agent_ca_file="$(read_env_or_default NETWATCH_AGENT_SERVER_CA_FILE ./secrets/tls/ca.crt)"
agent_tls_server_name="$(read_env_or_default NETWATCH_AGENT_TLS_SERVER_NAME localhost)"
force_regen="$(read_env_or_default NETWATCH_FORCE_REGENERATE_CERTS false)"

abs_tls_cert_file="$(as_abs_path "$tls_cert_file")"
abs_tls_key_file="$(as_abs_path "$tls_key_file")"

if [[ "$force_regen" == "true" || "$force_regen" == "1" ]]; then
  generate_dev_tls_cert "$tls_cert_file" "$tls_key_file" "$agent_tls_server_name"
fi

if [[ ! -f "$abs_tls_cert_file" || ! -f "$abs_tls_key_file" ]]; then
  generate_dev_tls_cert "$tls_cert_file" "$tls_key_file" "$agent_tls_server_name"
fi

abs_agent_ca_file="$(as_abs_path "$agent_ca_file")"
if [[ ! -f "$abs_agent_ca_file" && -f "$abs_tls_cert_file" ]]; then
  mkdir -p "$(dirname -- "$abs_agent_ca_file")"
  cp "$abs_tls_cert_file" "$abs_agent_ca_file"
  chmod 644 "$abs_agent_ca_file"
  echo "[preflight] seeded agent CA file from TLS certificate: $agent_ca_file"
fi

require_file_mount_source NETWATCH_TLS_CERT_FILE "$tls_cert_file"
require_file_mount_source NETWATCH_TLS_KEY_FILE "$tls_key_file"
require_file_mount_source NETWATCH_AGENT_SERVER_CA_FILE "$agent_ca_file"

ensure_readable_mode "$abs_tls_cert_file"
ensure_readable_mode "$abs_tls_key_file"

if ! cert_has_required_san "$tls_cert_file" "$agent_tls_server_name"; then
  generate_dev_tls_cert "$tls_cert_file" "$tls_key_file" "$agent_tls_server_name"
fi

require_world_or_group_readable NETWATCH_TLS_CERT_FILE "$tls_cert_file"
require_world_or_group_readable NETWATCH_TLS_KEY_FILE "$tls_key_file"
require_world_or_group_readable NETWATCH_AGENT_SERVER_CA_FILE "$agent_ca_file"

docker compose -f docker-compose.yml -f compose.dev.yml config -q >/dev/null

echo "[preflight] ok: docker, compose, openssl, curl, jq and compose config are ready"
