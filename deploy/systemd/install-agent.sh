#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
PACKAGING_DIR="${REPO_ROOT}/agent/packaging"
source "${PACKAGING_DIR}/lib/env-util.sh"

BUILD_FROM_SOURCE="${BUILD_FROM_SOURCE:-1}"
SOURCE_BINARY="${SOURCE_BINARY:-}"
BUILD_OUTPUT="${REPO_ROOT}/agent/bin/seagull-agent"
AUTO_START_IF_READY="${AUTO_START_IF_READY:-0}"

INSTALL_ENV_PATH="/etc/seagull/agent.env"
CA_SYNC_SCRIPT_SOURCE="${SCRIPT_DIR}/seagull-agent-sync-ca.sh"
CA_SYNC_SCRIPT_TARGET="/usr/local/lib/seagull/seagull-agent-sync-ca.sh"
CA_SYNC_SERVICE_SOURCE="${SCRIPT_DIR}/seagull-agent-ca-sync.service"
CA_SYNC_SERVICE_TARGET="/etc/systemd/system/seagull-agent-ca-sync.service"
CA_SYNC_TIMER_SOURCE="${SCRIPT_DIR}/seagull-agent-ca-sync.timer"
CA_SYNC_TIMER_TARGET="/etc/systemd/system/seagull-agent-ca-sync.timer"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[install] run as root"
    exit 1
  fi
}

build_binary_if_needed() {
  if [[ "${BUILD_FROM_SOURCE}" == "1" ]]; then
    if ! command -v go >/dev/null 2>&1; then
      echo "[install] go is not installed but BUILD_FROM_SOURCE=1"
      echo "[install] set BUILD_FROM_SOURCE=0 and provide SOURCE_BINARY=/path/to/seagull-agent"
      exit 1
    fi
    echo "[install] building agent from source"
    mkdir -p "$(dirname -- "${BUILD_OUTPUT}")"
    (
      cd "${REPO_ROOT}/agent"
      CGO_ENABLED=1 go build -buildvcs=false -o "${BUILD_OUTPUT}" ./cmd/agent
    )
    SOURCE_BINARY="${BUILD_OUTPUT}"
    return
  fi
  if [[ -z "${SOURCE_BINARY}" ]]; then
    echo "[install] BUILD_FROM_SOURCE=0 requires SOURCE_BINARY=/path/to/seagull-agent"
    exit 1
  fi
}

repo_env_value() {
  local key="$1"
  local repo_env=""
  if [[ -f "${REPO_ROOT}/.env" ]]; then
    repo_env="${REPO_ROOT}/.env"
  elif [[ -f "${REPO_ROOT}/.env.example" ]]; then
    repo_env="${REPO_ROOT}/.env.example"
  else
    printf ''
    return
  fi
  trim "$(read_env_value "${key}" "${repo_env}")"
}

resolve_agent_id() {
  local agent_id="${SEAGULL_AGENT_ID:-}"
  if [[ -z "${agent_id}" && -f "${INSTALL_ENV_PATH}" ]]; then
    agent_id="$(trim "$(read_env_value SEAGULL_AGENT_ID "${INSTALL_ENV_PATH}")")"
  fi
  if [[ -z "${agent_id}" ]]; then
    agent_id="$(repo_env_value AGENT_CORE_ID)"
  fi
  printf '%s' "${agent_id:-agent-core-1}"
}

resolve_bootstrap_token() {
  local agent_id="$1"
  if [[ -n "${SEAGULL_AGENT_BOOTSTRAP_TOKEN:-}" ]]; then
    printf '%s' "${SEAGULL_AGENT_BOOTSTRAP_TOKEN}"
    return
  fi
  local token_file="${REPO_ROOT}/secrets/bootstrap/${agent_id}.token"
  if [[ -f "${token_file}" ]]; then
    trim "$(tr -d '\r\n' < "${token_file}")"
    return
  fi
  local mapping agent_key token_key repo_agent_id
  for mapping in \
    "AGENT_CORE_ID:AGENT_CORE_BOOTSTRAP_TOKEN" \
    "AGENT_SENSOR_ID:AGENT_SENSOR_BOOTSTRAP_TOKEN" \
    "AGENT_LATERAL_ID:AGENT_LATERAL_BOOTSTRAP_TOKEN" \
    "AGENT_PROC_ID:AGENT_PROC_BOOTSTRAP_TOKEN" \
    "AGENT_SCAN_ID:AGENT_SCAN_BOOTSTRAP_TOKEN" \
    "AGENT_DDOS_ID:AGENT_DDOS_BOOTSTRAP_TOKEN" \
    "AGENT_VULN_ID:AGENT_VULN_BOOTSTRAP_TOKEN"; do
    IFS=: read -r agent_key token_key <<< "${mapping}"
    repo_agent_id="$(repo_env_value "${agent_key}")"
    if [[ "${repo_agent_id}" == "${agent_id}" ]]; then
      repo_env_value "${token_key}"
      return
    fi
  done
  printf ''
}

resolve_ca_file() {
  local mtls_enabled
  mtls_enabled="$(repo_env_value SEAGULL_MTLS_ENABLED | tr '[:upper:]' '[:lower:]')"
  if [[ -z "${mtls_enabled}" || "${mtls_enabled}" == "true" || "${mtls_enabled}" == "1" ]]; then
    local pki_dir
    pki_dir="$(repo_env_value SEAGULL_PKI_DIR)"
    pki_dir="${pki_dir:-./secrets/pki}"
    if [[ "${pki_dir}" != /* ]]; then
      pki_dir="${REPO_ROOT}/${pki_dir#./}"
    fi
    if [[ -f "${pki_dir}/server-ca.crt" ]]; then
      printf '%s' "${pki_dir}/server-ca.crt"
      return
    fi
  fi
  local candidate
  for candidate in \
    "$(repo_env_value SEAGULL_AGENT_SERVER_CA_FILE)" \
    "./secrets/tls/ca.crt" \
    "./secrets/tls/tls.crt" \
    "./secrets/dev-tls/ca.crt" \
    "./secrets/dev-tls/tls.crt"; do
    if [[ -z "${candidate}" ]]; then
      continue
    fi
    if [[ "${candidate}" != /* ]]; then
      candidate="${REPO_ROOT}/${candidate#./}"
    fi
    if [[ -f "${candidate}" ]]; then
      printf '%s' "${candidate}"
      return
    fi
  done
  printf ''
}

install_ca_sync_assets() {
  if [[ ! -f "${CA_SYNC_SCRIPT_SOURCE}" || ! -f "${CA_SYNC_SERVICE_SOURCE}" || ! -f "${CA_SYNC_TIMER_SOURCE}" ]]; then
    echo "[install] missing CA sync assets in deploy/systemd"
    exit 1
  fi
  install -d -m 0755 "$(dirname -- "${CA_SYNC_SCRIPT_TARGET}")"
  install -m 0755 "${CA_SYNC_SCRIPT_SOURCE}" "${CA_SYNC_SCRIPT_TARGET}"
  install -m 0644 "${CA_SYNC_SERVICE_SOURCE}" "${CA_SYNC_SERVICE_TARGET}"
  install -m 0644 "${CA_SYNC_TIMER_SOURCE}" "${CA_SYNC_TIMER_TARGET}"
  systemctl daemon-reload
  systemctl enable seagull-agent-ca-sync.timer || true
  systemctl reset-failed seagull-agent-ca-sync.service || true
  systemctl start seagull-agent-ca-sync.service || true
  systemctl start seagull-agent-ca-sync.timer || true
}

record_ca_source() {
  local ca_file="$1"
  if [[ -z "${ca_file}" || ! -f "${INSTALL_ENV_PATH}" ]]; then
    return
  fi
  set_env_value SEAGULL_TLS_CA_SOURCE_FILE "${ca_file}" "${INSTALL_ENV_PATH}"
}

main() {
  require_root
  build_binary_if_needed

  local agent_id api_url enroll_url ca_file token server_name
  agent_id="$(resolve_agent_id)"
  api_url="${SEAGULL_API_URL:-$(repo_env_value SEAGULL_API_URL)}"
  api_url="${api_url:-https://localhost:8444/agent}"
  enroll_url="${SEAGULL_ENROLL_URL:-$(repo_env_value SEAGULL_ENROLL_URL)}"
  if [[ -z "${enroll_url}" ]]; then
    local enroll_port
    enroll_port="$(repo_env_value SEAGULL_AGENT_ENROLL_PORT)"
    enroll_url="https://localhost:${enroll_port:-8445}"
  fi
  ca_file="$(resolve_ca_file)"
  token="$(resolve_bootstrap_token "${agent_id}")"
  server_name="${SEAGULL_TLS_SERVER_NAME:-$(repo_env_value SEAGULL_AGENT_TLS_SERVER_NAME)}"

  local args=(
    --binary "${SOURCE_BINARY}"
    --agent-id "${agent_id}"
    --api-url "${api_url}"
    --enroll-url "${enroll_url}"
  )
  if [[ -n "${ca_file}" ]]; then
    args+=(--ca-file "${ca_file}")
  fi
  if [[ -n "${token}" ]]; then
    args+=(--enroll-token "${token}")
  fi
  if [[ -n "${server_name}" ]]; then
    args+=(--tls-server-name "${server_name}")
  fi
  args+=(--profile "${SEAGULL_AGENT_PROFILE:-managed}")
  if [[ "${AUTO_START_IF_READY}" != "1" ]]; then
    args+=(--no-start)
  fi

  bash "${PACKAGING_DIR}/install.sh" "${args[@]}"
  record_ca_source "${ca_file}"
  install_ca_sync_assets
}

main "$@"
