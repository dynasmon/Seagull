#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_ENV_PATH="/etc/seagull/agent.env"
DEFAULT_CA_DEST="/etc/seagull/pki/root_ca.crt"
PROJECT_ENV_PATH="${REPO_ROOT}/.env"
PROJECT_ENV_EXAMPLE_PATH="${REPO_ROOT}/.env.example"
SERVICE_NAME="seagull-agent"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[refresh-ca] run as root"
    exit 1
  fi
}

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "${s}"
}

read_env_value() {
  local key="$1"
  local file="$2"
  if [[ ! -f "${file}" ]]; then
    return 0
  fi
  awk -F= -v k="${key}" '$1==k {print substr($0, index($0, "=")+1)}' "${file}" | tail -n1 | tr -d '\r'
}

resolve_source() {
  local src
  src="$(trim "$(read_env_value SEAGULL_AGENT_SERVER_CA_FILE "${PROJECT_ENV_PATH}")")"
  if [[ -z "${src}" ]]; then
    src="$(trim "$(read_env_value SEAGULL_AGENT_SERVER_CA_FILE "${PROJECT_ENV_EXAMPLE_PATH}")")"
  fi
  if [[ -z "${src}" ]]; then
    src="./secrets/tls/tls.crt"
  fi
  if [[ "${src}" != /* ]]; then
    src="${REPO_ROOT}/${src#./}"
  fi
  printf '%s' "${src}"
}

resolve_dest() {
  local dst
  dst="$(trim "$(read_env_value SEAGULL_TLS_CA_FILE "${INSTALL_ENV_PATH}")")"
  if [[ -z "${dst}" ]]; then
    dst="${DEFAULT_CA_DEST}"
  fi
  printf '%s' "${dst}"
}

main() {
  require_root
  local src dst
  src="$(resolve_source)"
  dst="$(resolve_dest)"

  if [[ ! -f "${src}" ]]; then
    echo "[refresh-ca] source CA/cert file not found: ${src}"
    exit 1
  fi

  install -d -m 0755 "$(dirname -- "${dst}")"
  install -m 0644 "${src}" "${dst}"
  chown root:root "${dst}" || true
  chmod 0644 "${dst}" || true
  echo "[refresh-ca] copied ${src} -> ${dst}"

  if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl restart "${SERVICE_NAME}"
    echo "[refresh-ca] restarted ${SERVICE_NAME}"
  fi
}

main "$@"
