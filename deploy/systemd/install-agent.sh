#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

SERVICE_NAME="netwatch-agent"
SERVICE_FILE="${SCRIPT_DIR}/${SERVICE_NAME}.service"
ENV_EXAMPLE="${SCRIPT_DIR}/${SERVICE_NAME}.env.example"

INSTALL_BIN_PATH="/usr/local/bin/netwatch-agent"
INSTALL_SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
INSTALL_ENV_PATH="/etc/netwatch/agent.env"
INSTALL_CONFIG_DIR="/etc/netwatch"
INSTALL_PKI_DIR="/etc/netwatch/pki"
INSTALL_STATE_DIR="/var/lib/netwatch"
INSTALL_LOG_DIR="/var/log/netwatch"

BUILD_FROM_SOURCE="${BUILD_FROM_SOURCE:-1}"
SOURCE_BINARY="${SOURCE_BINARY:-}"
BUILD_OUTPUT="${REPO_ROOT}/agent/bin/netwatch-agent"

DEFAULT_CA_FILE="/etc/netwatch/pki/root_ca.crt"
DEFAULT_BOOTSTRAP_TOKEN_FILE="/var/lib/netwatch/bootstrap.token"
LEGACY_BOOTSTRAP_TOKEN_FILE="/etc/netwatch/bootstrap.token"

# If CA file is missing, optionally seed it from local dev cert.
AUTO_INSTALL_DEV_CA="${AUTO_INSTALL_DEV_CA:-1}"
DEV_CA_SOURCE="${DEV_CA_SOURCE:-${REPO_ROOT}/secrets/dev-tls/tls.crt}"

# Remove stale drop-ins that override bootstrap token env vars.
PRESERVE_BOOTSTRAP_DROPINS="${PRESERVE_BOOTSTRAP_DROPINS:-0}"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[install] run as root"
    exit 1
  fi
}

ensure_prerequisites() {
  if [[ ! -f "${SERVICE_FILE}" || ! -f "${ENV_EXAMPLE}" ]]; then
    echo "[install] missing required deploy/systemd files"
    exit 1
  fi
}

ensure_service_user() {
  if ! id -u netwatch >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin netwatch
    echo "[install] created user: netwatch"
  fi
  if getent group adm >/dev/null 2>&1; then
    usermod -a -G adm netwatch || true
  fi
}

create_directories() {
  install -d -m 0755 "${INSTALL_CONFIG_DIR}"
  install -d -m 0755 "${INSTALL_PKI_DIR}"
  install -d -m 0755 "${INSTALL_STATE_DIR}"
  install -d -m 0755 "${INSTALL_LOG_DIR}"

  chown netwatch:netwatch "${INSTALL_STATE_DIR}"
  chown netwatch:netwatch "${INSTALL_LOG_DIR}"
}

build_binary_if_needed() {
  if [[ "${BUILD_FROM_SOURCE}" == "1" ]]; then
    if ! command -v go >/dev/null 2>&1; then
      echo "[install] go is not installed but BUILD_FROM_SOURCE=1"
      echo "[install] set BUILD_FROM_SOURCE=0 and provide SOURCE_BINARY=/path/to/netwatch-agent"
      exit 1
    fi

    echo "[install] building agent from source"
    mkdir -p "$(dirname -- "${BUILD_OUTPUT}")"
    (
      cd "${REPO_ROOT}/agent"
      CGO_ENABLED=1 go build -o "${BUILD_OUTPUT}" ./cmd/agent
    )
    SOURCE_BINARY="${BUILD_OUTPUT}"
    return
  fi

  if [[ -z "${SOURCE_BINARY}" ]]; then
    echo "[install] BUILD_FROM_SOURCE=0 requires SOURCE_BINARY=/path/to/netwatch-agent"
    exit 1
  fi
}

install_binary() {
  if [[ ! -f "${SOURCE_BINARY}" ]]; then
    echo "[install] binary not found: ${SOURCE_BINARY}"
    exit 1
  fi

  install -m 0755 "${SOURCE_BINARY}" "${INSTALL_BIN_PATH}"

  if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin=eip "${INSTALL_BIN_PATH}" || true
  fi
}

install_env_file() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    install -m 0600 "${ENV_EXAMPLE}" "${INSTALL_ENV_PATH}"
    echo "[install] created ${INSTALL_ENV_PATH}"
    echo "[install] edit this file before starting the service"
  else
    echo "[install] keeping existing ${INSTALL_ENV_PATH}"
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
  awk -F= -v k="${key}" '$1==k {print substr($0, index($0, "=")+1)}' "${file}" | tail -n1 | tr -d '\r'
}

set_env_value() {
  local key="$1"
  local value="$2"
  local file="$3"

  if grep -qE "^${key}=" "${file}"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${file}"
  else
    printf "\n%s=%s\n" "${key}" "${value}" >> "${file}"
  fi
}

remove_env_key() {
  local key="$1"
  local file="$2"
  sed -i -E "/^${key}=/d" "${file}"
}

normalize_bootstrap_token_settings() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    return
  fi

  local token_inline token_file
  token_inline="$(trim "$(read_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN "${INSTALL_ENV_PATH}")")"
  token_file="$(trim "$(read_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE "${INSTALL_ENV_PATH}")")"

  if [[ "${token_file}" == "${LEGACY_BOOTSTRAP_TOKEN_FILE}" ]]; then
    token_file="${DEFAULT_BOOTSTRAP_TOKEN_FILE}"
    set_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE "${token_file}" "${INSTALL_ENV_PATH}"
    echo "[install] migrated NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE to ${token_file}"
  fi

  if [[ -z "${token_file}" ]]; then
    token_file="${DEFAULT_BOOTSTRAP_TOKEN_FILE}"
    set_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE "${token_file}" "${INSTALL_ENV_PATH}"
    echo "[install] set default NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE=${token_file}"
  fi

  if [[ -n "${token_inline}" ]]; then
    install -d -m 0755 "$(dirname -- "${token_file}")"
    printf '%s' "${token_inline}" > "${token_file}"
    chown netwatch:netwatch "${token_file}" || true
    chmod 0600 "${token_file}" || true
    set_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN "" "${INSTALL_ENV_PATH}"
    echo "[install] moved NETWATCH_AGENT_BOOTSTRAP_TOKEN into ${token_file}"
  fi

  if [[ "${token_file}" == "${DEFAULT_BOOTSTRAP_TOKEN_FILE}" && -f "${LEGACY_BOOTSTRAP_TOKEN_FILE}" && ! -f "${DEFAULT_BOOTSTRAP_TOKEN_FILE}" ]]; then
    install -o netwatch -g netwatch -m 0600 "${LEGACY_BOOTSTRAP_TOKEN_FILE}" "${DEFAULT_BOOTSTRAP_TOKEN_FILE}"
    echo "[install] copied legacy bootstrap token to ${DEFAULT_BOOTSTRAP_TOKEN_FILE}"
  fi

  if [[ -f "${token_file}" ]]; then
    local token_clean
    token_clean="$(tr -d '\r\n' < "${token_file}")"
    token_clean="$(trim "${token_clean}")"
    printf '%s' "${token_clean}" > "${token_file}"
    chown netwatch:netwatch "${token_file}" || true
    chmod 0600 "${token_file}" || true
    echo "[install] ensured bootstrap token permissions: ${token_file}"
  fi
}

normalize_tls_ca_settings() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    return
  fi

  local ca_file
  ca_file="$(trim "$(read_env_value NETWATCH_TLS_CA_FILE "${INSTALL_ENV_PATH}")")"
  if [[ -z "${ca_file}" ]]; then
    ca_file="${DEFAULT_CA_FILE}"
    set_env_value NETWATCH_TLS_CA_FILE "${ca_file}" "${INSTALL_ENV_PATH}"
  fi

  install -d -m 0755 "$(dirname -- "${ca_file}")"

  if [[ ! -f "${ca_file}" && "${AUTO_INSTALL_DEV_CA}" == "1" && -f "${DEV_CA_SOURCE}" ]]; then
    install -m 0644 "${DEV_CA_SOURCE}" "${ca_file}"
    echo "[install] auto-installed CA from ${DEV_CA_SOURCE} to ${ca_file}"
  fi

  if [[ -f "${ca_file}" ]]; then
    chown root:root "${ca_file}" || true
    chmod 0644 "${ca_file}" || true
  fi
}

sanitize_service_dropins() {
  local dropin_dir
  dropin_dir="/etc/systemd/system/${SERVICE_NAME}.service.d"
  if [[ ! -d "${dropin_dir}" ]]; then
    return
  fi

  local conflicts
  conflicts="$(grep -lER 'NETWATCH_AGENT_BOOTSTRAP_TOKEN(_FILE)?=' "${dropin_dir}" --include '*.conf' 2>/dev/null || true)"
  if [[ -z "${conflicts}" ]]; then
    return
  fi

  if [[ "${PRESERVE_BOOTSTRAP_DROPINS}" == "1" ]]; then
    echo "[install] warning: bootstrap token overrides found in ${dropin_dir} (preserved by PRESERVE_BOOTSTRAP_DROPINS=1)"
    echo "${conflicts}" | sed 's/^/[install]   /'
    return
  fi

  while IFS= read -r file; do
    [[ -z "${file}" ]] && continue
    rm -f "${file}"
    echo "[install] removed conflicting bootstrap token drop-in: ${file}"
  done <<< "${conflicts}"
}

install_service_file() {
  install -m 0644 "${SERVICE_FILE}" "${INSTALL_SERVICE_PATH}"
}

validate_runtime_readiness() {
  local ca_file token_file token_inline
  ca_file="$(trim "$(read_env_value NETWATCH_TLS_CA_FILE "${INSTALL_ENV_PATH}")")"
  token_file="$(trim "$(read_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE "${INSTALL_ENV_PATH}")")"
  token_inline="$(trim "$(read_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN "${INSTALL_ENV_PATH}")")"

  if [[ -z "${token_inline}" && ( -z "${token_file}" || ! -f "${token_file}" ) ]]; then
    echo "[install] warning: no bootstrap token available (set NETWATCH_AGENT_BOOTSTRAP_TOKEN or NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE)"
  fi

  if [[ -n "${token_file}" && -f "${token_file}" ]]; then
    if command -v runuser >/dev/null 2>&1; then
      if ! runuser -u netwatch -- test -r "${token_file}"; then
        echo "[install] warning: token file is not readable by netwatch: ${token_file}"
      fi
    fi
  fi

  if [[ -z "${ca_file}" || ! -f "${ca_file}" ]]; then
    echo "[install] warning: CA file missing: ${ca_file:-<empty>}"
    echo "[install] place your server CA bundle before starting the service"
  fi
}

enable_service() {
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl reset-failed "${SERVICE_NAME}" || true
}

main() {
  require_root
  ensure_prerequisites
  ensure_service_user
  create_directories
  build_binary_if_needed
  install_binary
  install_env_file
  normalize_bootstrap_token_settings
  normalize_tls_ca_settings
  sanitize_service_dropins
  install_service_file
  validate_runtime_readiness
  enable_service

  echo
  echo "[install] done"
  echo "[install] service enabled but not started"
  echo "[install] next steps:"
  echo "  1. review ${INSTALL_ENV_PATH}"
  echo "  2. start with: systemctl start ${SERVICE_NAME}"
  echo "  3. inspect with: systemctl status ${SERVICE_NAME} --no-pager"
  echo "  4. logs with: journalctl -u ${SERVICE_NAME} -f"
}

main "$@"
