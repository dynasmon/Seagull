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
# Auto-start only when runtime prerequisites are satisfied.
AUTO_START_IF_READY="${AUTO_START_IF_READY:-0}"

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

env_key_exists() {
  local key="$1"
  local file="$2"
  grep -qE "^${key}=" "${file}"
}

set_env_value() {
  local key="$1"
  local value="$2"
  local file="$3"

  remove_env_key "${key}" "${file}"
  printf "%s=%s\n" "${key}" "${value}" >> "${file}"
}

remove_env_key() {
  local key="$1"
  local file="$2"
  sed -i -E "/^${key}=/d" "${file}"
}

normalize_env_key() {
  local key="$1"
  local file="$2"
  if ! env_key_exists "${key}" "${file}"; then
    return
  fi
  local value
  value="$(trim "$(read_env_value "${key}" "${file}")")"
  set_env_value "${key}" "${value}" "${file}"
}

ensure_env_value() {
  local key="$1"
  local value="$2"
  local file="$3"
  if ! env_key_exists "${key}" "${file}"; then
    set_env_value "${key}" "${value}" "${file}"
  fi
}

normalize_agent_runtime_defaults() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    return
  fi

  normalize_env_key NETWATCH_AUTHLOG_DEDUP_TTL "${INSTALL_ENV_PATH}"
  normalize_env_key NETWATCH_AUTHLOG_INCLUDE_ACCEPTED "${INSTALL_ENV_PATH}"
  normalize_env_key NETWATCH_DDOS_SUSTAIN_WINDOWS "${INSTALL_ENV_PATH}"
  normalize_env_key NETWATCH_DDOS_COOLDOWN "${INSTALL_ENV_PATH}"
  normalize_env_key NETWATCH_DDOS_MAX_BATCH "${INSTALL_ENV_PATH}"
  normalize_env_key NETWATCH_DDOS_BACKPRESSURE_HIGH_WATERMARK "${INSTALL_ENV_PATH}"
  normalize_env_key NETWATCH_DDOS_BACKPRESSURE_SAMPLE_EVERY "${INSTALL_ENV_PATH}"

  ensure_env_value NETWATCH_AUTHLOG_DEDUP_TTL "1s" "${INSTALL_ENV_PATH}"
  ensure_env_value NETWATCH_AUTHLOG_INCLUDE_ACCEPTED "true" "${INSTALL_ENV_PATH}"
  ensure_env_value NETWATCH_DDOS_SUSTAIN_WINDOWS "1" "${INSTALL_ENV_PATH}"
  ensure_env_value NETWATCH_DDOS_COOLDOWN "10s" "${INSTALL_ENV_PATH}"
  ensure_env_value NETWATCH_DDOS_MAX_BATCH "200" "${INSTALL_ENV_PATH}"
  ensure_env_value NETWATCH_DDOS_BACKPRESSURE_HIGH_WATERMARK "160" "${INSTALL_ENV_PATH}"
  ensure_env_value NETWATCH_DDOS_BACKPRESSURE_SAMPLE_EVERY "4" "${INSTALL_ENV_PATH}"
}

normalize_bootstrap_token_settings() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    return
  fi

  normalize_env_key NETWATCH_AGENT_BOOTSTRAP_TOKEN "${INSTALL_ENV_PATH}"
  normalize_env_key NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE "${INSTALL_ENV_PATH}"
  normalize_env_key NETWATCH_AGENT_CREDENTIAL_FILE "${INSTALL_ENV_PATH}"

  local credential_file token_inline token_file credential_present
  credential_file="$(trim "$(read_env_value NETWATCH_AGENT_CREDENTIAL_FILE "${INSTALL_ENV_PATH}")")"
  if [[ -z "${credential_file}" ]]; then
    credential_file="${INSTALL_STATE_DIR}/agent.credential"
    set_env_value NETWATCH_AGENT_CREDENTIAL_FILE "${credential_file}" "${INSTALL_ENV_PATH}"
  fi
  credential_present="0"
  if [[ -s "${credential_file}" ]]; then
    credential_present="1"
  fi

  token_inline="$(trim "$(read_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN "${INSTALL_ENV_PATH}")")"
  token_file="$(trim "$(read_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE "${INSTALL_ENV_PATH}")")"

  if [[ "${token_file}" == "${LEGACY_BOOTSTRAP_TOKEN_FILE}" ]]; then
    token_file="${DEFAULT_BOOTSTRAP_TOKEN_FILE}"
    set_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE "${token_file}" "${INSTALL_ENV_PATH}"
    echo "[install] migrated NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE to ${token_file}"
  fi

  if [[ -n "${token_inline}" ]]; then
    if [[ -z "${token_file}" ]]; then
      token_file="${DEFAULT_BOOTSTRAP_TOKEN_FILE}"
      set_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE "${token_file}" "${INSTALL_ENV_PATH}"
      echo "[install] set NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE=${token_file}"
    fi
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

  if [[ -n "${token_file}" && -f "${token_file}" ]]; then
    local token_clean
    token_clean="$(tr -d '\r\n' < "${token_file}")"
    token_clean="$(trim "${token_clean}")"
    printf '%s' "${token_clean}" > "${token_file}"
    chown netwatch:netwatch "${token_file}" || true
    chmod 0600 "${token_file}" || true
    echo "[install] ensured bootstrap token permissions: ${token_file}"
  elif [[ -n "${token_file}" && "${credential_present}" == "1" ]]; then
    # After a successful enroll the agent deletes bootstrap token file.
    # Keep restart-safe behavior by clearing stale file path when credential already exists.
    set_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE "" "${INSTALL_ENV_PATH}"
    token_file=""
    echo "[install] cleared stale NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE (credential already present)"
  elif [[ -z "${token_file}" && -f "${DEFAULT_BOOTSTRAP_TOKEN_FILE}" ]]; then
    set_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE "${DEFAULT_BOOTSTRAP_TOKEN_FILE}" "${INSTALL_ENV_PATH}"
    token_file="${DEFAULT_BOOTSTRAP_TOKEN_FILE}"
    chown netwatch:netwatch "${token_file}" || true
    chmod 0600 "${token_file}" || true
    echo "[install] using bootstrap token file ${token_file}"
  elif [[ -z "${token_file}" && "${credential_present}" == "0" ]]; then
    echo "[install] warning: bootstrap token not configured in ${INSTALL_ENV_PATH}"
    echo "[install] set NETWATCH_AGENT_BOOTSTRAP_TOKEN or NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE before first enroll"
  fi
}

normalize_tls_ca_settings() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    return
  fi

  local ca_file
  normalize_env_key NETWATCH_TLS_CA_FILE "${INSTALL_ENV_PATH}"
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
  local ca_file token_file token_inline credential_file credential_inline
  ca_file="$(trim "$(read_env_value NETWATCH_TLS_CA_FILE "${INSTALL_ENV_PATH}")")"
  token_file="$(trim "$(read_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE "${INSTALL_ENV_PATH}")")"
  token_inline="$(trim "$(read_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN "${INSTALL_ENV_PATH}")")"
  credential_file="$(trim "$(read_env_value NETWATCH_AGENT_CREDENTIAL_FILE "${INSTALL_ENV_PATH}")")"
  credential_inline="$(trim "$(read_env_value NETWATCH_AGENT_CREDENTIAL "${INSTALL_ENV_PATH}")")"

  local has_credential="0"
  if [[ -n "${credential_inline}" || ( -n "${credential_file}" && -s "${credential_file}" ) ]]; then
    has_credential="1"
  fi

  if [[ "${has_credential}" == "0" && -z "${token_inline}" && ( -z "${token_file}" || ! -f "${token_file}" ) ]]; then
    echo "[install] warning: no bootstrap token available (set NETWATCH_AGENT_BOOTSTRAP_TOKEN or NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE)"
  fi

  if [[ "${has_credential}" == "1" && -n "${token_file}" && ! -f "${token_file}" ]]; then
    echo "[install] info: NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE points to a missing file but credential is already present"
    echo "[install] info: this install will clear stale token-file paths automatically"
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

is_runtime_ready() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    return 1
  fi

  local ca_file token_file token_inline credential_file credential_inline
  ca_file="$(trim "$(read_env_value NETWATCH_TLS_CA_FILE "${INSTALL_ENV_PATH}")")"
  token_file="$(trim "$(read_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE "${INSTALL_ENV_PATH}")")"
  token_inline="$(trim "$(read_env_value NETWATCH_AGENT_BOOTSTRAP_TOKEN "${INSTALL_ENV_PATH}")")"
  credential_file="$(trim "$(read_env_value NETWATCH_AGENT_CREDENTIAL_FILE "${INSTALL_ENV_PATH}")")"
  credential_inline="$(trim "$(read_env_value NETWATCH_AGENT_CREDENTIAL "${INSTALL_ENV_PATH}")")"

  local has_credential="0"
  local has_bootstrap="0"

  if [[ -n "${credential_inline}" || ( -n "${credential_file}" && -s "${credential_file}" ) ]]; then
    has_credential="1"
  fi

  if [[ -n "${token_inline}" ]]; then
    has_bootstrap="1"
  elif [[ -n "${token_file}" && -f "${token_file}" ]]; then
    if command -v runuser >/dev/null 2>&1; then
      if runuser -u netwatch -- test -r "${token_file}"; then
        has_bootstrap="1"
      fi
    elif [[ -r "${token_file}" ]]; then
      has_bootstrap="1"
    fi
  fi

  if [[ -z "${ca_file}" || ! -f "${ca_file}" ]]; then
    return 1
  fi

  if [[ "${has_credential}" == "1" || "${has_bootstrap}" == "1" ]]; then
    return 0
  fi

  return 1
}

enable_service() {
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl reset-failed "${SERVICE_NAME}" || true
}

auto_start_if_ready() {
  if [[ "${AUTO_START_IF_READY}" != "1" ]]; then
    echo "[install] auto-start disabled (set AUTO_START_IF_READY=1 to enable)"
    return
  fi

  if ! is_runtime_ready; then
    echo "[install] auto-start skipped: runtime prerequisites not met"
    echo "[install] requirements: NETWATCH_TLS_CA_FILE exists and credential or bootstrap token is configured"
    return
  fi

  if systemctl restart "${SERVICE_NAME}"; then
    echo "[install] service started"
  else
    echo "[install] warning: service failed to start"
    echo "[install] inspect with: systemctl status ${SERVICE_NAME} --no-pager"
    echo "[install] logs with: journalctl -u ${SERVICE_NAME} -n 80 --no-pager"
  fi
}

main() {
  require_root
  ensure_prerequisites
  ensure_service_user
  create_directories
  build_binary_if_needed
  install_binary
  install_env_file
  normalize_agent_runtime_defaults
  normalize_bootstrap_token_settings
  normalize_tls_ca_settings
  sanitize_service_dropins
  install_service_file
  validate_runtime_readiness
  enable_service
  auto_start_if_ready

  echo
  echo "[install] done"
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "[install] service enabled and running"
  else
    echo "[install] service enabled but not started"
  fi
  echo "[install] next steps:"
  echo "  1. review ${INSTALL_ENV_PATH}"
  echo "  2. start with: systemctl start ${SERVICE_NAME}"
  echo "  3. inspect with: systemctl status ${SERVICE_NAME} --no-pager"
  echo "  4. logs with: journalctl -u ${SERVICE_NAME} -f"
}

main "$@"
