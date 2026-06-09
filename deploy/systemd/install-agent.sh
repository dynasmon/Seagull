#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env-util.sh
source "${SCRIPT_DIR}/lib/env-util.sh"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

SERVICE_NAME="seagull-agent"
SERVICE_FILE="${SCRIPT_DIR}/${SERVICE_NAME}.service"
ENV_EXAMPLE="${SCRIPT_DIR}/${SERVICE_NAME}.env.example"

INSTALL_BIN_PATH="/usr/local/bin/seagull-agent"
INSTALL_SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
INSTALL_ENV_PATH="/etc/seagull/agent.env"
INSTALL_CONFIG_DIR="/etc/seagull"
INSTALL_PKI_DIR="/etc/seagull/pki"
INSTALL_STATE_DIR="/var/lib/seagull"
INSTALL_LOG_DIR="/var/log/seagull"
INSTALL_LIBEXEC_DIR="/usr/local/lib/seagull"

BUILD_FROM_SOURCE="${BUILD_FROM_SOURCE:-1}"
SOURCE_BINARY="${SOURCE_BINARY:-}"
BUILD_OUTPUT="${REPO_ROOT}/agent/bin/seagull-agent"

DEFAULT_CA_FILE="/etc/seagull/pki/root_ca.crt"
DEFAULT_CA_SOURCE_FILE=""
DEFAULT_BOOTSTRAP_TOKEN_FILE="/var/lib/seagull/bootstrap.token"
LEGACY_BOOTSTRAP_TOKEN_FILE="/etc/seagull/bootstrap.token"

INSTALL_CLIENT_CERT_FILE="/etc/seagull/pki/agent.crt"
INSTALL_CLIENT_KEY_FILE="/etc/seagull/pki/agent.key"

# If CA file is missing, optionally seed it from local dev cert.
AUTO_INSTALL_DEV_CA="${AUTO_INSTALL_DEV_CA:-1}"
DEV_CA_SOURCE="${DEV_CA_SOURCE:-${REPO_ROOT}/secrets/pki/server-ca.crt}"
CA_SYNC_SCRIPT_SOURCE="${SCRIPT_DIR}/seagull-agent-sync-ca.sh"
CA_SYNC_SCRIPT_TARGET="${INSTALL_LIBEXEC_DIR}/seagull-agent-sync-ca.sh"
CA_SYNC_SERVICE_SOURCE="${SCRIPT_DIR}/seagull-agent-ca-sync.service"
CA_SYNC_SERVICE_TARGET="/etc/systemd/system/seagull-agent-ca-sync.service"
CA_SYNC_TIMER_SOURCE="${SCRIPT_DIR}/seagull-agent-ca-sync.timer"
CA_SYNC_TIMER_TARGET="/etc/systemd/system/seagull-agent-ca-sync.timer"

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
  if ! id -u seagull >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin seagull
    echo "[install] created user: seagull"
  fi
  if getent group adm >/dev/null 2>&1; then
    usermod -a -G adm seagull || true
  fi
}

create_directories() {
  install -d -m 0755 "${INSTALL_CONFIG_DIR}"
  install -d -m 0755 "${INSTALL_PKI_DIR}"
  install -d -m 0755 "${INSTALL_STATE_DIR}"
  install -d -m 0755 "${INSTALL_LOG_DIR}"
  install -d -m 0755 "${INSTALL_LIBEXEC_DIR}"

  chown seagull:seagull "${INSTALL_STATE_DIR}"
  chown seagull:seagull "${INSTALL_LOG_DIR}"
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

apply_runtime_env_overrides() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    return
  fi

  local override_agent_id override_bootstrap_token override_bootstrap_token_file
  override_agent_id="$(trim "${SEAGULL_AGENT_ID:-}")"
  override_bootstrap_token="$(trim "${SEAGULL_AGENT_BOOTSTRAP_TOKEN:-}")"
  override_bootstrap_token_file="$(trim "${SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE:-}")"

  if [[ -n "${override_agent_id}" ]]; then
    set_env_value SEAGULL_AGENT_ID "${override_agent_id}" "${INSTALL_ENV_PATH}"
    echo "[install] applied SEAGULL_AGENT_ID override"
  fi

  if [[ -n "${override_bootstrap_token}" ]]; then
    set_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN "${override_bootstrap_token}" "${INSTALL_ENV_PATH}"
    echo "[install] applied bootstrap token override"
  fi

  if [[ -n "${override_bootstrap_token_file}" ]]; then
    set_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${override_bootstrap_token_file}" "${INSTALL_ENV_PATH}"
    echo "[install] applied bootstrap token file override"
  fi
}

ensure_sources_default_includes_l7() {
  local file="$1"
  local legacy_default="authlog,proc,scan,ddos,syscollector,vuln"
  local phase1_default="authlog,proc,scan,ddos,l7,syscollector,vuln"
  local current

  if ! env_key_exists SEAGULL_SOURCES "${file}"; then
    set_env_value SEAGULL_SOURCES "${phase1_default}" "${file}"
    return
  fi

  current="$(trim "$(read_env_value SEAGULL_SOURCES "${file}")")"
  if [[ -z "${current}" || "${current}" == "${legacy_default}" ]]; then
    set_env_value SEAGULL_SOURCES "${phase1_default}" "${file}"
  fi
}

resolve_repo_env_file() {
  if [[ -f "${REPO_ROOT}/.env" ]]; then
    printf '%s' "${REPO_ROOT}/.env"
    return
  fi
  if [[ -f "${REPO_ROOT}/.env.example" ]]; then
    printf '%s' "${REPO_ROOT}/.env.example"
    return
  fi
  printf ''
}

resolve_repo_path() {
  local value="$1"
  if [[ -z "${value}" ]]; then
    return
  fi
  if [[ "${value}" = /* ]]; then
    printf '%s' "${value}"
    return
  fi
  printf '%s' "${REPO_ROOT}/${value#./}"
}

discover_repo_env_value() {
  local key="$1"
  local repo_env
  repo_env="$(resolve_repo_env_file)"
  if [[ -z "${repo_env}" || ! -f "${repo_env}" ]]; then
    return
  fi
  trim "$(read_env_value "${key}" "${repo_env}")"
}

discover_repo_bootstrap_token() {
  local agent_id repo_agent_id token token_file candidate
  agent_id="$(trim "$(read_env_value SEAGULL_AGENT_ID "${INSTALL_ENV_PATH}")")"
  if [[ -z "${agent_id}" ]]; then
    agent_id="$(trim "$(discover_repo_env_value AGENT_CORE_ID)")"
  fi
  if [[ -z "${agent_id}" ]]; then
    printf ''
    return
  fi

  local mappings=(
    "AGENT_CORE_ID:AGENT_CORE_BOOTSTRAP_TOKEN:AGENT_CORE_BOOTSTRAP_TOKEN_FILE"
    "AGENT_SENSOR_ID:AGENT_SENSOR_BOOTSTRAP_TOKEN:AGENT_SENSOR_BOOTSTRAP_TOKEN_FILE"
    "AGENT_LATERAL_ID:AGENT_LATERAL_BOOTSTRAP_TOKEN:AGENT_LATERAL_BOOTSTRAP_TOKEN_FILE"
    "AGENT_PROC_ID:AGENT_PROC_BOOTSTRAP_TOKEN:AGENT_PROC_BOOTSTRAP_TOKEN_FILE"
    "AGENT_SCAN_ID:AGENT_SCAN_BOOTSTRAP_TOKEN:AGENT_SCAN_BOOTSTRAP_TOKEN_FILE"
    "AGENT_DDOS_ID:AGENT_DDOS_BOOTSTRAP_TOKEN:AGENT_DDOS_BOOTSTRAP_TOKEN_FILE"
    "AGENT_VULN_ID:AGENT_VULN_BOOTSTRAP_TOKEN:AGENT_VULN_BOOTSTRAP_TOKEN_FILE"
  )

  local mapping agent_key token_key token_file_key
  for mapping in "${mappings[@]}"; do
    IFS=: read -r agent_key token_key token_file_key <<< "${mapping}"
    repo_agent_id="$(trim "$(discover_repo_env_value "${agent_key}")")"
    if [[ "${repo_agent_id}" != "${agent_id}" ]]; then
      continue
    fi

    token="$(trim "$(discover_repo_env_value "${token_key}")")"
    if [[ -n "${token}" ]]; then
      printf '%s' "${token}"
      return
    fi

    token_file="$(trim "$(discover_repo_env_value "${token_file_key}")")"
    if [[ -z "${token_file}" ]]; then
      continue
    fi
    candidate="$(resolve_repo_path "${token_file}")"
    if [[ -f "${candidate}" ]]; then
      trim "$(tr -d '\r\n' < "${candidate}")"
      return
    fi
  done

  printf ''
}

discover_ca_source_file() {
  local configured repo_value candidate
  configured="$(trim "$(read_env_value SEAGULL_TLS_CA_SOURCE_FILE "${INSTALL_ENV_PATH}")")"
  if [[ -n "${configured}" ]]; then
    printf '%s' "${configured}"
    return
  fi

  repo_value="$(discover_repo_env_value SEAGULL_AGENT_SERVER_CA_FILE)"
  if [[ -n "${repo_value}" ]]; then
    candidate="$(resolve_repo_path "${repo_value}")"
    if [[ -f "${candidate}" ]]; then
      if [[ "$(basename -- "${candidate}")" == "tls.crt" ]]; then
        local sibling_ca
        sibling_ca="$(dirname -- "${candidate}")/ca.crt"
        if [[ -f "${sibling_ca}" ]]; then
          printf '%s' "${sibling_ca}"
          return
        fi
      fi
      printf '%s' "${candidate}"
      return
    fi
  fi

  for candidate in     "${REPO_ROOT}/secrets/tls/ca.crt"     "${REPO_ROOT}/secrets/tls/tls.crt"     "${REPO_ROOT}/secrets/dev-tls/ca.crt"     "${REPO_ROOT}/secrets/dev-tls/tls.crt"; do
    if [[ -f "${candidate}" ]]; then
      printf '%s' "${candidate}"
      return
    fi
  done

  printf '%s' "${DEFAULT_CA_SOURCE_FILE}"
}

discover_api_host() {
  local api_url="$1"
  if [[ -z "${api_url}" ]]; then
    printf ''
    return
  fi
  SEAGULL_DISCOVER_API_URL="${api_url}" python3 - <<'EOF_PY'
from urllib.parse import urlparse
import os
url = os.environ.get('SEAGULL_DISCOVER_API_URL', '').strip()
if not url:
    raise SystemExit(0)
parsed = urlparse(url)
print(parsed.hostname or '')
EOF_PY
}

discover_tls_server_name() {
  local configured repo_value api_url api_host
  configured="$(trim "$(read_env_value SEAGULL_TLS_SERVER_NAME "${INSTALL_ENV_PATH}")")"
  if [[ -n "${configured}" ]]; then
    printf '%s' "${configured}"
    return
  fi

  repo_value="$(discover_repo_env_value SEAGULL_AGENT_TLS_SERVER_NAME)"
  if [[ -n "${repo_value}" ]]; then
    printf '%s' "${repo_value}"
    return
  fi

  api_url="$(trim "$(read_env_value SEAGULL_API_URL "${INSTALL_ENV_PATH}")")"
  api_host="$(discover_api_host "${api_url}")"
  if [[ "${api_host}" == "127.0.0.1" || "${api_host}" == "::1" || "${api_host}" == "localhost" ]]; then
    printf 'localhost'
    return
  fi

  if [[ -n "${api_host}" ]]; then
    printf '%s' "${api_host}"
    return
  fi

  printf ''
}

normalize_agent_runtime_defaults() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    return
  fi

  normalize_env_key SEAGULL_SOURCES "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_AUTHLOG_DEDUP_TTL "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_AUTHLOG_INCLUDE_ACCEPTED "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_DDOS_SUSTAIN_WINDOWS "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_DDOS_COOLDOWN "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_DDOS_MAX_BATCH "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_DDOS_BACKPRESSURE_HIGH_WATERMARK "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_DDOS_BACKPRESSURE_SAMPLE_EVERY "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_L7_PCAP_IFACE "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_L7_DEDUP_TTL "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_L7_MAX_BATCH "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_L7_MAX_PAYLOAD_BYTES "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_L7_INCLUDE_PAYLOAD "${INSTALL_ENV_PATH}"

  ensure_sources_default_includes_l7 "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_AUTHLOG_DEDUP_TTL "1s" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_AUTHLOG_INCLUDE_ACCEPTED "true" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_DDOS_SUSTAIN_WINDOWS "1" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_DDOS_COOLDOWN "10s" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_DDOS_MAX_BATCH "200" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_DDOS_BACKPRESSURE_HIGH_WATERMARK "160" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_DDOS_BACKPRESSURE_SAMPLE_EVERY "4" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_L7_PCAP_IFACE "any" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_L7_DEDUP_TTL "20s" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_L7_MAX_BATCH "400" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_L7_MAX_PAYLOAD_BYTES "512" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_L7_INCLUDE_PAYLOAD "false" "${INSTALL_ENV_PATH}"
}

normalize_bootstrap_token_settings() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    return
  fi

  normalize_env_key SEAGULL_AGENT_BOOTSTRAP_TOKEN "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_AGENT_IDENTITY_STATE_FILE "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_AGENT_CREDENTIAL_FILE "${INSTALL_ENV_PATH}"

  local identity_state_file credential_file token_inline token_file persisted_identity_present repo_bootstrap_token
  identity_state_file="$(trim "$(read_env_value SEAGULL_AGENT_IDENTITY_STATE_FILE "${INSTALL_ENV_PATH}")")"
  if [[ -z "${identity_state_file}" ]]; then
    identity_state_file="${INSTALL_STATE_DIR}/agent.identity.json"
    set_env_value SEAGULL_AGENT_IDENTITY_STATE_FILE "${identity_state_file}" "${INSTALL_ENV_PATH}"
  fi
  credential_file="$(trim "$(read_env_value SEAGULL_AGENT_CREDENTIAL_FILE "${INSTALL_ENV_PATH}")")"
  if [[ -z "${credential_file}" ]]; then
    credential_file="${INSTALL_STATE_DIR}/agent.credential"
    set_env_value SEAGULL_AGENT_CREDENTIAL_FILE "${credential_file}" "${INSTALL_ENV_PATH}"
  fi
  persisted_identity_present="0"
  if [[ -s "${credential_file}" || ( -n "${identity_state_file}" && -s "${identity_state_file}" ) ]]; then
    persisted_identity_present="1"
  fi

  token_inline="$(trim "$(read_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN "${INSTALL_ENV_PATH}")")"
  token_file="$(trim "$(read_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${INSTALL_ENV_PATH}")")"

  if [[ "${persisted_identity_present}" == "0" && -z "${token_inline}" && ( -z "${token_file}" || ! -f "${token_file}" ) ]]; then
    repo_bootstrap_token="$(discover_repo_bootstrap_token)"
    if [[ -n "${repo_bootstrap_token}" ]]; then
      token_inline="${repo_bootstrap_token}"
      set_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN "${token_inline}" "${INSTALL_ENV_PATH}"
      echo "[install] imported bootstrap token from repo env"
    fi
  fi

  if [[ "${token_file}" == "${LEGACY_BOOTSTRAP_TOKEN_FILE}" ]]; then
    token_file="${DEFAULT_BOOTSTRAP_TOKEN_FILE}"
    set_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${token_file}" "${INSTALL_ENV_PATH}"
    echo "[install] migrated SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE to ${token_file}"
  fi

  if [[ -n "${token_inline}" ]]; then
    if [[ -z "${token_file}" ]]; then
      token_file="${DEFAULT_BOOTSTRAP_TOKEN_FILE}"
      set_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${token_file}" "${INSTALL_ENV_PATH}"
      echo "[install] set SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE=${token_file}"
    fi
    install -d -m 0755 "$(dirname -- "${token_file}")"
    printf '%s' "${token_inline}" > "${token_file}"
    chown seagull:seagull "${token_file}" || true
    chmod 0600 "${token_file}" || true
    set_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN "" "${INSTALL_ENV_PATH}"
    echo "[install] moved SEAGULL_AGENT_BOOTSTRAP_TOKEN into ${token_file}"
  fi

  if [[ "${token_file}" == "${DEFAULT_BOOTSTRAP_TOKEN_FILE}" && -f "${LEGACY_BOOTSTRAP_TOKEN_FILE}" && ! -f "${DEFAULT_BOOTSTRAP_TOKEN_FILE}" ]]; then
    install -o seagull -g seagull -m 0600 "${LEGACY_BOOTSTRAP_TOKEN_FILE}" "${DEFAULT_BOOTSTRAP_TOKEN_FILE}"
    echo "[install] copied legacy bootstrap token to ${DEFAULT_BOOTSTRAP_TOKEN_FILE}"
  fi

  if [[ -n "${token_file}" && -f "${token_file}" ]]; then
    local token_clean
    token_clean="$(tr -d '\r\n' < "${token_file}")"
    token_clean="$(trim "${token_clean}")"
    printf '%s' "${token_clean}" > "${token_file}"
    chown seagull:seagull "${token_file}" || true
    chmod 0600 "${token_file}" || true
    echo "[install] ensured bootstrap token permissions: ${token_file}"
  elif [[ -n "${token_file}" && "${persisted_identity_present}" == "1" ]]; then
    # Keep restart-safe behavior by clearing stale file paths once the agent has persisted identity.
    set_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "" "${INSTALL_ENV_PATH}"
    token_file=""
    echo "[install] cleared stale SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE (persisted identity already present)"
  elif [[ -z "${token_file}" && -f "${DEFAULT_BOOTSTRAP_TOKEN_FILE}" ]]; then
    set_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${DEFAULT_BOOTSTRAP_TOKEN_FILE}" "${INSTALL_ENV_PATH}"
    token_file="${DEFAULT_BOOTSTRAP_TOKEN_FILE}"
    chown seagull:seagull "${token_file}" || true
    chmod 0600 "${token_file}" || true
    echo "[install] using bootstrap token file ${token_file}"
  elif [[ -z "${token_file}" && "${persisted_identity_present}" == "0" ]]; then
    echo "[install] warning: bootstrap token not configured in ${INSTALL_ENV_PATH}"
    echo "[install] set SEAGULL_AGENT_BOOTSTRAP_TOKEN or SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE before first enroll"
  fi
}

normalize_tls_ca_settings() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    return
  fi

  local ca_file ca_source_file tls_server_name
  normalize_env_key SEAGULL_TLS_CA_FILE "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_TLS_CA_SOURCE_FILE "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_TLS_SERVER_NAME "${INSTALL_ENV_PATH}"

  ca_file="$(trim "$(read_env_value SEAGULL_TLS_CA_FILE "${INSTALL_ENV_PATH}")")"
  if [[ -z "${ca_file}" ]]; then
    ca_file="${DEFAULT_CA_FILE}"
    set_env_value SEAGULL_TLS_CA_FILE "${ca_file}" "${INSTALL_ENV_PATH}"
  fi

  ca_source_file="$(discover_ca_source_file)"
  if [[ -n "${ca_source_file}" ]]; then
    set_env_value SEAGULL_TLS_CA_SOURCE_FILE "${ca_source_file}" "${INSTALL_ENV_PATH}"
  fi

  tls_server_name="$(discover_tls_server_name)"
  if [[ -n "${tls_server_name}" ]]; then
    set_env_value SEAGULL_TLS_SERVER_NAME "${tls_server_name}" "${INSTALL_ENV_PATH}"
  fi

  install -d -m 0755 "$(dirname -- "${ca_file}")"

  if [[ -n "${ca_source_file}" && -f "${ca_source_file}" ]]; then
    install -m 0644 "${ca_source_file}" "${ca_file}"
    echo "[install] synchronized CA from ${ca_source_file} to ${ca_file}"
  elif [[ ! -f "${ca_file}" && "${AUTO_INSTALL_DEV_CA}" == "1" && -f "${DEV_CA_SOURCE}" ]]; then
    install -m 0644 "${DEV_CA_SOURCE}" "${ca_file}"
    echo "[install] auto-installed CA from ${DEV_CA_SOURCE} to ${ca_file}"
  fi

  if [[ -f "${ca_file}" ]]; then
    chown root:root "${ca_file}" || true
    chmod 0644 "${ca_file}" || true
  fi
}

discover_pki_dir() {
  local repo_value
  repo_value="$(discover_repo_env_value SEAGULL_PKI_DIR)"
  if [[ -n "${repo_value}" ]]; then
    resolve_repo_path "${repo_value}"
    return
  fi
  printf '%s' "${REPO_ROOT}/secrets/pki"
}

mtls_is_enabled() {
  local value
  value="$(discover_repo_env_value SEAGULL_MTLS_ENABLED | tr '[:upper:]' '[:lower:]')"
  [[ -z "${value}" || "${value}" == "true" || "${value}" == "1" ]]
}

normalize_tls_client_cert_settings() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    return
  fi

  normalize_env_key SEAGULL_TLS_CERT_FILE "${INSTALL_ENV_PATH}"
  normalize_env_key SEAGULL_TLS_KEY_FILE "${INSTALL_ENV_PATH}"

  if ! mtls_is_enabled; then
    set_env_value SEAGULL_TLS_CERT_FILE "" "${INSTALL_ENV_PATH}"
    set_env_value SEAGULL_TLS_KEY_FILE "" "${INSTALL_ENV_PATH}"
    echo "[install] mTLS disabled (SEAGULL_MTLS_ENABLED=false); cleared agent client certificate"
    return
  fi

  local agent_id pki_dir cert_source key_source api_url
  agent_id="$(trim "$(read_env_value SEAGULL_AGENT_ID "${INSTALL_ENV_PATH}")")"
  if [[ -z "${agent_id}" ]]; then
    agent_id="$(trim "$(discover_repo_env_value AGENT_CORE_ID)")"
  fi
  if [[ -z "${agent_id}" ]]; then
    agent_id="agent-core-1"
  fi

  pki_dir="$(discover_pki_dir)"
  cert_source="${pki_dir}/agents/${agent_id}.crt"
  key_source="${pki_dir}/agents/${agent_id}.key"

  if [[ ! -f "${cert_source}" || ! -f "${key_source}" ]]; then
    echo "[install] warning: mTLS enabled but client certificate for ${agent_id} not found"
    echo "[install] expected ${cert_source} and ${key_source}"
    echo "[install] run ./seagull up to generate the agent PKI, then re-run this install"
    return
  fi

  install -d -m 0755 "${INSTALL_PKI_DIR}"
  install -o root -g root -m 0644 "${cert_source}" "${INSTALL_CLIENT_CERT_FILE}"
  install -o root -g seagull -m 0640 "${key_source}" "${INSTALL_CLIENT_KEY_FILE}"
  set_env_value SEAGULL_TLS_CERT_FILE "${INSTALL_CLIENT_CERT_FILE}" "${INSTALL_ENV_PATH}"
  set_env_value SEAGULL_TLS_KEY_FILE "${INSTALL_CLIENT_KEY_FILE}" "${INSTALL_ENV_PATH}"
  echo "[install] installed mTLS client certificate for ${agent_id}"

  local server_ca_source="${pki_dir}/server-ca.crt"
  if [[ -f "${server_ca_source}" ]]; then
    install -o root -g root -m 0644 "${server_ca_source}" "${DEFAULT_CA_FILE}"
    set_env_value SEAGULL_TLS_CA_FILE "${DEFAULT_CA_FILE}" "${INSTALL_ENV_PATH}"
    set_env_value SEAGULL_TLS_CA_SOURCE_FILE "${server_ca_source}" "${INSTALL_ENV_PATH}"
    echo "[install] installed internal mTLS server CA (agent now trusts the server CA)"
  else
    echo "[install] warning: server CA ${server_ca_source} not found; run ./seagull up to generate it"
  fi

  api_url="$(discover_repo_env_value SEAGULL_API_URL)"
  if [[ -n "${api_url}" ]]; then
    set_env_value SEAGULL_API_URL "${api_url}" "${INSTALL_ENV_PATH}"
    echo "[install] aligned SEAGULL_API_URL with repo value ${api_url}"
  fi
}

install_ca_sync_assets() {
  if [[ ! -f "${CA_SYNC_SCRIPT_SOURCE}" || ! -f "${CA_SYNC_SERVICE_SOURCE}" || ! -f "${CA_SYNC_TIMER_SOURCE}" ]]; then
    echo "[install] missing CA sync assets in deploy/systemd"
    exit 1
  fi

  install -m 0755 "${CA_SYNC_SCRIPT_SOURCE}" "${CA_SYNC_SCRIPT_TARGET}"
  install -m 0644 "${CA_SYNC_SERVICE_SOURCE}" "${CA_SYNC_SERVICE_TARGET}"
  install -m 0644 "${CA_SYNC_TIMER_SOURCE}" "${CA_SYNC_TIMER_TARGET}"
}

sanitize_service_dropins() {
  local dropin_dir
  dropin_dir="/etc/systemd/system/${SERVICE_NAME}.service.d"
  if [[ ! -d "${dropin_dir}" ]]; then
    return
  fi

  local conflicts
  conflicts="$(grep -lER 'SEAGULL_AGENT_BOOTSTRAP_TOKEN(_FILE)?=' "${dropin_dir}" --include '*.conf' 2>/dev/null || true)"
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
  local ca_file token_file token_inline credential_file credential_inline identity_state_file
  ca_file="$(trim "$(read_env_value SEAGULL_TLS_CA_FILE "${INSTALL_ENV_PATH}")")"
  token_file="$(trim "$(read_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${INSTALL_ENV_PATH}")")"
  token_inline="$(trim "$(read_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN "${INSTALL_ENV_PATH}")")"
  credential_file="$(trim "$(read_env_value SEAGULL_AGENT_CREDENTIAL_FILE "${INSTALL_ENV_PATH}")")"
  credential_inline="$(trim "$(read_env_value SEAGULL_AGENT_CREDENTIAL "${INSTALL_ENV_PATH}")")"
  identity_state_file="$(trim "$(read_env_value SEAGULL_AGENT_IDENTITY_STATE_FILE "${INSTALL_ENV_PATH}")")"

  local has_credential="0"
  if [[ -n "${credential_inline}" || ( -n "${credential_file}" && -s "${credential_file}" ) || ( -n "${identity_state_file}" && -s "${identity_state_file}" ) ]]; then
    has_credential="1"
  fi

  if [[ "${has_credential}" == "0" && -z "${token_inline}" && ( -z "${token_file}" || ! -f "${token_file}" ) ]]; then
    echo "[install] warning: no bootstrap token available (set SEAGULL_AGENT_BOOTSTRAP_TOKEN or SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE)"
  fi

  if [[ "${has_credential}" == "1" && -n "${token_file}" && ! -f "${token_file}" ]]; then
    echo "[install] info: SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE points to a missing file but credential or identity state is already present"
    echo "[install] info: this install will clear stale token-file paths automatically"
  fi

  if [[ -n "${token_file}" && -f "${token_file}" ]]; then
    if command -v runuser >/dev/null 2>&1; then
      if ! runuser -u seagull -- test -r "${token_file}"; then
        echo "[install] warning: token file is not readable by seagull: ${token_file}"
      fi
    fi
  fi

  if [[ -z "${ca_file}" || ! -f "${ca_file}" ]]; then
    echo "[install] warning: CA file missing: ${ca_file:-<empty>}"
    echo "[install] place your server CA bundle before starting the service"
  fi

  local cert_file key_file
  cert_file="$(trim "$(read_env_value SEAGULL_TLS_CERT_FILE "${INSTALL_ENV_PATH}")")"
  key_file="$(trim "$(read_env_value SEAGULL_TLS_KEY_FILE "${INSTALL_ENV_PATH}")")"
  if [[ -n "${cert_file}" || -n "${key_file}" ]]; then
    if [[ -z "${cert_file}" || -z "${key_file}" ]]; then
      echo "[install] warning: set SEAGULL_TLS_CERT_FILE and SEAGULL_TLS_KEY_FILE together for mTLS"
    elif [[ ! -f "${cert_file}" || ! -f "${key_file}" ]]; then
      echo "[install] warning: mTLS client certificate missing (${cert_file}, ${key_file})"
    fi
  fi
}

is_runtime_ready() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    return 1
  fi

  local ca_file token_file token_inline credential_file credential_inline identity_state_file
  ca_file="$(trim "$(read_env_value SEAGULL_TLS_CA_FILE "${INSTALL_ENV_PATH}")")"
  token_file="$(trim "$(read_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${INSTALL_ENV_PATH}")")"
  token_inline="$(trim "$(read_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN "${INSTALL_ENV_PATH}")")"
  credential_file="$(trim "$(read_env_value SEAGULL_AGENT_CREDENTIAL_FILE "${INSTALL_ENV_PATH}")")"
  credential_inline="$(trim "$(read_env_value SEAGULL_AGENT_CREDENTIAL "${INSTALL_ENV_PATH}")")"
  identity_state_file="$(trim "$(read_env_value SEAGULL_AGENT_IDENTITY_STATE_FILE "${INSTALL_ENV_PATH}")")"

  local has_credential="0"
  local has_bootstrap="0"

  if [[ -n "${credential_inline}" || ( -n "${credential_file}" && -s "${credential_file}" ) || ( -n "${identity_state_file}" && -s "${identity_state_file}" ) ]]; then
    has_credential="1"
  fi

  if [[ -n "${token_inline}" ]]; then
    has_bootstrap="1"
  elif [[ -n "${token_file}" && -f "${token_file}" ]]; then
    if command -v runuser >/dev/null 2>&1; then
      if runuser -u seagull -- test -r "${token_file}"; then
        has_bootstrap="1"
      fi
    elif [[ -r "${token_file}" ]]; then
      has_bootstrap="1"
    fi
  fi

  if [[ -z "${ca_file}" || ! -f "${ca_file}" ]]; then
    return 1
  fi

  local cert_file key_file
  cert_file="$(trim "$(read_env_value SEAGULL_TLS_CERT_FILE "${INSTALL_ENV_PATH}")")"
  key_file="$(trim "$(read_env_value SEAGULL_TLS_KEY_FILE "${INSTALL_ENV_PATH}")")"
  if [[ -n "${cert_file}" || -n "${key_file}" ]]; then
    if [[ -z "${cert_file}" || -z "${key_file}" || ! -f "${cert_file}" || ! -f "${key_file}" ]]; then
      return 1
    fi
  fi

  if [[ "${has_credential}" == "1" || "${has_bootstrap}" == "1" ]]; then
    return 0
  fi

  return 1
}

enable_service() {
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl enable seagull-agent-ca-sync.timer
  systemctl reset-failed "${SERVICE_NAME}" || true
  systemctl reset-failed seagull-agent-ca-sync.service || true
}

auto_start_if_ready() {
  if [[ "${AUTO_START_IF_READY}" != "1" ]]; then
    echo "[install] auto-start disabled (set AUTO_START_IF_READY=1 to enable)"
    return
  fi

  if ! is_runtime_ready; then
    echo "[install] auto-start skipped: runtime prerequisites not met"
    echo "[install] requirements: SEAGULL_TLS_CA_FILE exists and credential or bootstrap token is configured"
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
  apply_runtime_env_overrides
  normalize_agent_runtime_defaults
  normalize_bootstrap_token_settings
  normalize_tls_ca_settings
  normalize_tls_client_cert_settings
  sanitize_service_dropins
  install_ca_sync_assets
  install_service_file
  validate_runtime_readiness
  enable_service
  systemctl start seagull-agent-ca-sync.service || true
  systemctl start seagull-agent-ca-sync.timer || true
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
