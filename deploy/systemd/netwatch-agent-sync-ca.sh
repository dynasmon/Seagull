#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${NETWATCH_AGENT_ENV_FILE:-/etc/netwatch/agent.env}"

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

log() {
  echo "[ca-sync] $*"
}

main() {
  if [[ ! -f "${ENV_FILE}" ]]; then
    log "env file not found: ${ENV_FILE}; nothing to do"
    return 0
  fi

  local source_file target_file
  source_file="$(trim "$(read_env_value NETWATCH_TLS_CA_SOURCE_FILE "${ENV_FILE}")")"
  target_file="$(trim "$(read_env_value NETWATCH_TLS_CA_FILE "${ENV_FILE}")")"

  if [[ -z "${target_file}" ]]; then
    target_file="/etc/netwatch/pki/root_ca.crt"
  fi

  if [[ -z "${source_file}" ]]; then
    log "NETWATCH_TLS_CA_SOURCE_FILE is empty; keeping existing CA target ${target_file}"
    return 0
  fi

  if [[ ! -f "${source_file}" ]]; then
    log "CA source file not found: ${source_file}; keeping existing target ${target_file}"
    return 0
  fi

  install -d -m 0755 "$(dirname -- "${target_file}")"

  if [[ -f "${target_file}" ]] && cmp -s "${source_file}" "${target_file}"; then
    chown root:root "${target_file}" || true
    chmod 0644 "${target_file}" || true
    log "CA already synchronized: ${target_file}"
    return 0
  fi

  install -m 0644 "${source_file}" "${target_file}"
  chown root:root "${target_file}" || true
  chmod 0644 "${target_file}" || true
  log "synchronized CA from ${source_file} to ${target_file}"
}

main "$@"
