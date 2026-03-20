#!/usr/bin/env sh
set -eu

CA_URL="${NETWATCH_STEP_CA_URL:-https://netwatch-step-ca:9000}"
PROVISIONER="${NETWATCH_STEP_CA_PROVISIONER:-netwatch-provisioner}"
PASSWORD_FILE="${NETWATCH_STEP_CA_PROVISIONER_PASSWORD_FILE:-/run/secrets/step_ca_provisioner_password}"
PKI_DIR="${NETWATCH_PKI_DIR:-/var/lib/netwatch/pki}"
ROOT_CA_SOURCE="${NETWATCH_STEP_CA_ROOT_SOURCE:-/home/step/certs/root_ca.crt}"
EDGE_CN="${NETWATCH_EDGE_CERT_CN:-localhost}"
EDGE_SANS="${NETWATCH_EDGE_CERT_SANS:-localhost,netwatch-edge,127.0.0.1}"
RENEW_EVERY_SECONDS="${NETWATCH_STEP_CA_RENEW_EVERY_SECONDS:-21600}"
AGENT_IDS_RAW="${NETWATCH_STEP_CA_AGENT_IDS:-agent-proc-1,agent-scan-1,agent-ddos-1,agent-vuln-1}"

ROOT_CA_DST="${PKI_DIR}/root_ca.crt"
EDGE_DIR="${PKI_DIR}/edge"
AGENT_DIR="${PKI_DIR}/agents"

mkdir -p "${EDGE_DIR}" "${AGENT_DIR}"

if [ ! -f "${ROOT_CA_SOURCE}" ]; then
  echo "[step-ca-issuer] root CA not found at ${ROOT_CA_SOURCE}" >&2
  exit 1
fi
cp "${ROOT_CA_SOURCE}" "${ROOT_CA_DST}"
chmod 0644 "${ROOT_CA_DST}"

issue_with_token() {
  subject="$1"
  cert_path="$2"
  key_path="$3"
  sans_csv="${4:-}"

  token="$(step ca token "${subject}" --ca-url "${CA_URL}" --root "${ROOT_CA_DST}" --provisioner "${PROVISIONER}" --password-file "${PASSWORD_FILE}")"

  set -- step ca certificate "${subject}" "${cert_path}" "${key_path}" --force --token "${token}" --ca-url "${CA_URL}" --root "${ROOT_CA_DST}"
  old_ifs="$IFS"
  IFS=','
  for san in ${sans_csv}; do
    san="$(echo "${san}" | tr -d '[:space:]')"
    [ -n "${san}" ] || continue
    set -- "$@" --san "${san}"
  done
  IFS="$old_ifs"
  "$@"

  chmod 0644 "${cert_path}"
  chmod 0600 "${key_path}"
}

renew_or_issue() {
  subject="$1"
  cert_path="$2"
  key_path="$3"
  sans_csv="${4:-}"

  if [ -f "${cert_path}" ] && [ -f "${key_path}" ]; then
    if step ca renew --force "${cert_path}" "${key_path}" --ca-url "${CA_URL}" --root "${ROOT_CA_DST}" --provisioner "${PROVISIONER}" --password-file "${PASSWORD_FILE}" >/dev/null 2>&1; then
      chmod 0644 "${cert_path}"
      chmod 0600 "${key_path}"
      return 0
    fi
  fi

  issue_with_token "${subject}" "${cert_path}" "${key_path}" "${sans_csv}"
}

issue_all() {
  cp "${ROOT_CA_SOURCE}" "${ROOT_CA_DST}"
  chmod 0644 "${ROOT_CA_DST}"

  renew_or_issue "${EDGE_CN}" "${EDGE_DIR}/tls.crt" "${EDGE_DIR}/tls.key" "${EDGE_SANS}"

  old_ifs="$IFS"
  IFS=','
  for raw_id in ${AGENT_IDS_RAW}; do
    agent_id="$(echo "${raw_id}" | tr -d '[:space:]')"
    [ -n "${agent_id}" ] || continue
    target_dir="${AGENT_DIR}/${agent_id}"
    mkdir -p "${target_dir}"
    renew_or_issue "${agent_id}" "${target_dir}/tls.crt" "${target_dir}/tls.key" "${agent_id}"
  done
  IFS="$old_ifs"
}

issue_all

while true; do
  sleep "${RENEW_EVERY_SECONDS}"
  issue_all
done
