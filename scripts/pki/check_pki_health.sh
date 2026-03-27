#!/usr/bin/env sh
set -eu

PKI_DIR="${NETWATCH_PKI_DIR:-/var/lib/netwatch/pki}"
ROOT_CA="${PKI_DIR}/root_ca.crt"
EDGE_CERT="${PKI_DIR}/edge/tls.crt"
EDGE_KEY="${PKI_DIR}/edge/tls.key"
STATUS_FILE="${NETWATCH_STEP_CA_STATUS_FILE:-${PKI_DIR}/status/issuer.json}"
AGENT_IDS_RAW="${NETWATCH_STEP_CA_AGENT_IDS:-agent-core-1,agent-sensor-1,agent-lateral-1,agent-proc-1,agent-scan-1,agent-ddos-1,agent-vuln-1}"
MIN_VALID_SECONDS="${NETWATCH_PKI_MIN_VALID_SECONDS:-300}"

require_file() {
  path="$1"
  if [ ! -s "${path}" ]; then
    echo "[check-pki-health] missing file: ${path}" >&2
    exit 1
  fi
}

pubkey_digest_from_cert() {
  cert_path="$1"
  openssl x509 -in "${cert_path}" -pubkey -noout 2>/dev/null     | openssl pkey -pubin -outform DER 2>/dev/null     | openssl dgst -sha256 2>/dev/null     | awk '{print $2}'
}

pubkey_digest_from_key() {
  key_path="$1"
  openssl pkey -in "${key_path}" -pubout -outform DER 2>/dev/null     | openssl dgst -sha256 2>/dev/null     | awk '{print $2}'
}

check_cert_pair() {
  cert_path="$1"
  key_path="$2"
  purpose="$3"

  require_file "${cert_path}"
  require_file "${key_path}"

  if ! openssl x509 -in "${cert_path}" -checkend "${MIN_VALID_SECONDS}" -noout >/dev/null 2>&1; then
    echo "[check-pki-health] certificate expired or expiring too soon: ${cert_path}" >&2
    exit 1
  fi

  cert_digest="$(pubkey_digest_from_cert "${cert_path}")"
  key_digest="$(pubkey_digest_from_key "${key_path}")"
  if [ -z "${cert_digest}" ] || [ -z "${key_digest}" ] || [ "${cert_digest}" != "${key_digest}" ]; then
    echo "[check-pki-health] certificate/key mismatch: ${cert_path} ${key_path}" >&2
    exit 1
  fi

  if ! openssl verify -purpose "${purpose}" -CAfile "${ROOT_CA}" "${cert_path}" >/dev/null 2>&1; then
    echo "[check-pki-health] failed certificate verification: ${cert_path}" >&2
    exit 1
  fi
}

require_file "${ROOT_CA}"
require_file "${STATUS_FILE}"
check_cert_pair "${EDGE_CERT}" "${EDGE_KEY}" sslserver

old_ifs="$IFS"
IFS=','
for raw_agent_id in ${AGENT_IDS_RAW}; do
  agent_id="$(echo "${raw_agent_id}" | tr -d '[:space:]')"
  [ -n "${agent_id}" ] || continue
  check_cert_pair "${PKI_DIR}/agents/${agent_id}/tls.crt" "${PKI_DIR}/agents/${agent_id}/tls.key" sslclient
done
IFS="$old_ifs"

echo "[check-pki-health] PKI material is present and valid" >&2
