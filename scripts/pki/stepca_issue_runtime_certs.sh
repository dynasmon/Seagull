#!/usr/bin/env sh
set -eu

CA_URL="${NETWATCH_STEP_CA_URL:-https://netwatch-step-ca:9000}"
PROVISIONER="${NETWATCH_STEP_CA_PROVISIONER:-netwatch-provisioner}"
PASSWORD_FILE="${NETWATCH_STEP_CA_PROVISIONER_PASSWORD_FILE:-/etc/netwatch/step-ca/provisioner-password.txt}"
PKI_DIR="${NETWATCH_PKI_DIR:-/var/lib/netwatch/pki}"
ROOT_CA_SOURCE="${NETWATCH_STEP_CA_ROOT_SOURCE:-/var/lib/step/certs/root_ca.crt}"
EDGE_CN="${NETWATCH_EDGE_CERT_CN:-localhost}"
EDGE_SANS="${NETWATCH_EDGE_CERT_SANS:-localhost,netwatch-edge,127.0.0.1}"
RENEW_EVERY_SECONDS="${NETWATCH_STEP_CA_RENEW_EVERY_SECONDS:-21600}"
RENEW_BEFORE_SECONDS="${NETWATCH_STEP_CA_RENEW_BEFORE_SECONDS:-43200}"
STATUS_DIR="${NETWATCH_STEP_CA_STATUS_DIR:-${PKI_DIR}/status}"
AGENT_IDS_RAW="${NETWATCH_STEP_CA_AGENT_IDS:-agent-core-1,agent-sensor-1,agent-lateral-1,agent-proc-1,agent-scan-1,agent-ddos-1,agent-vuln-1}"

ROOT_CA_DST="${PKI_DIR}/root_ca.crt"
EDGE_DIR="${PKI_DIR}/edge"
AGENT_DIR="${PKI_DIR}/agents"
mkdir -p "${EDGE_DIR}" "${AGENT_DIR}" "${STATUS_DIR}"

atomic_copy() { src="$1"; dst="$2"; mode="$3"; tmp="${dst}.tmp.$$"; cp "${src}" "${tmp}"; chmod "${mode}" "${tmp}"; mv -f "${tmp}" "${dst}"; }
set_key_permissions() { key_path="$1"; case "${key_path}" in ${EDGE_DIR}/*) chmod 0644 "${key_path}" ;; *) chmod 0600 "${key_path}" ;; esac; }
cert_expires_soon() { cert_path="$1"; [ -f "${cert_path}" ] || return 0; openssl x509 -in "${cert_path}" -checkend "${RENEW_BEFORE_SECONDS}" -noout >/dev/null 2>&1 && return 1 || return 0; }

issue_with_token() {
  subject="$1"; cert_path="$2"; key_path="$3"; sans_csv="${4:-}"
  set -- step ca token "${subject}" --ca-url "${CA_URL}" --root "${ROOT_CA_DST}" --provisioner "${PROVISIONER}" --password-file "${PASSWORD_FILE}"
  old_ifs="$IFS"; IFS=','
  for san in ${sans_csv}; do san="$(echo "${san}" | tr -d '[:space:]')"; [ -n "${san}" ] || continue; set -- "$@" --san "${san}"; done
  IFS="$old_ifs"
  token="$("$@")"
  tmp_cert="${cert_path}.tmp.$$"; tmp_key="${key_path}.tmp.$$"
  rm -f "${tmp_cert}" "${tmp_key}"
  step ca certificate "${subject}" "${tmp_cert}" "${tmp_key}" --force --token "${token}" --ca-url "${CA_URL}" --root "${ROOT_CA_DST}"
  chmod 0644 "${tmp_cert}"; set_key_permissions "${tmp_key}"; mv -f "${tmp_cert}" "${cert_path}"; mv -f "${tmp_key}" "${key_path}"
}

renew_or_issue() {
  subject="$1"; cert_path="$2"; key_path="$3"; sans_csv="${4:-}"
  if [ -f "${cert_path}" ] && [ -f "${key_path}" ] && ! cert_expires_soon "${cert_path}"; then return 0; fi
  if [ -f "${cert_path}" ] && [ -f "${key_path}" ]; then
    tmp_cert="${cert_path}.tmp.$$"; tmp_key="${key_path}.tmp.$$"; cp "${cert_path}" "${tmp_cert}"; cp "${key_path}" "${tmp_key}"
    if step ca renew --force "${tmp_cert}" "${tmp_key}" --ca-url "${CA_URL}" --root "${ROOT_CA_DST}" --provisioner "${PROVISIONER}" --password-file "${PASSWORD_FILE}" >/dev/null 2>&1; then chmod 0644 "${tmp_cert}"; set_key_permissions "${tmp_key}"; mv -f "${tmp_cert}" "${cert_path}"; mv -f "${tmp_key}" "${key_path}"; return 0; fi
    rm -f "${tmp_cert}" "${tmp_key}"
  fi
  issue_with_token "${subject}" "${cert_path}" "${key_path}" "${sans_csv}"
}

record_status() {
  status_file="${STATUS_DIR}/issuer.json"; tmp_file="${status_file}.tmp.$$"
  edge_not_after="$(openssl x509 -in "${EDGE_DIR}/tls.crt" -noout -enddate | cut -d= -f2- | tr -d '
' || true)"
  edge_subject="$(openssl x509 -in "${EDGE_DIR}/tls.crt" -noout -subject | cut -d= -f2- | sed 's/^ //g' | tr -d '
' || true)"
  {
    printf '{
'; printf '  "updated_at": "%s",
' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"; printf '  "edge_subject": "%s",
' "${edge_subject}"; printf '  "edge_not_after": "%s",
' "${edge_not_after}"; printf '  "agent_ids": ['
    first=1; old_ifs="$IFS"; IFS=','
    for raw_id in ${AGENT_IDS_RAW}; do agent_id="$(echo "${raw_id}" | tr -d '[:space:]')"; [ -n "${agent_id}" ] || continue; [ "${first}" -eq 1 ] && first=0 || printf ', '; printf '"%s"' "${agent_id}"; done
    IFS="$old_ifs"; printf ']
}
'
  } > "${tmp_file}"
  mv -f "${tmp_file}" "${status_file}"
}

issue_all() {
  [ -f "${ROOT_CA_SOURCE}" ] || { echo "[step-ca-issuer] root CA not found at ${ROOT_CA_SOURCE}" >&2; exit 1; }
  atomic_copy "${ROOT_CA_SOURCE}" "${ROOT_CA_DST}" 0644
  renew_or_issue "${EDGE_CN}" "${EDGE_DIR}/tls.crt" "${EDGE_DIR}/tls.key" "${EDGE_SANS}"
  old_ifs="$IFS"; IFS=','
  for raw_id in ${AGENT_IDS_RAW}; do agent_id="$(echo "${raw_id}" | tr -d '[:space:]')"; [ -n "${agent_id}" ] || continue; target_dir="${AGENT_DIR}/${agent_id}"; mkdir -p "${target_dir}"; renew_or_issue "${agent_id}" "${target_dir}/tls.crt" "${target_dir}/tls.key" "${agent_id}"; done
  IFS="$old_ifs"
  record_status
}

issue_all
while true; do sleep "${RENEW_EVERY_SECONDS}"; issue_all; done
