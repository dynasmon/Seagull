#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${ENV_FILE:-.env}"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a
  source "$ENV_FILE"
  set +a
fi

if [[ "${NETWATCH_ENV:-dev}" =~ ^(prod|production)$ ]]; then
  echo "[pki] NETWATCH_ENV=${NETWATCH_ENV} -> skipping local runtime PKI bootstrap (production uses step-ca)"
  exit 0
fi

TLS_DIR="${TLS_DIR:-secrets/tls}"
AGENT_CA_DIR="${AGENT_CA_DIR:-secrets/agent-ca}"
AGENT_PKI_DIR="${AGENT_PKI_DIR:-secrets/agent-pki}"

mkdir -p "$TLS_DIR"

EDGE_CN="${NETWATCH_AGENT_TLS_SERVER_NAME:-localhost}"

build_agent_ids() {
  local out=()
  local id=""
  for id in \
    "${AGENT_PROC_ID:-agent-proc-1}" \
    "${AGENT_SCAN_ID:-agent-scan-1}" \
    "${AGENT_DDOS_ID:-agent-ddos-1}" \
    "${AGENT_LATERAL_ID:-}" \
    "${AGENT_VULN_ID:-}"; do
    id="${id// /}"
    [[ -n "$id" ]] || continue
    local seen="false"
    local existing=""
    for existing in "${out[@]:-}"; do
      if [[ "$existing" == "$id" ]]; then
        seen="true"
        break
      fi
    done
    [[ "$seen" == "true" ]] || out+=("$id")
  done
  printf "%s\n" "${out[@]:-}"
}

edge_bundle_valid() {
  local ca_crt="$TLS_DIR/ca.crt"
  local ca_key="$TLS_DIR/ca.key"
  local tls_crt="$TLS_DIR/tls.crt"
  local tls_key="$TLS_DIR/tls.key"
  [[ -f "$ca_crt" && -f "$ca_key" && -f "$tls_crt" && -f "$tls_key" ]] || return 1

  openssl x509 -in "$ca_crt" -noout >/dev/null 2>&1 || return 1
  openssl x509 -in "$tls_crt" -noout >/dev/null 2>&1 || return 1
  openssl verify -CAfile "$ca_crt" "$tls_crt" >/dev/null 2>&1 || return 1
  openssl x509 -in "$tls_crt" -checkend 86400 -noout >/dev/null 2>&1 || return 1

  local san=""
  san="$(openssl x509 -in "$tls_crt" -noout -ext subjectAltName 2>/dev/null || true)"
  grep -Fq "DNS:${EDGE_CN}" <<<"$san" || return 1
  return 0
}

agent_bundle_valid() {
  local ca_crt="$AGENT_CA_DIR/ca.crt"
  local ca_key="$AGENT_CA_DIR/private/ca.key.pem"
  local ca_cnf="$AGENT_CA_DIR/openssl.cnf"
  [[ -f "$ca_crt" && -f "$ca_key" && -f "$ca_cnf" ]] || return 1
  openssl x509 -in "$ca_crt" -noout >/dev/null 2>&1 || return 1

  local id=""
  for id in "$@"; do
    local cert="$AGENT_PKI_DIR/$id/tls.crt"
    local key="$AGENT_PKI_DIR/$id/tls.key"
    [[ -f "$cert" && -f "$key" ]] || return 1
    openssl verify -CAfile "$ca_crt" "$cert" >/dev/null 2>&1 || return 1
    openssl x509 -in "$cert" -checkend 86400 -noout >/dev/null 2>&1 || return 1
    local subject=""
    subject="$(openssl x509 -in "$cert" -noout -subject -nameopt RFC2253 2>/dev/null || true)"
    grep -Fq "CN=${id}" <<<"$subject" || return 1
  done
  return 0
}

generate_edge_bundle() {
  rm -f "$TLS_DIR/ca.key" "$TLS_DIR/ca.crt" "$TLS_DIR/ca.srl" "$TLS_DIR/tls.key" "$TLS_DIR/tls.crt" "$TLS_DIR/tls.csr"

  local edge_ca_cnf="$TLS_DIR/edge-ca-openssl.cnf"
  cat > "$edge_ca_cnf" <<CONF
[ req ]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca

[ dn ]
CN = Dynasmon NetWatch Edge CA

[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
CONF

  openssl req -x509 -nodes -newkey rsa:4096 \
    -days "${EDGE_CA_DAYS:-3650}" \
    -keyout "$TLS_DIR/ca.key" \
    -out "$TLS_DIR/ca.crt" \
    -config "$edge_ca_cnf" \
    -extensions v3_ca >/dev/null 2>&1

  local edge_srv_cnf="$TLS_DIR/edge-server-openssl.cnf"
  cat > "$edge_srv_cnf" <<CONF
[ req ]
prompt = no
distinguished_name = dn

[ dn ]
CN = ${EDGE_CN}

[ v3_server ]
subjectAltName = @alt_names
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1 = ${EDGE_CN}
DNS.2 = localhost
IP.1 = 127.0.0.1
CONF

  openssl req -new -nodes -newkey rsa:4096 \
    -keyout "$TLS_DIR/tls.key" \
    -out "$TLS_DIR/tls.csr" \
    -config "$edge_srv_cnf" >/dev/null 2>&1

  openssl x509 -req \
    -in "$TLS_DIR/tls.csr" \
    -CA "$TLS_DIR/ca.crt" \
    -CAkey "$TLS_DIR/ca.key" \
    -CAcreateserial \
    -out "$TLS_DIR/tls.crt" \
    -days "${EDGE_TLS_DAYS:-365}" \
    -sha256 \
    -extfile "$edge_srv_cnf" \
    -extensions v3_server >/dev/null 2>&1

  rm -f "$TLS_DIR/tls.csr"
  chmod 644 "$TLS_DIR/tls.crt"
  chmod 644 "$TLS_DIR/tls.key"
  chmod 644 "$TLS_DIR/ca.crt"
  chmod 600 "$TLS_DIR/ca.key"
}

generate_agent_bundle() {
  local ids=("$@")
  rm -rf "$AGENT_CA_DIR" "$AGENT_PKI_DIR"
  mkdir -p "$AGENT_PKI_DIR"

  scripts/pki/init_agent_ca.sh "$AGENT_CA_DIR" >/dev/null
  local id=""
  for id in "${ids[@]:-}"; do
    CA_DIR="$AGENT_CA_DIR" OUT_DIR="$AGENT_PKI_DIR/$id" scripts/pki/issue_agent_cert.sh "$id" "${AGENT_CERT_DAYS:-30}" >/dev/null
    echo "[pki] issued mTLS cert for $id"
  done
}

readarray -t agent_ids < <(build_agent_ids)

force_regenerate="${NETWATCH_FORCE_REGENERATE_CERTS:-false}"
regen_edge="false"
regen_agent="false"

if [[ "$force_regenerate" == "true" ]]; then
  regen_edge="true"
  regen_agent="true"
else
  edge_bundle_valid || regen_edge="true"
  agent_bundle_valid "${agent_ids[@]:-}" || regen_agent="true"
fi

if [[ "$regen_edge" == "false" && "$regen_agent" == "false" ]]; then
  echo "[pki] using existing edge+agent certificates (valid bundle)"
  exit 0
fi

if [[ "$regen_edge" == "true" ]]; then
  echo "[pki] generating edge TLS CA/certificate bundle"
  generate_edge_bundle
  echo "[pki] edge TLS cert generated at $TLS_DIR/tls.crt (signed by $TLS_DIR/ca.crt)"
fi

if [[ "$regen_agent" == "true" ]]; then
  echo "[pki] generating agent CA/certificates bundle"
  generate_agent_bundle "${agent_ids[@]:-}"
  echo "[pki] agent CA generated at $AGENT_CA_DIR/ca.crt"
  echo "[pki] CRL generated at $AGENT_CA_DIR/ca.crl"
fi
