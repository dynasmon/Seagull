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

TLS_DIR="${TLS_DIR:-secrets/tls}"
AGENT_CA_DIR="${AGENT_CA_DIR:-secrets/agent-ca}"
AGENT_PKI_DIR="${AGENT_PKI_DIR:-secrets/agent-pki}"

mkdir -p "$TLS_DIR"

EDGE_CN="${NETWATCH_AGENT_TLS_SERVER_NAME:-localhost}"
EDGE_CA_CNF="$TLS_DIR/edge-ca-openssl.cnf"
cat > "$EDGE_CA_CNF" <<CONF
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
  -config "$EDGE_CA_CNF" \
  -extensions v3_ca >/dev/null 2>&1

EDGE_SRV_CNF="$TLS_DIR/edge-server-openssl.cnf"
cat > "$EDGE_SRV_CNF" <<CONF
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
  -config "$EDGE_SRV_CNF" >/dev/null 2>&1

openssl x509 -req \
  -in "$TLS_DIR/tls.csr" \
  -CA "$TLS_DIR/ca.crt" \
  -CAkey "$TLS_DIR/ca.key" \
  -CAcreateserial \
  -out "$TLS_DIR/tls.crt" \
  -days "${EDGE_TLS_DAYS:-365}" \
  -sha256 \
  -extfile "$EDGE_SRV_CNF" \
  -extensions v3_server >/dev/null 2>&1

rm -f "$TLS_DIR/tls.csr"
chmod 644 "$TLS_DIR/tls.crt"
chmod 644 "$TLS_DIR/tls.key"
chmod 644 "$TLS_DIR/ca.crt"
chmod 600 "$TLS_DIR/ca.key"

rm -rf "$AGENT_CA_DIR" "$AGENT_PKI_DIR"
mkdir -p "$AGENT_PKI_DIR"

scripts/pki/init_agent_ca.sh "$AGENT_CA_DIR" >/dev/null

agent_ids=()
for id in \
  "${AGENT_PROC_ID:-agent-proc-1}" \
  "${AGENT_SCAN_ID:-agent-scan-1}" \
  "${AGENT_DDOS_ID:-agent-ddos-1}" \
  "${AGENT_LATERAL_ID:-}" \
  "${AGENT_VULN_ID:-}"; do
  id="${id// /}"
  [[ -n "$id" ]] || continue
  skip="false"
  for existing in "${agent_ids[@]:-}"; do
    if [[ "$existing" == "$id" ]]; then
      skip="true"
      break
    fi
  done
  [[ "$skip" == "true" ]] || agent_ids+=("$id")
done

for id in "${agent_ids[@]}"; do
  CA_DIR="$AGENT_CA_DIR" OUT_DIR="$AGENT_PKI_DIR/$id" scripts/pki/issue_agent_cert.sh "$id" "${AGENT_CERT_DAYS:-30}" >/dev/null
  echo "[pki] issued mTLS cert for $id"
done

echo "[pki] edge TLS cert generated at $TLS_DIR/tls.crt (signed by $TLS_DIR/ca.crt)"
echo "[pki] agent CA generated at $AGENT_CA_DIR/ca.crt"
echo "[pki] CRL generated at $AGENT_CA_DIR/ca.crl"
