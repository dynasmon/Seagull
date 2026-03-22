#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <agent_id> [days]" >&2
  exit 1
fi

AGENT_ID="$1"
DAYS="${2:-${CERT_DAYS:-30}}"
CA_DIR="${CA_DIR:-secrets/agent-ca}"
OUT_DIR="${OUT_DIR:-secrets/agent-pki/${AGENT_ID}}"

mkdir -p "$OUT_DIR"

if [[ ! -f "$CA_DIR/ca.crt" || ! -f "$CA_DIR/private/ca.key.pem" || ! -f "$CA_DIR/openssl.cnf" ]]; then
  echo "Agent CA not initialized. Run scripts/pki/init_agent_ca.sh first." >&2
  exit 1
fi

KEY_PATH="$OUT_DIR/tls.key"
CSR_PATH="$OUT_DIR/tls.csr"
CERT_PATH="$OUT_DIR/tls.crt"
EXT_PATH="$OUT_DIR/extensions.cnf"

openssl genrsa -out "$KEY_PATH" 4096

if [[ "${NETWATCH_ENV:-dev}" =~ ^(prod|production)$ ]]; then
  chmod 600 "$KEY_PATH"
else
  chmod 644 "$KEY_PATH"
fi

cat > "$EXT_PATH" <<EXT
[ req ]
prompt = no
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = ${AGENT_ID}
O = Dynasmon NetWatch Agents

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${AGENT_ID}
URI.1 = spiffe://dynasmon-netwatch/agent/${AGENT_ID}

EXT

openssl req -new -key "$KEY_PATH" -out "$CSR_PATH" -config "$EXT_PATH"
openssl ca -batch -config "$CA_DIR/openssl.cnf" -extensions usr_cert -days "$DAYS" -notext -md sha256 -in "$CSR_PATH" -out "$CERT_PATH"
chmod 644 "$CERT_PATH"

FINGERPRINT="$(openssl x509 -in "$CERT_PATH" -noout -fingerprint -sha256 | cut -d= -f2 | tr 'A-Z' 'a-z' | tr -d ':')"
SERIAL="$(openssl x509 -in "$CERT_PATH" -noout -serial | cut -d= -f2 | tr 'A-Z' 'a-z')"

cat <<INFO
Issued certificate for agent ${AGENT_ID}
  cert: ${CERT_PATH}
  key:  ${KEY_PATH}
  serial: ${SERIAL}
  fingerprint_sha256: ${FINGERPRINT}
INFO
