#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <cert_path>" >&2
  exit 1
fi

CERT_PATH="$1"
CA_DIR="${CA_DIR:-secrets/agent-ca}"

if [[ ! -f "$CERT_PATH" ]]; then
  echo "Certificate not found: $CERT_PATH" >&2
  exit 1
fi

if [[ ! -f "$CA_DIR/openssl.cnf" ]]; then
  echo "CA config not found: $CA_DIR/openssl.cnf" >&2
  exit 1
fi

openssl ca -config "$CA_DIR/openssl.cnf" -revoke "$CERT_PATH"
openssl ca -gencrl -config "$CA_DIR/openssl.cnf" -out "$CA_DIR/ca.crl"

echo "Revoked certificate: $CERT_PATH"
echo "Updated CRL: $CA_DIR/ca.crl"
