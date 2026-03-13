#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-secrets/agent-ca}"
CA_DAYS="${CA_DAYS:-3650}"

mkdir -p "$OUT_DIR" "$OUT_DIR/certs" "$OUT_DIR/crl" "$OUT_DIR/newcerts" "$OUT_DIR/private"
chmod 700 "$OUT_DIR/private"

: > "$OUT_DIR/index.txt"
echo 1000 > "$OUT_DIR/serial"
echo 1000 > "$OUT_DIR/crlnumber"

if [[ ! -f "$OUT_DIR/openssl.cnf" ]]; then
  cat > "$OUT_DIR/openssl.cnf" <<CONF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${OUT_DIR}
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
RANDFILE          = \$dir/private/.rand
private_key       = \$dir/private/ca.key.pem
certificate       = \$dir/ca.crt
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 30
default_crl_days  = 7
preserve          = no
policy            = policy_any
copy_extensions   = copy

[ policy_any ]
commonName              = supplied
organizationName        = optional
organizationalUnitName  = optional
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
emailAddress            = optional

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
x509_extensions     = v3_ca
prompt              = no

[ req_distinguished_name ]
CN = Dynasmon NetWatch Agent CA
O  = Dynasmon NetWatch

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth

CONF
fi

if [[ ! -f "$OUT_DIR/private/ca.key.pem" ]]; then
  openssl genrsa -out "$OUT_DIR/private/ca.key.pem" 4096
  chmod 600 "$OUT_DIR/private/ca.key.pem"
fi

if [[ ! -f "$OUT_DIR/ca.crt" ]]; then
  openssl req -config "$OUT_DIR/openssl.cnf" -key "$OUT_DIR/private/ca.key.pem" -new -x509 -days "$CA_DAYS" -sha256 -extensions v3_ca -out "$OUT_DIR/ca.crt"
fi

openssl ca -gencrl -config "$OUT_DIR/openssl.cnf" -out "$OUT_DIR/ca.crl" >/dev/null 2>&1 || true

printf 'Agent CA initialized at %s\n' "$OUT_DIR"
