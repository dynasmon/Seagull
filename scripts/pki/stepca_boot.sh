#!/usr/bin/env sh
set -eu

STEPPATH="${STEPPATH:-/var/lib/step}"
STEP_CA_URL="${NETWATCH_STEP_CA_URL:-https://netwatch-step-ca:9000}"
STEP_PROVISIONER="${NETWATCH_STEP_CA_PROVISIONER:-netwatch-provisioner}"
STEP_PASSWORD_FILE="${NETWATCH_STEP_CA_PASSWORD_FILE:-/etc/netwatch/step-ca/ca-password.txt}"
STEP_PROVISIONER_PASSWORD_FILE="${NETWATCH_STEP_CA_PROVISIONER_PASSWORD_FILE:-/etc/netwatch/step-ca/provisioner-password.txt}"
STEP_DNS_NAMES="${NETWATCH_STEP_CA_DNS_NAMES:-netwatch-step-ca,localhost,netwatch-edge}"

mkdir -p "${STEPPATH}/config" "${STEPPATH}/certs" "${STEPPATH}/secrets"
chmod 700 "${STEPPATH}" || true

if [ ! -s "${STEP_PASSWORD_FILE}" ]; then
  echo "[step-ca] missing CA password file: ${STEP_PASSWORD_FILE}" >&2
  exit 1
fi
if [ ! -s "${STEP_PROVISIONER_PASSWORD_FILE}" ]; then
  echo "[step-ca] missing provisioner password file: ${STEP_PROVISIONER_PASSWORD_FILE}" >&2
  exit 1
fi

if [ ! -s "${STEPPATH}/config/ca.json" ]; then
  step ca init \
    --name "Dynasmon NetWatch PKI" \
    --dns "${STEP_DNS_NAMES}" \
    --address ":9000" \
    --provisioner "${STEP_PROVISIONER}" \
    --password-file "${STEP_PASSWORD_FILE}" \
    --provisioner-password-file "${STEP_PROVISIONER_PASSWORD_FILE}" \
    --deployment-type standalone \
    --with-ca-url "${STEP_CA_URL}"
fi

exec step-ca "${STEPPATH}/config/ca.json" --password-file "${STEP_PASSWORD_FILE}"
