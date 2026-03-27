#!/usr/bin/env sh
set -eu

# Healthcheck for runtime PKI artifacts produced by the issuer.

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

trim() {
  printf '%s' "$1" | tr -d '[:space:]'
}

ROOT_CA_PATH="${NETWATCH_PKI_DIR:-/var/lib/netwatch/pki}/root_ca.crt"
EDGE_CERT_PATH="${NETWATCH_PKI_DIR:-/var/lib/netwatch/pki}/edge/tls.crt"
EDGE_KEY_PATH="${NETWATCH_PKI_DIR:-/var/lib/netwatch/pki}/edge/tls.key"
STATUS_FILE="${NETWATCH_STEP_CA_STATUS_DIR:-${NETWATCH_PKI_DIR:-/var/lib/netwatch/pki}/status}/issuer.json"
AGENT_IDS_RAW="${NETWATCH_STEP_CA_AGENT_IDS:-agent-core-1,agent-sensor-1,agent-lateral-1,agent-proc-1,agent-scan-1,agent-ddos-1,agent-vuln-1}"
AGENTS_DIR="${NETWATCH_PKI_DIR:-/var/lib/netwatch/pki}/agents"

command -v step >/dev/null 2>&1 || fail "step command not found"

[ -s "$ROOT_CA_PATH" ] || fail "missing root CA: $ROOT_CA_PATH"
[ -s "$EDGE_CERT_PATH" ] || fail "missing edge cert: $EDGE_CERT_PATH"
[ -s "$EDGE_KEY_PATH" ] || fail "missing edge key: $EDGE_KEY_PATH"
[ -s "$STATUS_FILE" ] || fail "missing issuer status file: $STATUS_FILE"

step certificate inspect "$ROOT_CA_PATH" >/dev/null 2>&1 || fail "invalid root CA"
step certificate inspect "$EDGE_CERT_PATH" >/dev/null 2>&1 || fail "invalid edge cert"
step certificate verify --roots "$ROOT_CA_PATH" "$EDGE_CERT_PATH" >/dev/null 2>&1 || fail "edge cert verification failed"

old_ifs="$IFS"
IFS=','
for raw_id in $AGENT_IDS_RAW; do
  agent_id="$(trim "$raw_id")"
  [ -n "$agent_id" ] || continue

  cert_path="${AGENTS_DIR}/${agent_id}/tls.crt"
  key_path="${AGENTS_DIR}/${agent_id}/tls.key"

  [ -s "$cert_path" ] || fail "missing agent cert: $cert_path"
  [ -s "$key_path" ] || fail "missing agent key: $key_path"

  step certificate inspect "$cert_path" >/dev/null 2>&1 || fail "invalid agent cert: $agent_id"
  step certificate verify --roots "$ROOT_CA_PATH" "$cert_path" >/dev/null 2>&1 || fail "agent cert verification failed: $agent_id"
done
IFS="$old_ifs"

grep -q '"updated_at"' "$STATUS_FILE" || fail "status file missing updated_at"
exit 0