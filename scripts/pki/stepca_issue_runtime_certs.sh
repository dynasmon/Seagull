#!/usr/bin/env sh
set -eu

# Runtime issuer for NetWatch production PKI.
# This script must stay alive for the lifetime of the container.

log() {
  printf '%s %s\n' "[step-ca-issuer]" "$*"
}

fail() {
  printf '%s %s\n' "[step-ca-issuer][error]" "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

trim() {
  printf '%s' "$1" | tr -d '[:space:]'
}

atomic_copy() {
  src="$1"
  dst="$2"
  mode="$3"
  tmp="${dst}.tmp.$$"

  cp "$src" "$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$dst"
}

atomic_write() {
  dst="$1"
  mode="$2"
  tmp="${dst}.tmp.$$"

  cat > "$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$dst"
}

set_key_permissions() {
  key_path="$1"
  case "$key_path" in
    */edge/*) chmod 0644 "$key_path" ;;
    *) chmod 0600 "$key_path" ;;
  esac
}

cert_parse_ok() {
  cert_path="$1"
  [ -s "$cert_path" ] || return 1
  step certificate inspect "$cert_path" >/dev/null 2>&1
}

cert_verify_ok() {
  cert_path="$1"
  root_path="$2"
  [ -s "$cert_path" ] || return 1
  [ -s "$root_path" ] || return 1
  step certificate verify --roots "$root_path" "$cert_path" >/dev/null 2>&1
}

write_status() {
  now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  atomic_write "$STATUS_FILE" 0644 <<EOF
{
  "updated_at": "$now",
  "pid": $$,
  "ca_url": "$CA_URL",
  "provisioner": "$PROVISIONER",
  "edge_cn": "$EDGE_CN",
  "edge_cert": "$EDGE_CERT",
  "root_ca": "$ROOT_CA_DST"
}
EOF
}

issue_with_token() {
  subject="$1"
  cert_path="$2"
  key_path="$3"
  sans_csv="${4:-}"

  token_args="--ca-url ${CA_URL} --root ${ROOT_CA_DST} --provisioner ${PROVISIONER} --password-file ${PASSWORD_FILE}"

  # Build token command with SANs.
  set -- step ca token "$subject" --ca-url "$CA_URL" --root "$ROOT_CA_DST" --provisioner "$PROVISIONER" --password-file "$PASSWORD_FILE"
  old_ifs="$IFS"
  IFS=','
  for raw_san in $sans_csv; do
    san="$(trim "$raw_san")"
    [ -n "$san" ] || continue
    set -- "$@" --san "$san"
  done
  IFS="$old_ifs"

  token="$("$@")"

  tmp_cert="${cert_path}.tmp.$$"
  tmp_key="${key_path}.tmp.$$"
  rm -f "$tmp_cert" "$tmp_key"

  step ca certificate "$subject" "$tmp_cert" "$tmp_key" \
    --force \
    --token "$token" \
    --ca-url "$CA_URL" \
    --root "$ROOT_CA_DST"

  chmod 0644 "$tmp_cert"
  set_key_permissions "$tmp_key"
  mv -f "$tmp_cert" "$cert_path"
  mv -f "$tmp_key" "$key_path"

  log "issued certificate for subject=${subject}"
}

ensure_present_or_issue() {
  subject="$1"
  cert_path="$2"
  key_path="$3"
  sans_csv="${4:-}"

  if [ -s "$cert_path" ] && [ -s "$key_path" ] && cert_parse_ok "$cert_path" && cert_verify_ok "$cert_path" "$ROOT_CA_DST"; then
    log "keeping existing certificate for subject=${subject}"
    return 0
  fi

  log "issuing missing/invalid certificate for subject=${subject}"
  issue_with_token "$subject" "$cert_path" "$key_path" "$sans_csv"
}

renew_or_reissue() {
  subject="$1"
  cert_path="$2"
  key_path="$3"
  sans_csv="${4:-}"

  if [ -s "$cert_path" ] && [ -s "$key_path" ]; then
    tmp_cert="${cert_path}.tmp.$$"
    tmp_key="${key_path}.tmp.$$"
    cp "$cert_path" "$tmp_cert"
    cp "$key_path" "$tmp_key"

    if step ca renew --force "$tmp_cert" "$tmp_key" \
      --ca-url "$CA_URL" \
      --root "$ROOT_CA_DST" \
      --provisioner "$PROVISIONER" \
      --password-file "$PASSWORD_FILE" >/dev/null 2>&1; then
      chmod 0644 "$tmp_cert"
      set_key_permissions "$tmp_key"
      mv -f "$tmp_cert" "$cert_path"
      mv -f "$tmp_key" "$key_path"
      log "renewed certificate for subject=${subject}"
      return 0
    fi

    rm -f "$tmp_cert" "$tmp_key"
    log "renew failed, reissuing certificate for subject=${subject}"
  else
    log "certificate/key missing, issuing certificate for subject=${subject}"
  fi

  issue_with_token "$subject" "$cert_path" "$key_path" "$sans_csv"
}

for_each_agent() {
  callback="$1"
  old_ifs="$IFS"
  IFS=','
  for raw_id in $AGENT_IDS_RAW; do
    agent_id="$(trim "$raw_id")"
    [ -n "$agent_id" ] || continue
    "$callback" "$agent_id"
  done
  IFS="$old_ifs"
}

ensure_agent_bundle() {
  agent_id="$1"
  target_dir="${AGENTS_DIR}/${agent_id}"
  mkdir -p "$target_dir"
  ensure_present_or_issue "$agent_id" "${target_dir}/tls.crt" "${target_dir}/tls.key" "$agent_id"
}

renew_agent_bundle() {
  agent_id="$1"
  target_dir="${AGENTS_DIR}/${agent_id}"
  mkdir -p "$target_dir"
  renew_or_reissue "$agent_id" "${target_dir}/tls.crt" "${target_dir}/tls.key" "$agent_id"
}

bootstrap_once() {
  [ -s "$PASSWORD_FILE" ] || fail "provisioner password file not found or empty: $PASSWORD_FILE"
  [ -s "$ROOT_CA_SOURCE" ] || fail "root CA source not found or empty: $ROOT_CA_SOURCE"

  atomic_copy "$ROOT_CA_SOURCE" "$ROOT_CA_DST" 0644

  ensure_present_or_issue "$EDGE_CN" "$EDGE_CERT" "$EDGE_KEY" "$EDGE_SANS"
  for_each_agent ensure_agent_bundle
  write_status

  log "bootstrap completed successfully"
}

renew_cycle() {
  atomic_copy "$ROOT_CA_SOURCE" "$ROOT_CA_DST" 0644

  renew_or_reissue "$EDGE_CN" "$EDGE_CERT" "$EDGE_KEY" "$EDGE_SANS"
  for_each_agent renew_agent_bundle
  write_status

  log "renewal cycle completed successfully"
}

CA_URL="${NETWATCH_STEP_CA_URL:-https://netwatch-step-ca:9000}"
PROVISIONER="${NETWATCH_STEP_CA_PROVISIONER:-netwatch-provisioner}"
PASSWORD_FILE="${NETWATCH_STEP_CA_PROVISIONER_PASSWORD_FILE:-/etc/netwatch/step-ca/provisioner-password.txt}"
PKI_DIR="${NETWATCH_PKI_DIR:-/var/lib/netwatch/pki}"
ROOT_CA_SOURCE="${NETWATCH_STEP_CA_ROOT_SOURCE:-/var/lib/step/certs/root_ca.crt}"
EDGE_CN="${NETWATCH_EDGE_CERT_CN:-localhost}"
EDGE_SANS="${NETWATCH_EDGE_CERT_SANS:-localhost,netwatch-edge,127.0.0.1}"
RENEW_EVERY_SECONDS="${NETWATCH_STEP_CA_RENEW_EVERY_SECONDS:-21600}"
AGENT_IDS_RAW="${NETWATCH_STEP_CA_AGENT_IDS:-agent-core-1,agent-sensor-1,agent-lateral-1,agent-proc-1,agent-scan-1,agent-ddos-1,agent-vuln-1}"

STATUS_DIR="${NETWATCH_STEP_CA_STATUS_DIR:-${PKI_DIR}/status}"
ROOT_CA_DST="${PKI_DIR}/root_ca.crt"
EDGE_DIR="${PKI_DIR}/edge"
AGENTS_DIR="${PKI_DIR}/agents"
EDGE_CERT="${EDGE_DIR}/tls.crt"
EDGE_KEY="${EDGE_DIR}/tls.key"
STATUS_FILE="${STATUS_DIR}/issuer.json"

require_cmd step
require_cmd cp
require_cmd mv
require_cmd chmod
require_cmd date
require_cmd tr

case "$RENEW_EVERY_SECONDS" in
  ''|*[!0-9]*)
    fail "NETWATCH_STEP_CA_RENEW_EVERY_SECONDS must be a positive integer, got: $RENEW_EVERY_SECONDS"
    ;;
esac

[ "$RENEW_EVERY_SECONDS" -gt 0 ] || fail "NETWATCH_STEP_CA_RENEW_EVERY_SECONDS must be > 0"

mkdir -p "$EDGE_DIR" "$AGENTS_DIR" "$STATUS_DIR"

stop_requested=0
trap 'stop_requested=1; log "termination signal received"' INT TERM

log "starting issuer"
log "ca_url=${CA_URL}"
log "provisioner=${PROVISIONER}"
log "edge_cn=${EDGE_CN}"
log "renew_every_seconds=${RENEW_EVERY_SECONDS}"
log "pki_dir=${PKI_DIR}"

bootstrap_once

while [ "$stop_requested" -eq 0 ]; do
  sleep "$RENEW_EVERY_SECONDS" || true
  [ "$stop_requested" -eq 0 ] || break

  if ! renew_cycle; then
    log "renewal cycle failed; will retry on next interval"
  fi
done

log "issuer stopped"