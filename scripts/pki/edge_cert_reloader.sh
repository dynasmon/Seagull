#!/usr/bin/env sh
set -eu

PKI_DIR="${NETWATCH_PKI_DIR:-/etc/netwatch/pki}"
CHECK_SECONDS="${NETWATCH_EDGE_RELOAD_CHECK_SECONDS:-15}"
STATE_DIR="${NETWATCH_EDGE_RELOAD_STATE_DIR:-/tmp/netwatch-edge-reloader}"
STATE_FILE="${STATE_DIR}/current.sha256"
WATCH_FILES="${PKI_DIR}/root_ca.crt ${PKI_DIR}/edge/tls.crt ${PKI_DIR}/edge/tls.key"

mkdir -p "${STATE_DIR}"

require_files() {
  for path in ${WATCH_FILES}; do
    if [ ! -s "${path}" ]; then
      echo "[edge-reloader] missing file: ${path}" >&2
      return 1
    fi
  done
  return 0
}

current_digest() {
  sha256sum ${WATCH_FILES} | sha256sum | awk '{print $1}'
}

validate_nginx_config() {
  if command -v nginx >/dev/null 2>&1; then
    nginx -t -q
  fi
}

reload_edge() {
  validate_nginx_config
  kill -HUP 1
}

until require_files; do
  sleep 2
done

current="$(current_digest)"
printf '%s
' "${current}" > "${STATE_FILE}"
echo "[edge-reloader] baseline checksum=${current}" >&2

while true; do
  sleep "${CHECK_SECONDS}"
  require_files || continue
  next="$(current_digest)"
  if [ "${next}" = "${current}" ]; then
    continue
  fi
  echo "[edge-reloader] certificate material changed, validating and reloading edge" >&2
  if reload_edge; then
    current="${next}"
    printf '%s
' "${current}" > "${STATE_FILE}"
    echo "[edge-reloader] reload complete checksum=${current}" >&2
  else
    echo "[edge-reloader] reload failed; keeping previous checksum=${current}" >&2
  fi
done
