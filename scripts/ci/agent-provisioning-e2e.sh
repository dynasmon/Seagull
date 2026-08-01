#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

PORTAL_URL="${SEAGULL_PORTAL_URL:-https://localhost:8443}"
ADMIN_USERNAME="${SEAGULL_ADMIN_USERNAME:-}"
ADMIN_PASSWORD="${SEAGULL_ADMIN_PASSWORD:-}"
BACKEND_CONTAINER="${SEAGULL_BACKEND_CONTAINER:-seagull-backend}"
ENDPOINT_IMAGE="seagull-agent-endpoint:e2e"
TRANSFER_AGENT="${SEAGULL_E2E_TRANSFER_AGENT:-e2e-transfer-endpoint}"
BOOTSTRAP_AGENT="${SEAGULL_E2E_BOOTSTRAP_AGENT:-e2e-bootstrap-endpoint}"
TRANSFER_CONTAINER="seagull-e2e-transfer"
BOOTSTRAP_CONTAINER="seagull-e2e-bootstrap"
KEEP=0
WORKDIR=""
PASSED=0

usage() {
  cat <<'USAGE'
Usage: agent-provisioning-e2e.sh [--keep]

Provisions two endpoints from a running Seagull stack exactly as an operator
would, and asserts that each one enrols, authenticates with mTLS and delivers
telemetry.

  --keep    Leave the endpoint containers running for inspection
  -h        Show this help

Environment:
  SEAGULL_PORTAL_URL       Portal base URL (default https://localhost:8443)
  SEAGULL_ADMIN_USERNAME   Portal administrator (read from the backend when unset)
  SEAGULL_ADMIN_PASSWORD   Portal administrator password
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

log() { printf '::: %s\n' "$*"; }
fail() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [[ "${PASSED}" != "1" ]]; then
    for container in "${TRANSFER_CONTAINER}" "${BOOTSTRAP_CONTAINER}"; do
      if docker inspect "${container}" >/dev/null 2>&1; then
        printf '::: %s journal :::\n' "${container}" >&2
        docker exec "${container}" journalctl -u seagull-agent -n 40 --no-pager -o cat >&2 2>/dev/null || true
      fi
    done
  fi
  if [[ "${KEEP}" != "1" ]]; then
    docker rm -f "${TRANSFER_CONTAINER}" "${BOOTSTRAP_CONTAINER}" >/dev/null 2>&1 || true
  fi
  [[ -n "${WORKDIR}" && -d "${WORKDIR}" ]] && rm -rf "${WORKDIR}"
}
trap cleanup EXIT

api() {
  local method="$1" path="$2"
  shift 2
  curl --silent --show-error --insecure --request "${method}" \
    --header "Authorization: Bearer ${ACCESS_TOKEN}" \
    "$@" "${PORTAL_URL}${path}"
}

json() {
  python3 -c 'import json,sys;d=json.load(sys.stdin)
for key in sys.argv[1:]:
    d = d[int(key)] if isinstance(d, list) else d[key]
print("" if d is None else d)' "$@"
}

start_endpoint() {
  local container="$1"
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker run --detach --name "${container}" \
    --privileged --cgroupns=host --network host \
    --volume /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock \
    "${ENDPOINT_IMAGE}" >/dev/null
  local waited=0
  while (( waited < 60 )); do
    if docker exec "${container}" test -d /run/systemd/system >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  fail "systemd did not boot inside ${container}"
}

delivered_events() {
  api GET "/api/agents/$1" | python3 -c 'import json,sys
metrics = (json.load(sys.stdin).get("metrics") or {}).get("metrics") or {}
print(int(metrics.get("events_durable_total") or 0), int(metrics.get("send_errors_total") or 0))'
}

wait_for_telemetry() {
  local agent_id="$1" waited=0 delivered errors
  while (( waited < 90 )); do
    read -r delivered errors <<< "$(delivered_events "${agent_id}")"
    if (( delivered > 0 )); then
      (( errors == 0 )) || fail "${agent_id} reported ${errors} delivery errors"
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  return 1
}

assert_enrolled() {
  local agent_id="$1" expected_profile="$2" container="$3"
  wait_for_telemetry "${agent_id}" || fail "the platform accepted no telemetry from ${agent_id}"
  local detail
  detail="$(api GET "/api/agents/${agent_id}")"
  local seen profile serial
  seen="$(printf '%s' "${detail}" | json last_seen_at)"
  profile="$(printf '%s' "${detail}" | json metrics profile)"
  serial="$(printf '%s' "${detail}" | json metrics metrics tls_client_cert_serial)"
  [[ -n "${seen}" ]] || fail "${agent_id} never reported to the platform"
  [[ "${profile}" == "${expected_profile}" ]] || fail "${agent_id} runs profile '${profile}', expected '${expected_profile}'"
  [[ -n "${serial}" ]] || fail "${agent_id} did not authenticate with a client certificate"
  docker exec "${container}" systemctl is-active --quiet seagull-agent || fail "${agent_id} service is not active"
  docker exec "${container}" test -s /var/lib/seagull/pki/client.crt || fail "${agent_id} has no client certificate"
  docker exec "${container}" test -s /var/lib/seagull/agent.identity.json || fail "${agent_id} has no identity state"
  docker exec "${container}" test ! -e /var/lib/seagull/bootstrap.token || fail "${agent_id} kept its enrollment token"
  log "${agent_id}: enrolled, ${expected_profile} profile, certificate issued, telemetry delivered"
}

log "host prerequisites"
for tool in docker curl python3 openssl; do
  command -v "${tool}" >/dev/null 2>&1 || fail "missing required command: ${tool}"
done

if [[ -z "${ADMIN_USERNAME}" || -z "${ADMIN_PASSWORD}" ]]; then
  ADMIN_USERNAME="${ADMIN_USERNAME:-$(docker exec "${BACKEND_CONTAINER}" printenv SEAGULL_BOOTSTRAP_ADMIN_USERNAME 2>/dev/null || true)}"
  ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(docker exec "${BACKEND_CONTAINER}" printenv SEAGULL_BOOTSTRAP_ADMIN_PASSWORD 2>/dev/null || true)}"
fi
[[ -n "${ADMIN_USERNAME}" && -n "${ADMIN_PASSWORD}" ]] \
  || fail "set SEAGULL_ADMIN_USERNAME and SEAGULL_ADMIN_PASSWORD"

WORKDIR="$(mktemp -d)"
chmod 700 "${WORKDIR}"

log "authenticating against ${PORTAL_URL}"
ACCESS_TOKEN="$(
  curl --silent --show-error --insecure --request POST \
    --header 'Content-Type: application/json' \
    --data "$(python3 -c 'import json,sys;print(json.dumps({"username":sys.argv[1],"password":sys.argv[2]}))' "${ADMIN_USERNAME}" "${ADMIN_PASSWORD}")" \
    "${PORTAL_URL}/api/auth/login" | json access_token
)"
[[ -n "${ACCESS_TOKEN}" ]] || fail "portal authentication failed"

log "synchronising the pinned agent packages"
api POST /api/agents/packages/sync > "${WORKDIR}/packages.json"
[[ "$(json packages 0 cached < "${WORKDIR}/packages.json")" == "True" ]] \
  || fail "the platform could not make the pinned agent package available"

log "building the endpoint image"
docker build --quiet --file scripts/ci/agent-endpoint.Dockerfile --tag "${ENDPOINT_IMAGE}" scripts/ci >/dev/null

log "endpoint 1: installer downloaded from the portal and transferred"
start_endpoint "${TRANSFER_CONTAINER}"
api POST /api/agents/enrollment-tickets \
  --header 'Content-Type: application/json' \
  --data "{\"agent_id\":\"${TRANSFER_AGENT}\",\"profile\":\"sensor\",\"architecture\":\"amd64\",\"sources\":[\"authlog\",\"proc\",\"fim\"]}" \
  > "${WORKDIR}/ticket-transfer.json"
TRANSFER_TOKEN="$(json bootstrap_token < "${WORKDIR}/ticket-transfer.json")"
TRANSFER_FILE="$(json installer_filename < "${WORKDIR}/ticket-transfer.json")"
[[ -n "${TRANSFER_TOKEN}" ]] || fail "the platform issued no enrollment token"

curl --silent --show-error --insecure --fail \
  --header "X-Agent-Bootstrap-Token: ${TRANSFER_TOKEN}" \
  --output "${WORKDIR}/${TRANSFER_FILE}" \
  "${PORTAL_URL}/api/agents/installer" || fail "the installer download failed"
bash -n "${WORKDIR}/${TRANSFER_FILE}" || fail "the generated installer is not valid bash"
docker cp "${WORKDIR}/${TRANSFER_FILE}" "${TRANSFER_CONTAINER}:/root/${TRANSFER_FILE}" >/dev/null
docker exec --workdir /root "${TRANSFER_CONTAINER}" bash "${TRANSFER_FILE}"
assert_enrolled "${TRANSFER_AGENT}" sensor "${TRANSFER_CONTAINER}"

log "endpoint 1: re-running the installer preserves the endpoint identity"
CERT_BEFORE="$(docker exec "${TRANSFER_CONTAINER}" sha256sum /var/lib/seagull/pki/client.crt)"
docker exec --workdir /root "${TRANSFER_CONTAINER}" bash "${TRANSFER_FILE}" >/dev/null
CERT_AFTER="$(docker exec "${TRANSFER_CONTAINER}" sha256sum /var/lib/seagull/pki/client.crt)"
[[ "${CERT_BEFORE}" == "${CERT_AFTER}" ]] || fail "re-running the installer replaced the endpoint certificate"
docker exec "${TRANSFER_CONTAINER}" systemctl is-active --quiet seagull-agent \
  || fail "the service is not active after a re-run"
log "identity preserved across a re-run"

log "endpoint 2: single command executed on the endpoint"
start_endpoint "${BOOTSTRAP_CONTAINER}"
openssl s_client -connect "${PORTAL_URL#https://}" -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > "${WORKDIR}/portal.crt"
docker cp "${WORKDIR}/portal.crt" "${BOOTSTRAP_CONTAINER}:/usr/local/share/ca-certificates/seagull-portal.crt" >/dev/null
docker exec "${BOOTSTRAP_CONTAINER}" update-ca-certificates >/dev/null 2>&1

api POST /api/agents/enrollment-tickets \
  --header 'Content-Type: application/json' \
  --data "{\"agent_id\":\"${BOOTSTRAP_AGENT}\",\"profile\":\"managed\",\"architecture\":\"amd64\"}" \
  > "${WORKDIR}/ticket-bootstrap.json"
BOOTSTRAP_COMMAND="$(json bootstrap_command < "${WORKDIR}/ticket-bootstrap.json")"
[[ -n "${BOOTSTRAP_COMMAND}" ]] || fail "the platform rendered no endpoint command"
docker exec --workdir /root "${BOOTSTRAP_CONTAINER}" bash -lc "${BOOTSTRAP_COMMAND}"
assert_enrolled "${BOOTSTRAP_AGENT}" managed "${BOOTSTRAP_CONTAINER}"

log "a consumed enrollment token no longer yields an installer"
STATUS="$(curl --silent --insecure --output /dev/null --write-out '%{http_code}' \
  --header "X-Agent-Bootstrap-Token: ${TRANSFER_TOKEN}" \
  "${PORTAL_URL}/api/agents/installer")"
[[ "${STATUS}" == "401" ]] || fail "a consumed token returned HTTP ${STATUS} instead of 401"

log "an unauthenticated installer request is refused"
STATUS="$(curl --silent --insecure --output /dev/null --write-out '%{http_code}' \
  "${PORTAL_URL}/api/agents/installer")"
[[ "${STATUS}" == "401" ]] || fail "an unauthenticated request returned HTTP ${STATUS} instead of 401"

PASSED=1
log "agent provisioning end-to-end PASSED"
