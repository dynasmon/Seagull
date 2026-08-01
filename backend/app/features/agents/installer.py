from __future__ import annotations

import base64
from dataclasses import dataclass
from shlex import quote
from typing import Optional, Sequence

from app.features.agents.packages import PackageRef

SCHEMA_VERSION = 1
_PAYLOAD_MARKER = "SEAGULL_PAYLOAD_BEGIN"
_CA_HEREDOC = "SEAGULL_SERVER_CA_PEM"
_BASE64_WIDTH = 76

_BODY = """
START_SERVICE=1
INSTALL_DEPENDENCIES=1
ALLOW_DOWNGRADE=0
SELF="${BASH_SOURCE[0]}"
WORKDIR=""
PACKAGE_DIR=""

log() {
  printf '[seagull-agent] %s\\n' "$*"
}

fail() {
  printf '[seagull-agent] error: %s\\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage: seagull-agent installer [options]

This installer is pre-configured by the Seagull server for a single endpoint.
It carries the pinned agent release, the platform trust anchor and a single-use
enrollment token, and needs no additional arguments.

  --no-start            Install and enable the service without starting it
  --skip-dependencies   Never install runtime dependencies with the package manager
  --allow-downgrade     Permit replacing a newer installed release
  -h, --help            Show this help

Set SEAGULL_ENROLLMENT_TOKEN to override the embedded enrollment token.
USAGE
}

parse_arguments() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-start)
        START_SERVICE=0
        shift
        ;;
      --skip-dependencies)
        INSTALL_DEPENDENCIES=0
        shift
        ;;
      --allow-downgrade)
        ALLOW_DOWNGRADE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        printf 'unknown option: %s\\n' "$1" >&2
        usage >&2
        exit 2
        ;;
    esac
  done
}

expected_machine() {
  case "${AGENT_ARCH}" in
    amd64) printf 'x86_64' ;;
    arm64) printf 'aarch64' ;;
    *) printf '%s' "${AGENT_ARCH}" ;;
  esac
}

preflight() {
  [[ "${EUID}" -eq 0 ]] || fail 'run this installer as root'
  [[ -f "${SELF}" ]] || fail 'save this installer to a file before running it'
  local tool
  for tool in awk base64 sha256sum tar mktemp uname; do
    command -v "${tool}" >/dev/null 2>&1 || fail "required command not found: ${tool}"
  done
  local machine expected
  machine="$(uname -m)"
  expected="$(expected_machine)"
  if [[ "${machine}" != "${expected}" ]]; then
    fail "this installer targets linux/${AGENT_ARCH} (${expected}) but the host reports ${machine}"
  fi
  [[ "$(uname -s)" == "Linux" ]] || fail 'the Seagull agent supports Linux only'
}

unpack() {
  WORKDIR="$(mktemp -d)"
  chmod 700 "${WORKDIR}"
  trap 'rm -rf "${WORKDIR}"' EXIT INT TERM
  local start
  start="$(awk '/^SEAGULL_PAYLOAD_BEGIN$/ { print NR + 1; exit }' "${SELF}")"
  [[ -n "${start}" ]] || fail 'this installer has no embedded agent package'
  tail -n +"${start}" "${SELF}" | base64 -d > "${WORKDIR}/package.tar.gz" \\
    || fail 'the embedded agent package could not be decoded; download this installer again'
  printf '%s  %s\\n' "${PACKAGE_SHA256}" "${WORKDIR}/package.tar.gz" | sha256sum --check --status - \\
    || fail 'the embedded agent package failed its integrity check'
  log "verified ${PACKAGE_NAME}.tar.gz (sha256 ${PACKAGE_SHA256})"
  tar -xzf "${WORKDIR}/package.tar.gz" -C "${WORKDIR}"
  PACKAGE_DIR="${WORKDIR}/${PACKAGE_NAME}"
  [[ -f "${PACKAGE_DIR}/install.sh" ]] || fail 'the embedded agent package is malformed'
}

missing_libraries() {
  command -v ldd >/dev/null 2>&1 || return 0
  ldd "${PACKAGE_DIR}/seagull-agent" 2>/dev/null | awk '/not found/ { print $1 }' | sort -u || true
}

install_libpcap() {
  command -v apt-get >/dev/null 2>&1 \\
    || fail 'libpcap is required and no supported package manager was found; install it and run this installer again'
  log 'installing the libpcap runtime dependency'
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  local candidate
  for candidate in libpcap0.8t64 libpcap0.8; do
    if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${candidate}" >/dev/null 2>&1; then
      log "installed ${candidate}"
      return 0
    fi
  done
  fail 'unable to install libpcap with apt-get'
}

resolve_dependencies() {
  local missing
  missing="$(missing_libraries)"
  [[ -n "${missing}" ]] || return 0
  local library needs_libpcap=0
  while read -r library; do
    [[ -n "${library}" ]] || continue
    case "${library}" in
      libpcap.so.*) needs_libpcap=1 ;;
      *) fail "unresolved runtime dependency: ${library}" ;;
    esac
  done <<< "${missing}"
  [[ "${needs_libpcap}" -eq 1 ]] || return 0
  [[ "${INSTALL_DEPENDENCIES}" -eq 1 ]] \\
    || fail 'libpcap is required but dependency installation was skipped'
  install_libpcap
  missing="$(missing_libraries)"
  [[ -z "${missing}" ]] || fail "unresolved runtime dependencies after installation: ${missing//$'\\n'/ }"
}

installed_release() {
  local path=/var/lib/seagull/agent.release
  [[ -f "${path}" ]] || return 0
  awk -F= '$1 == "current" { print $2; exit }' "${path}"
}

write_credentials() {
  umask 077
  printf '%s\\n' "${ENROLLMENT_TOKEN}" > "${WORKDIR}/enroll.token"
  if [[ "${SERVER_CA_INCLUDED}" -eq 1 ]]; then
    write_server_ca "${WORKDIR}/server-ca.crt"
  fi
}

run_install() {
  local arguments=(
    --agent-id "${AGENT_ID}"
    --api-url "${API_URL}"
    --enroll-url "${ENROLL_URL}"
    --profile "${AGENT_PROFILE}"
    --sources "${AGENT_SOURCES}"
  )
  if [[ -n "${ENROLLMENT_TOKEN}" ]]; then
    arguments+=(--enroll-token-file "${WORKDIR}/enroll.token")
  fi
  if [[ "${SERVER_CA_INCLUDED}" -eq 1 ]]; then
    arguments+=(--ca-file "${WORKDIR}/server-ca.crt")
  fi
  if [[ "${START_SERVICE}" -eq 1 ]]; then
    arguments+=(--start)
  else
    arguments+=(--no-start)
  fi
  bash "${PACKAGE_DIR}/install.sh" "${arguments[@]}"
}

run_upgrade() {
  local current="$1"
  log "replacing the installed release ${current} with ${AGENT_VERSION}"
  log 'endpoint identity, configuration and queued telemetry are preserved'
  local arguments=()
  if [[ "${ALLOW_DOWNGRADE}" -eq 1 ]]; then
    arguments+=(--allow-downgrade)
  fi
  bash "${PACKAGE_DIR}/upgrade.sh" "${arguments[@]}"
}

main() {
  parse_arguments "$@"
  log "installer schema ${SEAGULL_INSTALLER_SCHEMA} for ${AGENT_ID}: seagull-agent ${AGENT_VERSION} linux/${AGENT_ARCH} (${AGENT_PROFILE})"
  preflight
  unpack
  resolve_dependencies
  write_credentials
  local current
  current="$(installed_release)"
  if [[ -n "${current}" && "${current}" != "${AGENT_VERSION}" ]]; then
    run_upgrade "${current}"
  else
    run_install
  fi
  log "endpoint ${AGENT_ID} provisioned against ${API_URL}"
}

main "$@"
exit 0
"""


@dataclass(frozen=True)
class InstallerSpec:
    agent_id: str
    profile: str
    sources: Sequence[str]
    api_url: str
    enroll_url: str
    enrollment_token: str
    package: PackageRef
    server_ca_pem: Optional[str] = None


def filename(*, agent_id: str, architecture: str) -> str:
    return f"seagull-agent-{agent_id}-{architecture}-installer.sh"


def _server_ca_function(pem: Optional[str]) -> str:
    if not pem:
        return "write_server_ca() {\n  return 0\n}\n"
    body = pem.strip("\n")
    if any(line.strip() == _CA_HEREDOC for line in body.splitlines()):
        raise ValueError("the server certificate authority bundle is malformed")
    return f"write_server_ca() {{\n  cat > \"$1\" <<'{_CA_HEREDOC}'\n{body}\n{_CA_HEREDOC}\n}}\n"


def _assignments(spec: InstallerSpec) -> str:
    package_name = spec.package.filename[: -len(".tar.gz")]
    values = (
        ("SEAGULL_INSTALLER_SCHEMA", str(SCHEMA_VERSION)),
        ("AGENT_ID", spec.agent_id),
        ("AGENT_PROFILE", spec.profile),
        ("AGENT_SOURCES", ",".join(spec.sources)),
        ("AGENT_VERSION", spec.package.version),
        ("AGENT_ARCH", spec.package.architecture),
        ("API_URL", spec.api_url),
        ("ENROLL_URL", spec.enroll_url),
        ("PACKAGE_NAME", package_name),
        ("PACKAGE_SHA256", spec.package.sha256),
        ("SERVER_CA_INCLUDED", "1" if spec.server_ca_pem else "0"),
        ("EMBEDDED_ENROLLMENT_TOKEN", spec.enrollment_token),
    )
    lines = [f"{name}={quote(value)}" for name, value in values]
    lines.append('ENROLLMENT_TOKEN="${SEAGULL_ENROLLMENT_TOKEN:-${EMBEDDED_ENROLLMENT_TOKEN}}"')
    return "\n".join(lines) + "\n"


def _payload(package: bytes) -> str:
    encoded = base64.b64encode(package).decode("ascii")
    return "\n".join(encoded[index : index + _BASE64_WIDTH] for index in range(0, len(encoded), _BASE64_WIDTH))


def render(spec: InstallerSpec, package: bytes) -> bytes:
    script = "".join(
        (
            "#!/usr/bin/env bash\n",
            "set -euo pipefail\n\n",
            _assignments(spec),
            "\n",
            _server_ca_function(spec.server_ca_pem),
            _BODY,
            f"\n{_PAYLOAD_MARKER}\n",
            _payload(package),
            "\n",
        )
    )
    return script.encode("utf-8")
