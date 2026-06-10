#!/usr/bin/env bash
set -euo pipefail

GO_MIN_MINOR=21
GO_FALLBACK_VERSION=1.22.12

log() {
  echo "[install-deps] $*"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    log "run as root (or via: ./seagull -d --install)"
    exit 1
  fi
}

detect_os() {
  if [[ ! -r /etc/os-release ]]; then
    log "cannot detect distribution: /etc/os-release missing"
    exit 1
  fi
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_LIKE="${ID_LIKE:-}"
  OS_CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
}

pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo apt
    return
  fi
  if command -v dnf >/dev/null 2>&1; then
    echo dnf
    return
  fi
  echo unsupported
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

ensure_base_apt() {
  apt-get update -y
  apt_install ca-certificates curl jq git gnupg sudo gcc libc6-dev libpcap-dev libcap2-bin python3 python3-cryptography
}

ensure_base_dnf() {
  dnf -y install ca-certificates curl jq git sudo gcc libpcap-devel libcap python3 python3-cryptography
}

ensure_docker_apt() {
  if ! command -v docker >/dev/null 2>&1; then
    if [[ ( "${OS_ID}" == "ubuntu" || "${OS_ID}" == "debian" ) && -n "${OS_CODENAME}" ]]; then
      install -m 0755 -d /etc/apt/keyrings
      curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" -o /etc/apt/keyrings/docker.asc
      chmod a+r /etc/apt/keyrings/docker.asc
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${OS_ID} ${OS_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
      apt-get update -y
      apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    else
      apt_install docker.io docker-compose-v2 || apt_install docker.io
    fi
    log "installed docker"
  fi
  if ! docker compose version >/dev/null 2>&1; then
    apt_install docker-compose-plugin || apt_install docker-compose-v2
  fi
}

ensure_docker_dnf() {
  if ! command -v docker >/dev/null 2>&1; then
    local repo_os=centos
    if [[ "${OS_ID}" == "fedora" ]]; then
      repo_os=fedora
    fi
    dnf -y install dnf-plugins-core || true
    dnf config-manager --add-repo "https://download.docker.com/linux/${repo_os}/docker-ce.repo" \
      || dnf config-manager addrepo --from-repofile="https://download.docker.com/linux/${repo_os}/docker-ce.repo"
    dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    log "installed docker"
  fi
}

go_minor() {
  if ! command -v go >/dev/null 2>&1; then
    return 0
  fi
  go version | sed -n 's/.*go1\.\([0-9][0-9]*\).*/\1/p'
}

ensure_go() {
  local mgr="$1"
  local minor
  minor="$(go_minor || true)"
  if [[ -n "${minor}" && "${minor}" -ge "${GO_MIN_MINOR}" ]]; then
    return
  fi

  if [[ "${mgr}" == "apt" ]]; then
    apt_install golang-go || true
  else
    dnf -y install golang || true
  fi

  minor="$(go_minor || true)"
  if [[ -n "${minor}" && "${minor}" -ge "${GO_MIN_MINOR}" ]]; then
    return
  fi

  local arch
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *)
      log "unsupported architecture for go tarball: $(uname -m)"
      exit 1
      ;;
  esac

  log "installing go ${GO_FALLBACK_VERSION} from go.dev"
  curl -fsSL "https://go.dev/dl/go${GO_FALLBACK_VERSION}.linux-${arch}.tar.gz" -o /tmp/seagull-go.tar.gz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/seagull-go.tar.gz
  rm -f /tmp/seagull-go.tar.gz
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
}

enable_docker_service() {
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl enable --now docker || true
  fi
}

ensure_docker_group() {
  local target="${SUDO_USER:-}"
  if [[ -z "${target}" || "${target}" == "root" ]]; then
    return
  fi
  if id -nG "${target}" | tr ' ' '\n' | grep -qx docker; then
    return
  fi
  usermod -aG docker "${target}"
  log "added ${target} to the docker group"
  log "log out and back in (or run: newgrp docker) before ./seagull up"
}

main() {
  require_root
  detect_os
  local mgr
  mgr="$(pkg_manager)"
  case "${mgr}" in
    apt)
      ensure_base_apt
      ensure_docker_apt
      ;;
    dnf)
      ensure_base_dnf
      ensure_docker_dnf
      ;;
    *)
      log "unsupported package manager"
      log "install manually: docker engine + compose plugin, curl, jq, git, gcc, libpcap headers, libcap (setcap), go >= 1.${GO_MIN_MINOR}, python3 cryptography"
      exit 1
      ;;
  esac
  ensure_go "${mgr}"
  enable_docker_service
  ensure_docker_group
  log "done"
}

main "$@"
