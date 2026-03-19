#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[preflight] missing required command: $1" >&2
    exit 1
  }
}

need_cmd docker
need_cmd openssl
need_cmd curl
need_cmd jq

docker compose version >/dev/null 2>&1 || {
  echo "[preflight] docker compose plugin is not available" >&2
  exit 1
}

docker info >/dev/null 2>&1 || {
  echo "[preflight] docker daemon is not reachable (is Docker running?)" >&2
  exit 1
}

"$ROOT_DIR/scripts/bootstrap_env.sh" "$ROOT_DIR/.env" "$ROOT_DIR/.env.example" >/dev/null

docker compose -f docker-compose.yml -f compose.dev.yml config -q >/dev/null

echo "[preflight] ok: docker, compose, openssl, curl, jq and compose config are ready"
