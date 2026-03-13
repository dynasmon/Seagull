#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$ROOT_DIR/scripts/bootstrap_env.sh" "$ROOT_DIR/.env" "$ROOT_DIR/.env.example"

exec docker compose "$@"
