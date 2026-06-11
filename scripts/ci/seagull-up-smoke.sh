#!/usr/bin/env bash
#
# End-to-end reproducibility smoke: bring the stack up from a clean checkout
# exactly like a fresh machine would, assert it becomes healthy, then tear down.
#
# Runs in CI (see .gitlab-ci.yml) and locally:  bash scripts/ci/seagull-up-smoke.sh
#
# Requirements on the host/runner: docker + docker compose, python3, curl, jq.
# The repository directory must live on the same host as the Docker daemon
# (shell executor / self-hosted runner / local machine) because the stack uses
# bind mounts — plain docker:dind on shared runners cannot see the checkout.
set -euo pipefail

cd "$(dirname "$0")/../.."

MODE="${SEAGULL_MODE:-dev}"
export SEAGULL_SKIP_AGENT_RECONCILE="${SEAGULL_SKIP_AGENT_RECONCILE:-true}"
SMOKE_OK=0

dc() { docker compose -f compose.yml "$@"; }

cleanup() {
  echo "::: final container state :::"
  dc ps || true
  if [ "$SMOKE_OK" != "1" ]; then
    echo "::: smoke FAILED — recent logs :::"
    dc logs --no-color --tail=200 || true
  fi
  # In CI the environment is ephemeral, so wipe volumes for a clean slate.
  # Locally, keep volumes so a developer's data is never destroyed by the smoke.
  if [ -n "${CI:-}" ]; then
    echo "::: tearing down (down -v, CI) :::"
    dc down -v --remove-orphans || true
  else
    echo "::: tearing down (down, keeping volumes — local) :::"
    dc down --remove-orphans || true
  fi
}
trap cleanup EXIT

echo "::: host prerequisites :::"
missing=0
for cmd in docker python3 curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "  MISSING: $cmd"; missing=1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "  MISSING: docker compose plugin"; missing=1
fi
if [ "$missing" != "0" ]; then
  echo "host is missing required tooling; install it (./seagull -d --install) and retry" >&2
  exit 1
fi
docker info >/dev/null

echo "::: confirming a clean slate (no .env / secrets carried over) :::"
test ! -f .env && echo "  .env absent (will be bootstrapped from .env.example)" || echo "  NOTE: reusing existing .env"

echo "::: seagull up --mode $MODE :::"
python3 ./seagull up --mode "$MODE"

echo "::: backend liveness smoke (HTTP 200 on /health/live) :::"
dc exec -T seagull-backend python -c \
  "import sys,urllib.request; u=urllib.request.urlopen('http://127.0.0.1:8000/health/live',timeout=5); sys.exit(0 if u.getcode()==200 else 1)"

SMOKE_OK=1
echo "::: reproducibility smoke PASSED :::"
