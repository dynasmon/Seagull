#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../backend"

export SEAGULL_SKIP_STARTUP_BOOTSTRAP="${SEAGULL_SKIP_STARTUP_BOOTSTRAP:-true}"
export SEAGULL_JWT_SECRET="${SEAGULL_JWT_SECRET:-ci-backend-quality-gate-jwt-secret-rotate-me}"
export SEAGULL_DB_URL="${SEAGULL_DB_URL:-postgresql://seagull:seagull@127.0.0.1:5432/seagull}"

ACCEPTED_ADVISORIES="pip-audit-accepted.txt"

run() {
  echo "::: $1"
  shift
  "$@"
}

audit_args=(-r requirements.lock --strict --progress-spinner off)
if [ -f "$ACCEPTED_ADVISORIES" ]; then
  while read -r advisory; do
    advisory="${advisory%%[[:space:]]*}"
    [ -z "$advisory" ] && continue
    audit_args+=(--ignore-vuln "$advisory")
  done < "$ACCEPTED_ADVISORIES"
fi

run "ruff" python -m ruff check app tests
run "import-linter" lint-imports
run "pytest" python -m pytest tests
run "pip-audit" python -m pip_audit "${audit_args[@]}"

echo "::: backend quality gate passed"
