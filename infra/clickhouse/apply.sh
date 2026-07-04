#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCHEMA_DIR="${SCRIPT_DIR}/schema"

if [[ -f "${REPO_ROOT}/.env" ]]; then
    while IFS='=' read -r key value; do
        key="${key#export }"
        [[ "${key}" == SEAGULL_CLICKHOUSE_* ]] || continue
        [[ -n "${!key:-}" ]] && continue
        value="${value%\"}"
        value="${value#\"}"
        export "${key}=${value}"
    done < <(grep -E '^(export )?SEAGULL_CLICKHOUSE_[A-Z_]+=' "${REPO_ROOT}/.env" || true)
fi

CH_HOST="${SEAGULL_CLICKHOUSE_HOST:-}"
CH_PORT="${SEAGULL_CLICKHOUSE_PORT:-8123}"
CH_DB="${SEAGULL_CLICKHOUSE_DATABASE:-seagull}"
CH_USER="${SEAGULL_CLICKHOUSE_USERNAME:-default}"
CH_PASSWORD="${SEAGULL_CLICKHOUSE_PASSWORD:-}"
CH_SECURE="${SEAGULL_CLICKHOUSE_SECURE:-false}"

if [[ ! "${CH_DB}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "invalid database name: ${CH_DB}" >&2
    exit 1
fi

# "clickhouse" is the compose-internal hostname: unreachable from the host, so it means local mode.
MODE="remote"
if [[ -z "${CH_HOST}" || "${CH_HOST}" == "clickhouse" ]]; then
    MODE="local"
fi

run_query() {
    local query="$1"
    local database="${2:-}"
    if [[ "${MODE}" == "local" ]]; then
        local args=(clickhouse-client --user "${CH_USER}")
        [[ -n "${CH_PASSWORD}" ]] && args+=(--password "${CH_PASSWORD}")
        [[ -n "${database}" ]] && args+=(--database "${database}")
        docker compose -f "${REPO_ROOT}/compose.yml" exec -T clickhouse "${args[@]}" --query "${query}" < /dev/null
    else
        local scheme="http"
        [[ "${CH_SECURE}" == "true" || "${CH_SECURE}" == "1" ]] && scheme="https"
        local url="${scheme}://${CH_HOST}:${CH_PORT}/"
        [[ -n "${database}" ]] && url="${url}?database=${database}"
        curl -fsS -X POST "${url}" \
            -H "X-ClickHouse-User: ${CH_USER}" \
            -H "X-ClickHouse-Key: ${CH_PASSWORD}" \
            --data-binary "${query}"
    fi
}

echo "mode=${MODE} database=${CH_DB} host=${CH_HOST:-compose} port=${CH_PORT}"

run_query "CREATE DATABASE IF NOT EXISTS ${CH_DB}"

applied=0
for file in "${SCHEMA_DIR}"/*.sql; do
    [[ -e "${file}" ]] || { echo "no schema files found in ${SCHEMA_DIR}" >&2; exit 1; }
    echo "applying $(basename "${file}")"
    while IFS= read -r -d '' statement; do
        [[ -n "${statement//[$' \t\n']/}" ]] || continue
        run_query "${statement}" "${CH_DB}"
        applied=$((applied + 1))
    done < <(awk 'BEGIN{stmt=""} /^[[:space:]]*--/{next} {stmt = stmt $0 "\n"} /;[[:space:]]*$/{printf "%s%c", stmt, 0; stmt=""}' "${file}")
done

mv_count="$(run_query "SELECT count() FROM system.tables WHERE database = '${CH_DB}' AND engine = 'MaterializedView'")"
echo "applied ${applied} statements; materialized views in ${CH_DB}: ${mv_count}"
