#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROM_IMAGE="${PROM_IMAGE:-prom/prometheus:v2.55.1}"

docker run --rm --entrypoint promtool \
  -v "${SCRIPT_DIR}:/cfg:ro" \
  "${PROM_IMAGE}" check config /cfg/prometheus.yml

docker run --rm --entrypoint sh \
  -v "${SCRIPT_DIR}:/cfg:ro" \
  "${PROM_IMAGE}" -c 'promtool check rules /cfg/rules/*.yml'
