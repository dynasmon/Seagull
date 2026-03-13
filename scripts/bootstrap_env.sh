#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-.env}"
TEMPLATE_FILE="${2:-.env.example}"

if [[ ! -f "$TEMPLATE_FILE" ]]; then
  echo "[bootstrap] template file not found: $TEMPLATE_FILE" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$TEMPLATE_FILE" "$ENV_FILE"
  echo "[bootstrap] created $ENV_FILE from $TEMPLATE_FILE"
  exit 0
fi

tmp_keys="$(mktemp)"
trap 'rm -f "$tmp_keys"' EXIT

awk -F= '/^[A-Za-z_][A-Za-z0-9_]*=/{print $1}' "$ENV_FILE" > "$tmp_keys"

added=0
while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in
    [A-Za-z_][A-Za-z0-9_]*=*)
      key="${line%%=*}"
      if ! grep -Fxq "$key" "$tmp_keys"; then
        if [[ $added -eq 0 ]]; then
          printf '\n# --- Auto-added from %s on %s ---\n' "$TEMPLATE_FILE" "$(date +%F)" >> "$ENV_FILE"
        fi
        printf '%s\n' "$line" >> "$ENV_FILE"
        printf '%s\n' "$key" >> "$tmp_keys"
        added=$((added + 1))
      fi
      ;;
  esac
done < "$TEMPLATE_FILE"

if [[ $added -gt 0 ]]; then
  echo "[bootstrap] synced $added missing vars from $TEMPLATE_FILE into $ENV_FILE"
else
  echo "[bootstrap] $ENV_FILE already up-to-date"
fi
