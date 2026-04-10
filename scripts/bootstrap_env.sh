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

# Drop deprecated keys that can break current startup flags.
# Keep this list short and only for vars we explicitly retire.
deprecated_removed=0
for deprecated_key in COMPOSE_IGNORE_ORPHANS; do
  if grep -qE "^${deprecated_key}=" "$ENV_FILE"; then
    tmp_clean="$(mktemp)"
    awk -v key="$deprecated_key" '!($0 ~ "^[[:space:]]*" key "=")' "$ENV_FILE" > "$tmp_clean"
    mv "$tmp_clean" "$ENV_FILE"
    deprecated_removed=$((deprecated_removed + 1))
  fi
done

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

if [[ $deprecated_removed -gt 0 ]]; then
  echo "[bootstrap] removed $deprecated_removed deprecated var(s) from $ENV_FILE"
fi
