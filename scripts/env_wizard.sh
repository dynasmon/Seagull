#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${ENV_FILE:-.env}"
ENV_EXAMPLE="${ENV_EXAMPLE:-.env.example}"
BOOTSTRAP_SCRIPT="./scripts/bootstrap_env.sh"

if [ ! -f "$ENV_FILE" ]; then
  if [ -x "$BOOTSTRAP_SCRIPT" ]; then
    "$BOOTSTRAP_SCRIPT" "$ENV_FILE" "$ENV_EXAMPLE"
  else
    echo "[env-wizard] missing $ENV_FILE and bootstrap script is not executable" >&2
    exit 1
  fi
fi

if [ ! -t 0 ] || [ ! -t 1 ]; then
  echo "[env-wizard] interactive TTY required" >&2
  exit 1
fi

TTY_IN="/dev/tty"
TTY_OUT="/dev/tty"

trim() {
  printf '%s' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

tty_printf() {
  printf "$@" >"$TTY_OUT"
}

tty_println() {
  printf '%s\n' "$1" >"$TTY_OUT"
}

tty_read_line() {
  IFS= read -r line <"$TTY_IN"
  printf '%s' "$line"
}

env_read() {
  key="$1"
  awk -F= -v k="$key" '$1==k{line=$0; sub(/^[^=]*=/, "", line); print line}' "$ENV_FILE" | tail -n1 | tr -d '\r'
}

env_upsert() {
  key="$1"
  value="$2"
  python3 - "$ENV_FILE" "$key" "$value" <<'PY'
from pathlib import Path
import sys

env_path = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]

lines = env_path.read_text().splitlines()
out = []
found = False

for line in lines:
    if line.startswith(f"{key}="):
        out.append(f"{key}={value}")
        found = True
    else:
        out.append(line)

if not found:
    if out and out[-1].strip() != "":
        out.append("")
    out.append(f"{key}={value}")

env_path.write_text("\n".join(out) + "\n")
PY
}

gen_secret() {
  bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "$bytes" | tr -d '\n'
  else
    python3 - "$bytes" <<'PY'
import secrets
import sys
print(secrets.token_urlsafe(int(sys.argv[1])))
PY
  fi
}

secret_status() {
  value="$1"
  min_len="$2"

  if [ -z "$value" ]; then
    printf 'missing'
    return 0
  fi

  if [ "${#value}" -lt "$min_len" ]; then
    printf 'weak'
    return 0
  fi

  case "$value" in
    change_me*|CHANGE_ME*|changeme*|netwatch123|example*|password*|secret*)
      printf 'placeholder'
      return 0
      ;;
  esac

  printf 'ok'
}

prompt_line() {
  prompt="$1"
  default_value="$2"

  while :; do
    if [ -n "$default_value" ]; then
      tty_printf "%s [%s]: " "$prompt" "$default_value"
    else
      tty_printf "%s: " "$prompt"
    fi

    answer="$(tty_read_line)"
    answer="$(trim "$answer")"

    if [ -n "$answer" ]; then
      printf '%s' "$answer"
      return 0
    fi

    if [ -n "$default_value" ]; then
      printf '%s' "$default_value"
      return 0
    fi
  done
}

prompt_optional_line() {
  prompt="$1"
  default_value="$2"

  if [ -n "$default_value" ]; then
    tty_printf "%s [%s]: " "$prompt" "$default_value"
  else
    tty_printf "%s: " "$prompt"
  fi

  answer="$(tty_read_line)"
  answer="$(trim "$answer")"

  if [ -n "$answer" ]; then
    printf '%s' "$answer"
    return 0
  fi

  printf '%s' "$default_value"
}

prompt_secret_hidden() {
  prompt="$1"

  while :; do
    tty_printf "%s: " "$prompt"
    stty -echo <"$TTY_IN"
    IFS= read -r first <"$TTY_IN"
    stty echo <"$TTY_IN"
    tty_printf "\n"

    tty_printf "Confirm %s: " "$prompt"
    stty -echo <"$TTY_IN"
    IFS= read -r second <"$TTY_IN"
    stty echo <"$TTY_IN"
    tty_printf "\n"

    if [ "$first" = "$second" ]; then
      printf '%s' "$first"
      return 0
    fi

    tty_println "Values did not match. Try again."
  done
}

normalize_csv() {
  python3 - "$@" <<'PY'
import sys

items = []
for chunk in sys.argv[1:]:
    for part in chunk.split(','):
        part = part.strip()
        if part and part not in items:
            items.append(part)

print(",".join(items))
PY
}

choose_secret() {
  key="$1"
  min_len="$2"
  bytes="$3"
  label="$4"

  current_value="$(env_read "$key")"
  status="$(secret_status "$current_value" "$min_len")"

  case "$status" in
    ok)
      tty_println "[env-wizard] $key already set (<hidden>, ${#current_value} chars)"
      while :; do
        tty_printf "Keep current %s, generate a new one, or type manually? [K/g/m]: " "$label"
        choice="$(tty_read_line)"
        choice="$(trim "$choice")"

        case "$choice" in
          ''|K|k)
            printf '%s' "$current_value"
            return 0
            ;;
          g|G)
            gen_secret "$bytes"
            return 0
            ;;
          m|M)
            while :; do
              manual="$(prompt_secret_hidden "$label")"
              if [ "${#manual}" -lt "$min_len" ]; then
                tty_println "$label must be at least $min_len characters."
                continue
              fi
              printf '%s' "$manual"
              return 0
            done
            ;;
        esac
      done
      ;;
    *)
      tty_println "[env-wizard] $key is $status and must be updated"
      while :; do
        tty_printf "Generate a strong %s automatically or type it manually? [G/m]: " "$label"
        choice="$(tty_read_line)"
        choice="$(trim "$choice")"

        case "$choice" in
          ''|G|g)
            gen_secret "$bytes"
            return 0
            ;;
          m|M)
            while :; do
              manual="$(prompt_secret_hidden "$label")"
              if [ "${#manual}" -lt "$min_len" ]; then
                tty_println "$label must be at least $min_len characters."
                continue
              fi
              printf '%s' "$manual"
              return 0
            done
            ;;
        esac
      done
      ;;
  esac
}

default_domain="$(env_read 'NETWATCH_AGENT_TLS_SERVER_NAME')"
case "$default_domain" in
  ''|localhost|127.0.0.1)
    default_domain="$(python3 - "$ENV_FILE" <<'PY'
from pathlib import Path
import sys

value = ""
for line in Path(sys.argv[1]).read_text().splitlines():
    if line.startswith("NETWATCH_ALLOWED_HOSTS_PROD="):
        value = line.split("=", 1)[1]
        break

for part in [x.strip() for x in value.split(",") if x.strip()]:
    if part not in {"localhost", "127.0.0.1"}:
        print(part)
        break
PY
)"
    ;;
esac

[ -n "$default_domain" ] || default_domain=""

tty_printf "\n"
tty_println "NetWatch production environment wizard"
tty_println "This updates critical values inside $ENV_FILE."
tty_printf "\n"

public_domain="$(prompt_line 'Primary public hostname for the portal/edge (no scheme, no port)' "$default_domain")"
extra_hosts="$(prompt_optional_line 'Additional hostnames or IPs for Allowed Hosts / SANs (comma-separated, optional)' '')"

admin_user_default="$(env_read 'NETWATCH_BOOTSTRAP_ADMIN_USERNAME')"
[ -n "$admin_user_default" ] || admin_user_default="admin"
admin_user="$(prompt_line 'Bootstrap admin username' "$admin_user_default")"

postgres_password="$(choose_secret 'POSTGRES_PASSWORD' 12 24 'PostgreSQL password')"
redis_password="$(choose_secret 'NETWATCH_REDIS_PASSWORD' 12 24 'Redis password')"
es_password="$(choose_secret 'NETWATCH_ES_PASSWORD' 12 24 'Elasticsearch password')"
jwt_secret="$(choose_secret 'NETWATCH_JWT_SECRET' 32 48 'JWT secret')"
bootstrap_admin_password="$(choose_secret 'NETWATCH_BOOTSTRAP_ADMIN_PASSWORD' 12 24 'bootstrap admin password')"
grafana_admin_password="$(choose_secret 'GF_SECURITY_ADMIN_PASSWORD' 12 24 'Grafana admin password')"

allowed_hosts="$(normalize_csv "$public_domain,$extra_hosts,localhost,127.0.0.1")"
edge_cert_sans="$(normalize_csv "$public_domain,$extra_hosts,localhost,netwatch-edge,127.0.0.1")"
agent_tls_server_name="$public_domain"

env_upsert 'NETWATCH_BOOTSTRAP_ADMIN_USERNAME' "$admin_user"
env_upsert 'POSTGRES_PASSWORD' "$postgres_password"
env_upsert 'NETWATCH_REDIS_PASSWORD' "$redis_password"
env_upsert 'NETWATCH_ES_PASSWORD' "$es_password"
env_upsert 'NETWATCH_JWT_SECRET' "$jwt_secret"
env_upsert 'NETWATCH_BOOTSTRAP_ADMIN_PASSWORD' "$bootstrap_admin_password"
env_upsert 'GF_SECURITY_ADMIN_PASSWORD' "$grafana_admin_password"
env_upsert 'NETWATCH_ALLOWED_HOSTS_PROD' "$allowed_hosts"
env_upsert 'NETWATCH_AGENT_TLS_SERVER_NAME' "$agent_tls_server_name"
env_upsert 'NETWATCH_EDGE_CERT_SANS' "$edge_cert_sans"

tty_printf "\n"
tty_println "[env-wizard] updated keys:"
tty_println "  NETWATCH_BOOTSTRAP_ADMIN_USERNAME=$admin_user"
tty_println "  NETWATCH_ALLOWED_HOSTS_PROD=$allowed_hosts"
tty_println "  NETWATCH_AGENT_TLS_SERVER_NAME=$agent_tls_server_name"
tty_println "  NETWATCH_EDGE_CERT_SANS=$edge_cert_sans"
tty_println "  POSTGRES_PASSWORD=<hidden>"
tty_println "  NETWATCH_REDIS_PASSWORD=<hidden>"
tty_println "  NETWATCH_ES_PASSWORD=<hidden>"
tty_println "  NETWATCH_JWT_SECRET=<hidden>"
tty_println "  NETWATCH_BOOTSTRAP_ADMIN_PASSWORD=<hidden>"
tty_println "  GF_SECURITY_ADMIN_PASSWORD=<hidden>"
tty_printf "\n"
tty_println "[env-wizard] next steps:"
tty_println "  1. make prod-prepare"
tty_println "  2. make prod"