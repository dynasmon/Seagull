from __future__ import annotations

import getpass
import sys

from . import env as _env
from ..security import secrets as _secrets


def _status(value: str, min_len: int) -> str:
    if not value:
        return "missing"
    if len(value) < min_len:
        return "weak"
    lower = value.lower().strip()
    for placeholder in ("change_me", "changeme", "seagull123", "example", "password", "secret"):
        if lower.startswith(placeholder):
            return "placeholder"
    return "ok"


def _prompt(msg: str, default: str = "") -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        val = input(f"{msg}{suffix}: ").strip()
        if val:
            return val
        if default:
            return default


def _prompt_optional(msg: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    return input(f"{msg}{suffix}: ").strip() or default


def _prompt_secret(label: str) -> str:
    while True:
        first = getpass.getpass(f"{label}: ")
        second = getpass.getpass(f"Confirm {label}: ")
        if first == second:
            return first
        print("Values did not match. Try again.")


def _choose_secret(key: str, min_len: int, gen_bytes: int, label: str) -> str:
    current = _env.read(key)
    st = _status(current, min_len)

    if st == "ok":
        print(f"[env-wizard] {key} already set (<hidden>, {len(current)} chars)")
        while True:
            choice = input(
                f"Keep current {label}, generate a new one, or type manually? [K/g/m]: "
            ).strip().lower()
            if choice in ("", "k"):
                return current
            if choice == "g":
                return _secrets.generate(gen_bytes)
            if choice == "m":
                while True:
                    val = _prompt_secret(label)
                    if len(val) >= min_len:
                        return val
                    print(f"{label} must be at least {min_len} characters.")
    else:
        print(f"[env-wizard] {key} is {st} and must be updated")
        while True:
            choice = input(
                f"Generate a strong {label} automatically or type it manually? [G/m]: "
            ).strip().lower()
            if choice in ("", "g"):
                return _secrets.generate(gen_bytes)
            if choice == "m":
                while True:
                    val = _prompt_secret(label)
                    if len(val) >= min_len:
                        return val
                    print(f"{label} must be at least {min_len} characters.")


def _normalize_csv(*parts: str) -> str:
    seen: list[str] = []
    for chunk in parts:
        for item in chunk.split(","):
            item = item.strip()
            if item and item not in seen:
                seen.append(item)
    return ",".join(seen)


def run() -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("[env-wizard] interactive TTY required")

    _env.bootstrap()

    ev = _env.read
    default_domain = ev("SEAGULL_AGENT_PUBLIC_HOST", "") or ev("SEAGULL_CADDY_DOMAIN", "")
    if not default_domain or default_domain in ("localhost", "127.0.0.1"):
        for part in ev("SEAGULL_ALLOWED_HOSTS_PROD", "").split(","):
            part = part.strip()
            if part and part not in ("localhost", "127.0.0.1"):
                default_domain = part
                break

    print()
    print("Seagull production environment wizard")
    print("This updates critical values inside .env")
    print()

    public_domain = _prompt(
        "Primary public hostname for the portal/edge (no scheme, no port)", default_domain
    )
    extra_hosts = _prompt_optional(
        "Additional hostnames or IPs for Allowed Hosts / SANs (comma-separated, optional)"
    )
    admin_user = _prompt(
        "Bootstrap admin username", ev("SEAGULL_BOOTSTRAP_ADMIN_USERNAME", "") or "admin"
    )

    postgres_password = _choose_secret("POSTGRES_PASSWORD", 12, 24, "PostgreSQL password")
    redis_password = _choose_secret("SEAGULL_REDIS_PASSWORD", 12, 24, "Redis password")
    es_password = _choose_secret("SEAGULL_ES_PASSWORD", 12, 24, "Elasticsearch password")
    jwt_secret = _choose_secret("SEAGULL_JWT_SECRET", 32, 48, "JWT secret")
    admin_password = _choose_secret(
        "SEAGULL_BOOTSTRAP_ADMIN_PASSWORD", 12, 24, "bootstrap admin password"
    )
    grafana_password = _prompt_optional(
        "Grafana admin password (optional; used only with observability profile)",
        ev("GF_SECURITY_ADMIN_PASSWORD", ""),
    )

    allowed_hosts = _normalize_csv(public_domain, extra_hosts, "localhost", "127.0.0.1")

    _env.upsert("SEAGULL_BOOTSTRAP_ADMIN_USERNAME", admin_user)
    _env.upsert("POSTGRES_PASSWORD", postgres_password)
    _env.upsert("SEAGULL_REDIS_PASSWORD", redis_password)
    _env.upsert("SEAGULL_ES_PASSWORD", es_password)
    _env.upsert("SEAGULL_JWT_SECRET", jwt_secret)
    _env.upsert("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD", admin_password)
    _env.upsert("GF_SECURITY_ADMIN_PASSWORD", grafana_password)
    _env.upsert("SEAGULL_ALLOWED_HOSTS_PROD", allowed_hosts)
    _env.upsert("SEAGULL_AGENT_PUBLIC_HOST", public_domain)
    _env.upsert("SEAGULL_CADDY_DOMAIN", public_domain)

    print()
    print("[env-wizard] updated keys:")
    print(f"  SEAGULL_BOOTSTRAP_ADMIN_USERNAME={admin_user}")
    print(f"  SEAGULL_ALLOWED_HOSTS_PROD={allowed_hosts}")
    print(f"  SEAGULL_AGENT_PUBLIC_HOST={public_domain}")
    print(f"  SEAGULL_CADDY_DOMAIN={public_domain}")
    print("  POSTGRES_PASSWORD=<hidden>")
    print("  SEAGULL_REDIS_PASSWORD=<hidden>")
    print("  SEAGULL_ES_PASSWORD=<hidden>")
    print("  SEAGULL_JWT_SECRET=<hidden>")
    print("  SEAGULL_BOOTSTRAP_ADMIN_PASSWORD=<hidden>")
    if grafana_password:
        print("  GF_SECURITY_ADMIN_PASSWORD=<hidden> (optional observability profile)")
    else:
        print("  GF_SECURITY_ADMIN_PASSWORD=<empty> (observability profile disabled by default)")
    print()
    print("[env-wizard] next steps:")
    print("  1. ./seagull env prepare")
    print("  2. ./seagull prod")
