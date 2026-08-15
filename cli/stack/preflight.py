from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from pathlib import Path

from ..config import env as _env
from ..security import tls as _tls
from ..security import secrets as _secrets
from . import compose as _compose

MIN_SIGNER_TOKEN_LENGTH = 32
SIGNER_TOKEN_BYTES = 32

INTERNAL_PORT_VARS = (
    "SEAGULL_BACKEND_PORT",
    "SEAGULL_PORTAL_PORT",
    "ELASTICSEARCH_PORT",
    "KIBANA_PORT",
    "CLICKHOUSE_HTTP_PORT",
    "CLICKHOUSE_NATIVE_PORT",
    "SEAGULL_REDPANDA_KAFKA_PORT",
    "SEAGULL_REDPANDA_ADMIN_PORT",
)


def _is_loopback_publish(value: str) -> bool:
    spec = value.strip()
    if not spec:
        return True
    host, separator, _ = spec.rpartition(":")
    if not separator:
        return False
    host = host.strip().strip("[]")
    if host in ("localhost", ""):
        return host == "localhost"
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def exposed_internal_ports() -> list[str]:
    return [name for name in INTERNAL_PORT_VARS if not _is_loopback_publish(_env.read(name, ""))]


def _check_internal_exposure() -> None:
    exposed = exposed_internal_ports()
    if not exposed:
        return
    listed = ", ".join(exposed)
    if _env.is_production():
        raise RuntimeError(
            f"[preflight] these ports are published outside loopback: {listed}. "
            f"In production only the edge listeners face the network — bind them to "
            f"127.0.0.1 (e.g. SEAGULL_BACKEND_PORT=127.0.0.1:8000) or leave them empty"
        )
    print(f"[preflight] warning: published outside loopback (dev only): {listed}")


def _resolve_signer_token() -> str:
    token = _env.read("SEAGULL_PKI_SIGNER_TOKEN", "")
    if token:
        return token
    location = _env.read("SEAGULL_PKI_SIGNER_TOKEN_FILE", "")
    if not location:
        return ""
    path = _abs(location)
    if not path.exists():
        raise RuntimeError(
            f"[preflight] SEAGULL_PKI_SIGNER_TOKEN_FILE points to missing file: {path}"
        )
    return path.read_text().strip()


def _ensure_signer_token() -> None:
    token = _resolve_signer_token()
    if not token:
        _env.upsert("SEAGULL_PKI_SIGNER_TOKEN", _secrets.generate(SIGNER_TOKEN_BYTES))
        print("[preflight] generated SEAGULL_PKI_SIGNER_TOKEN for the certificate authority")
        return
    if len(token) < MIN_SIGNER_TOKEN_LENGTH:
        raise RuntimeError(
            f"[preflight] SEAGULL_PKI_SIGNER_TOKEN must be at least {MIN_SIGNER_TOKEN_LENGTH} characters"
        )


def _require_cmd(name: str) -> None:
    if not shutil.which(name):
        raise RuntimeError(
            f"[preflight] missing required command: {name} — fix: ./seagull -d --install"
        )


def _check_caddyfile_mtls(caddy_cfg: Path) -> None:
    if "client_auth" not in caddy_cfg.read_text():
        raise RuntimeError(
            f"[preflight] {caddy_cfg.name} does not enable mTLS (no client_auth block); "
            f"set SEAGULL_MTLS_ENABLED=false to disable agent mTLS, or use a Caddyfile "
            f"that enforces client certificates on the agent listener"
        )


def _check_caddyfile_port(caddy_cfg: Path, https_port: int) -> None:
    if caddy_cfg.is_dir():
        raise RuntimeError(
            f"[preflight] SEAGULL_CADDY_CONFIG_FILE is a directory, not a file: {caddy_cfg}"
        )
    if not caddy_cfg.exists():
        raise RuntimeError(
            f"[preflight] SEAGULL_CADDY_CONFIG_FILE not found: {caddy_cfg}"
        )
    if https_port == 443:
        return
    text = caddy_cfg.read_text()
    site_with_port = re.search(rf"(?:^|\s)\S*:{https_port}\s*\{{", text, re.MULTILINE)
    global_https_port = re.search(rf"https_port\s+{https_port}", text)
    if not site_with_port and not global_https_port:
        raise RuntimeError(
            f"[preflight] {caddy_cfg.name} does not bind HTTPS on port {https_port} "
            f"(SEAGULL_CADDY_HTTPS_INTERNAL_PORT={https_port}). "
            f"Set SEAGULL_CADDY_CONFIG_FILE=./infra/caddy/Caddyfile.dev in .env"
        )


def _abs(p: str) -> Path:
    path = Path(p)
    return path if path.is_absolute() else _env.root() / path


def run() -> bool:
    for cmd in ("docker", "curl", "jq"):
        _require_cmd(cmd)

    if (
        subprocess.run(["docker", "compose", "version"], capture_output=True).returncode
        != 0
    ):
        raise RuntimeError(
            "[preflight] docker compose plugin is not available — fix: ./seagull -d --install"
        )

    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        raise RuntimeError(
            "[preflight] docker daemon is not reachable (is Docker running?)"
        )

    ev = _env.read

    mtls_enabled = ev("SEAGULL_MTLS_ENABLED", "true").lower() in ("true", "1")

    caddy_cfg = _abs(ev("SEAGULL_CADDY_CONFIG_FILE", "./infra/caddy/Caddyfile"))
    caddy_https_port = int(ev("SEAGULL_CADDY_HTTPS_INTERNAL_PORT", "8443") or "8443")
    _check_caddyfile_port(caddy_cfg, caddy_https_port)
    if mtls_enabled:
        _check_caddyfile_mtls(caddy_cfg)

    tls_cert = ev("SEAGULL_TLS_CERT_FILE", "./secrets/tls/tls.crt")
    tls_key = ev("SEAGULL_TLS_KEY_FILE", "./secrets/tls/tls.key")
    server_name = (
        ev("SEAGULL_AGENT_PUBLIC_HOST", "")
        or ev("SEAGULL_CADDY_DOMAIN", "localhost")
        or "localhost"
    )
    force_regen = ev("SEAGULL_FORCE_REGENERATE_CERTS", "false").lower() in ("true", "1")
    jwt_secret = ev("SEAGULL_JWT_SECRET", "")
    jwt_secret_file = ev("SEAGULL_JWT_SECRET_FILE", "")
    admin_user = ev("SEAGULL_BOOTSTRAP_ADMIN_USERNAME", "admin")
    admin_pass = ev("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD", "")
    admin_pass_file = ev("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD_FILE", "")

    if not jwt_secret and jwt_secret_file:
        jf = _abs(jwt_secret_file)
        if not jf.exists():
            raise RuntimeError(
                f"[preflight] SEAGULL_JWT_SECRET_FILE points to missing file: {jf}"
            )
        jwt_secret = jf.read_text().strip()

    if not admin_pass and admin_pass_file:
        af = _abs(admin_pass_file)
        if not af.exists():
            raise RuntimeError(
                f"[preflight] SEAGULL_BOOTSTRAP_ADMIN_PASSWORD_FILE points to missing file: {af}"
            )
        admin_pass = af.read_text().strip()

    if len(jwt_secret) < 32:
        raise RuntimeError(
            "[preflight] SEAGULL_JWT_SECRET must be at least 32 characters"
        )
    if not admin_pass:
        raise RuntimeError("[preflight] SEAGULL_BOOTSTRAP_ADMIN_PASSWORD must be set")

    err = _secrets.validate_password_policy(
        "SEAGULL_BOOTSTRAP_ADMIN_PASSWORD", admin_user, admin_pass
    )
    if err:
        raise RuntimeError(f"[preflight] {err}")

    abs_cert = _abs(tls_cert)
    abs_key = _abs(tls_key)
    if force_regen:
        _tls.generate_dev_cert(abs_cert, abs_key, server_name)

    if not abs_cert.exists() or not abs_key.exists():
        _tls.generate_dev_cert(abs_cert, abs_key, server_name)

    for label, path in [
        ("SEAGULL_TLS_CERT_FILE", abs_cert),
        ("SEAGULL_TLS_KEY_FILE", abs_key),
    ]:
        if path.is_dir():
            raise RuntimeError(
                f"[preflight] invalid {label}: expected file, got directory at {path}"
            )
        if not path.exists():
            raise RuntimeError(f"[preflight] missing {label} file at {path}")

    _tls.ensure_readable(abs_cert)
    _tls.harden_key_perms(abs_key)

    if not _tls.cert_has_san(abs_cert, server_name):
        _tls.generate_dev_cert(abs_cert, abs_key, server_name)

    for label, path in [
        ("SEAGULL_TLS_CERT_FILE", abs_cert),
        ("SEAGULL_TLS_KEY_FILE", abs_key),
    ]:
        if not _tls.is_group_or_world_readable(path):
            raise RuntimeError(
                f"[preflight] {label} is not readable by the edge container at {path}; "
                f"run: chmod g+r {path}"
            )

    _check_internal_exposure()
    _ensure_signer_token()

    mtls_reissued = False
    if mtls_enabled:
        from ..security import pki as _pki

        mtls_reissued = _pki.ensure("preflight")
    else:
        print(
            "[preflight] mTLS: disabled (SEAGULL_MTLS_ENABLED=false); skipping agent PKI"
        )

    if not _compose.validate(_compose.STACK_FILES):
        raise RuntimeError("[preflight] docker compose config validation failed")

    print("[preflight] ok: docker, compose, curl, jq and compose config are ready")
    return mtls_reissued
