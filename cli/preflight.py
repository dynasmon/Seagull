from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from . import env as _env
from . import tls as _tls
from . import secrets as _secrets
from . import compose as _compose


def _require_cmd(name: str) -> None:
    if not shutil.which(name):
        raise RuntimeError(f"[preflight] missing required command: {name}")


def _abs(p: str) -> Path:
    path = Path(p)
    return path if path.is_absolute() else _env.root() / path


def run() -> None:
    for cmd in ("docker", "openssl", "curl", "jq"):
        _require_cmd(cmd)

    if subprocess.run(["docker", "compose", "version"], capture_output=True).returncode != 0:
        raise RuntimeError("[preflight] docker compose plugin is not available")

    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        raise RuntimeError("[preflight] docker daemon is not reachable (is Docker running?)")

    _env.bootstrap()

    ev = _env.read
    tls_cert = ev("SEAGULL_TLS_CERT_FILE", "./secrets/tls/tls.crt")
    tls_key = ev("SEAGULL_TLS_KEY_FILE", "./secrets/tls/tls.key")
    agent_ca = ev("SEAGULL_AGENT_SERVER_CA_FILE", "./secrets/tls/ca.crt")
    server_name = ev("SEAGULL_AGENT_TLS_SERVER_NAME", "localhost")
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
        raise RuntimeError("[preflight] SEAGULL_JWT_SECRET must be at least 32 characters")
    if not admin_pass:
        raise RuntimeError("[preflight] SEAGULL_BOOTSTRAP_ADMIN_PASSWORD must be set")

    err = _secrets.validate_password_policy(
        "SEAGULL_BOOTSTRAP_ADMIN_PASSWORD", admin_user, admin_pass
    )
    if err:
        raise RuntimeError(f"[preflight] {err}")

    abs_cert = _abs(tls_cert)
    abs_key = _abs(tls_key)
    abs_ca = _abs(agent_ca)

    if force_regen:
        _tls.generate_dev_cert(abs_cert, abs_key, server_name)

    if not abs_cert.exists() or not abs_key.exists():
        _tls.generate_dev_cert(abs_cert, abs_key, server_name)

    if not abs_ca.exists() and abs_cert.exists():
        import shutil as _shutil
        abs_ca.parent.mkdir(parents=True, exist_ok=True)
        _shutil.copy(abs_cert, abs_ca)
        abs_ca.chmod(0o644)
        print(f"[preflight] seeded agent CA file from TLS certificate: {agent_ca}")

    for label, path in [
        ("SEAGULL_TLS_CERT_FILE", abs_cert),
        ("SEAGULL_TLS_KEY_FILE", abs_key),
        ("SEAGULL_AGENT_SERVER_CA_FILE", abs_ca),
    ]:
        if path.is_dir():
            raise RuntimeError(
                f"[preflight] invalid {label}: expected file, got directory at {path}"
            )
        if not path.exists():
            raise RuntimeError(f"[preflight] missing {label} file at {path}")

    _tls.ensure_readable(abs_cert)
    _tls.ensure_readable(abs_key)

    if not _tls.cert_has_san(abs_cert, server_name):
        _tls.generate_dev_cert(abs_cert, abs_key, server_name)

    for label, path in [
        ("SEAGULL_TLS_CERT_FILE", abs_cert),
        ("SEAGULL_TLS_KEY_FILE", abs_key),
        ("SEAGULL_AGENT_SERVER_CA_FILE", abs_ca),
    ]:
        if not _tls.is_group_or_world_readable(path):
            raise RuntimeError(
                f"[preflight] {label} is not readable by group/others at {path}; "
                f"run: chmod 644 {path}"
            )

    if not _compose.validate(_compose.STACK_FILES):
        raise RuntimeError("[preflight] docker compose config validation failed")

    print("[preflight] ok: docker, compose, openssl, curl, jq and compose config are ready")
