from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from . import env as _env


BINARY            = Path("/usr/local/bin/seagull-agent")
SERVICE_NAME      = "seagull-agent"
SERVICE_FILE      = Path("/etc/systemd/system/seagull-agent.service")
ENV_FILE          = Path("/etc/seagull/agent.env")
CA_DEFAULT        = Path("/etc/seagull/pki/root_ca.crt")
TOKEN_DEFAULT     = Path("/var/lib/seagull/bootstrap.token")
CREDENTIAL_DEFAULT = Path("/var/lib/seagull/agent.credential")


class ValidationError(Exception):
    pass


def _read_agent_env(key: str) -> str:
    try:
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith(f"{key}="):
                return line[len(key) + 1:].strip()
    except (PermissionError, OSError):
        pass
    return ""


def _env_readable() -> bool:
    try:
        ENV_FILE.read_bytes()
        return True
    except (PermissionError, OSError):
        return False


def _has_credential() -> bool:
    inline = _read_agent_env("SEAGULL_AGENT_CREDENTIAL")
    if inline:
        return True
    path = Path(_read_agent_env("SEAGULL_AGENT_CREDENTIAL_FILE") or str(CREDENTIAL_DEFAULT))
    return path.exists() and path.stat().st_size > 0


def _has_bootstrap_token() -> bool:
    if _read_agent_env("SEAGULL_AGENT_BOOTSTRAP_TOKEN"):
        return True
    path = Path(_read_agent_env("SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE") or str(TOKEN_DEFAULT))
    return path.exists()


def _service_enabled() -> bool:
    result = subprocess.run(
        ["systemctl", "is-enabled", "--quiet", SERVICE_NAME],
        capture_output=True,
    )
    return result.returncode == 0


def _service_active() -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", SERVICE_NAME],
        capture_output=True,
    )
    return result.returncode == 0


def is_installed() -> bool:
    """Return True only if the minimum installation requirements are met."""
    return BINARY.exists() and SERVICE_FILE.exists() and ENV_FILE.exists() and _service_enabled()


def validate() -> None:
    """Validate systemd agent installation and raise ValidationError if incomplete."""
    errors: list[str] = []
    warnings: list[str] = []

    if not BINARY.exists():
        errors.append(
            f"agent binary not found: {BINARY}\n"
            "  fix: ./seagull agent install-systemd"
        )

    if not SERVICE_FILE.exists():
        errors.append(
            f"service unit not installed: {SERVICE_FILE}\n"
            "  fix: ./seagull agent install-systemd"
        )
    else:
        if not _service_enabled():
            errors.append(
                f"service not enabled: {SERVICE_NAME}\n"
                "  fix: ./seagull agent install-systemd  (or: sudo systemctl enable seagull-agent)"
            )

    if not ENV_FILE.exists():
        errors.append(
            f"env file missing: {ENV_FILE}\n"
            "  fix: ./seagull agent install-systemd"
        )
    elif not _env_readable():
        warnings.append(
            f"{ENV_FILE} is not readable by current user — run as root for full validation"
        )
    else:
        api_url = _read_agent_env("SEAGULL_API_URL")
        if not api_url:
            errors.append(
                f"SEAGULL_API_URL not set in {ENV_FILE}\n"
                f"  fix: edit {ENV_FILE} and set SEAGULL_API_URL"
            )

        ca_file = Path(_read_agent_env("SEAGULL_TLS_CA_FILE") or str(CA_DEFAULT))
        if not ca_file.exists():
            errors.append(
                f"CA file missing: {ca_file}\n"
                "  fix: ./seagull agent install-systemd  (syncs CA from repo secrets)"
            )

        if not _has_credential() and not _has_bootstrap_token():
            errors.append(
                "no bootstrap token or credential found\n"
                "  fix: ./seagull agent tokens  then  ./seagull agent install-systemd"
            )

    for w in warnings:
        print(f"[systemd-agent] warning: {w}", file=sys.stderr)

    if errors:
        for err in errors:
            print(f"[systemd-agent] error: {err}", file=sys.stderr)
        raise ValidationError(
            f"systemd agent mode has {len(errors)} unresolved issue(s) — "
            "resolve them before running ./seagull up --agent-mode systemd"
        )


def status() -> int:
    return subprocess.run(
        ["systemctl", "status", SERVICE_NAME, "--no-pager"]
    ).returncode


def restart() -> int:
    rc = subprocess.run(["sudo", "systemctl", "restart", SERVICE_NAME]).returncode
    if rc == 0:
        subprocess.run(["systemctl", "status", SERVICE_NAME, "--no-pager"])
    return rc


def install() -> int:
    script = _env.root() / "deploy" / "systemd" / "install-agent.sh"
    return subprocess.run(
        ["sudo", "env", "AUTO_START_IF_READY=1", "bash", str(script)],
        cwd=str(_env.root()),
    ).returncode
