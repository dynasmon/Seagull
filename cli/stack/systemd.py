from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from ..config import env as _env


BINARY            = Path("/usr/local/bin/seagull-agent")
SERVICE_NAME      = "seagull-agent"
SERVICE_FILE      = Path("/etc/systemd/system/seagull-agent.service")
ENV_FILE          = Path("/etc/seagull/agent.env")
CA_DEFAULT        = Path("/etc/seagull/pki/root_ca.crt")
TOKEN_DEFAULT     = Path("/var/lib/seagull/bootstrap.token")
CREDENTIAL_DEFAULT = Path("/var/lib/seagull/agent.credential")
IDENTITY_STATE_DEFAULT = Path("/var/lib/seagull/agent.identity.json")

_AGENT_ENV_MAP: tuple[tuple[str, str], ...] = (
    ("AGENT_CORE_ID", "AGENT_CORE_BOOTSTRAP_TOKEN"),
    ("AGENT_SENSOR_ID", "AGENT_SENSOR_BOOTSTRAP_TOKEN"),
    ("AGENT_LATERAL_ID", "AGENT_LATERAL_BOOTSTRAP_TOKEN"),
    ("AGENT_PROC_ID", "AGENT_PROC_BOOTSTRAP_TOKEN"),
    ("AGENT_SCAN_ID", "AGENT_SCAN_BOOTSTRAP_TOKEN"),
    ("AGENT_DDOS_ID", "AGENT_DDOS_BOOTSTRAP_TOKEN"),
    ("AGENT_VULN_ID", "AGENT_VULN_BOOTSTRAP_TOKEN"),
)


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
    if path.exists() and path.stat().st_size > 0:
        return True
    identity_path = Path(_read_agent_env("SEAGULL_AGENT_IDENTITY_STATE_FILE") or str(IDENTITY_STATE_DEFAULT))
    return identity_path.exists() and identity_path.stat().st_size > 0


def _has_bootstrap_token() -> bool:
    if _read_agent_env("SEAGULL_AGENT_BOOTSTRAP_TOKEN"):
        return True
    path = Path(_read_agent_env("SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE") or str(TOKEN_DEFAULT))
    return path.exists()


def _parse_optional_timestamp(raw: str) -> datetime | None:
    text = (raw or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _identity_state_path() -> Path:
    return Path(_read_agent_env("SEAGULL_AGENT_IDENTITY_STATE_FILE") or str(IDENTITY_STATE_DEFAULT))


def _has_active_recovery_token() -> tuple[bool, str | None]:
    path = _identity_state_path()
    try:
        payload = json.loads(path.read_text())
    except FileNotFoundError:
        return False, None
    except PermissionError:
        return False, (
            f"identity state is not readable: {path}\n"
            "  fix: run ./seagull agent validate-systemd as root for full recovery validation"
        )
    except OSError as exc:
        return False, f"failed to read identity state: {path} ({exc})"
    except json.JSONDecodeError as exc:
        return False, f"identity state is not valid JSON: {path} ({exc})"

    if not isinstance(payload, dict):
        return False, f"identity state has invalid format: {path}"

    now = datetime.now(timezone.utc)
    candidates = (
        ("renewal_token", "renewal_token_expires_at"),
        ("previous_renewal_token", "previous_renewal_token_expires_at"),
    )
    for token_key, expires_key in candidates:
        token = str(payload.get(token_key) or "").strip()
        if not token:
            continue
        expires_at = _parse_optional_timestamp(str(payload.get(expires_key) or ""))
        if expires_at is None or expires_at > now:
            return True, None
    return False, None


def _is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}


def _validate_tls_server_name(api_url: str) -> str | None:
    parsed = urlparse(api_url)
    host = (parsed.hostname or "").strip().lower()
    if parsed.scheme != "https" or not _is_loopback_host(host):
        return None
    tls_server_name = (_read_agent_env("SEAGULL_TLS_SERVER_NAME") or "").strip().lower()
    if not tls_server_name or _is_loopback_host(tls_server_name):
        return None
    return (
        f"SEAGULL_TLS_SERVER_NAME={tls_server_name!r} is incompatible with loopback API host {host!r}\n"
        "  fix: set SEAGULL_TLS_SERVER_NAME=localhost or issue a certificate that includes that hostname"
    )


def _validate_live_tls(api_url: str, ca_file: Path) -> str | None:
    parsed = urlparse(api_url)
    host = (parsed.hostname or "").strip()
    if parsed.scheme != "https" or not host or not ca_file.exists():
        return None

    server_name = (_read_agent_env("SEAGULL_TLS_SERVER_NAME") or "").strip() or host
    port = parsed.port or 443
    try:
        context = ssl.create_default_context(cafile=str(ca_file))
    except ssl.SSLError as exc:
        return (
            f"failed to load agent CA file {ca_file}: {exc}\n"
            "  fix: replace SEAGULL_TLS_CA_FILE with a valid PEM certificate bundle"
        )

    cert_file = (_read_agent_env("SEAGULL_TLS_CERT_FILE") or "").strip()
    key_file = (_read_agent_env("SEAGULL_TLS_KEY_FILE") or "").strip()
    if cert_file and key_file:
        if not Path(cert_file).exists() or not Path(key_file).exists():
            return None
        try:
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        except (ssl.SSLError, OSError) as exc:
            return (
                f"failed to load mTLS client certificate {cert_file}: {exc}\n"
                "  fix: verify SEAGULL_TLS_CERT_FILE and SEAGULL_TLS_KEY_FILE form a valid keypair"
            )

    try:
        with socket.create_connection((host, port), timeout=2.5) as sock:
            with context.wrap_socket(sock, server_hostname=server_name):
                return None
    except ssl.SSLCertVerificationError as exc:
        verify_message = getattr(exc, "verify_message", "") or str(exc)
        return (
            f"TLS verification failed for {api_url} using server name {server_name!r}: {verify_message}\n"
            "  fix: align SEAGULL_TLS_SERVER_NAME with the certificate SANs or replace the server certificate"
        )
    except ssl.SSLError as exc:
        message = str(exc)
        # Caddy can briefly tear down loopback handshakes while the edge is restarting.
        if _is_loopback_host(host.strip().lower()) and "EOF occurred in violation of protocol" in message:
            return None
        return (
            f"TLS handshake failed for {api_url} using server name {server_name!r}: {message}\n"
            "  fix: verify the agent CA file and the server certificate chain"
        )
    except (ConnectionError, TimeoutError, OSError):
        return None


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


def is_active() -> bool:
    return _service_active()


def installed_agent_id() -> str:
    agent_id = (_read_agent_env("SEAGULL_AGENT_ID") or "").strip()
    if agent_id:
        return agent_id
    fallback = (_env.read("AGENT_CORE_ID", "agent-core-1") or "").strip()
    return fallback or "agent-core-1"


def repo_bootstrap_token_for_agent(agent_id: str) -> str:
    target = str(agent_id or "").strip()
    if not target:
        return ""

    token_file = _env.root() / "secrets" / "bootstrap" / f"{target}.token"
    try:
        token = token_file.read_text().strip()
        if token:
            return token
    except OSError:
        pass

    for agent_key, token_key in _AGENT_ENV_MAP:
        mapped_agent_id = (_env.read(agent_key, "") or "").strip()
        if mapped_agent_id != target:
            continue
        token = (_env.read(token_key, "") or "").strip()
        if token:
            return token
    return ""


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

        has_credential = _has_credential()
        has_bootstrap_token = _has_bootstrap_token()
        has_recovery_token, recovery_warning = _has_active_recovery_token()

        if recovery_warning:
            warnings.append(recovery_warning)

        tls_server_name_error = _validate_tls_server_name(api_url)
        if tls_server_name_error:
            errors.append(tls_server_name_error)
        live_tls_error = _validate_live_tls(api_url, ca_file)
        if live_tls_error:
            errors.append(live_tls_error)

        if not has_credential and not has_bootstrap_token:
            errors.append(
                "no bootstrap token or credential found\n"
                "  fix: ./seagull agent tokens  then  ./seagull agent install-systemd"
            )
        elif has_credential and not has_bootstrap_token and not has_recovery_token:
            errors.append(
                "credential present but no active bootstrap token or renewal token found\n"
                "  fix: issue a new bootstrap token or re-enroll the agent so it can recover after a 401/expiry"
            )

    for w in warnings:
        print(f"[systemd-agent] warning: {w}", file=sys.stderr)

    if errors:
        for err in errors:
            print(f"[systemd-agent] error: {err}", file=sys.stderr)
        raise ValidationError(
            f"systemd agent mode has {len(errors)} unresolved issue(s) — "
            "resolve them before running ./seagull up"
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


def sync_ca() -> int:
    script = _env.root() / "deploy" / "systemd" / "refresh-ca.sh"
    if not script.exists():
        print(f"[systemd-agent] warning: CA sync script not found: {script}", file=sys.stderr)
        return 1
    print("[systemd-agent] syncing CA certificate to agent...")
    return subprocess.run(["sudo", "bash", str(script)], cwd=str(_env.root())).returncode


def install(*, bootstrap_token: str | None = None) -> int:
    script = _env.root() / "deploy" / "systemd" / "install-agent.sh"
    token = str(bootstrap_token or "").strip()
    child_env = {**os.environ, "AUTO_START_IF_READY": "1"}
    preserve = ["AUTO_START_IF_READY"]
    if token:
        child_env["SEAGULL_AGENT_BOOTSTRAP_TOKEN"] = token
        preserve.append("SEAGULL_AGENT_BOOTSTRAP_TOKEN")
    cmd = ["sudo", f"--preserve-env={','.join(preserve)}", "bash", str(script)]
    return subprocess.run(cmd, cwd=str(_env.root()), env=child_env).returncode
