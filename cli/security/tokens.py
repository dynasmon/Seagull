from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from ..config import env as _env

_AGENT_MAP: list[tuple[str, str]] = [
    ("AGENT_CORE_ID", "AGENT_CORE_BOOTSTRAP_TOKEN"),
    ("AGENT_SENSOR_ID", "AGENT_SENSOR_BOOTSTRAP_TOKEN"),
    ("AGENT_LATERAL_ID", "AGENT_LATERAL_BOOTSTRAP_TOKEN"),
    ("AGENT_PROC_ID", "AGENT_PROC_BOOTSTRAP_TOKEN"),
    ("AGENT_SCAN_ID", "AGENT_SCAN_BOOTSTRAP_TOKEN"),
    ("AGENT_DDOS_ID", "AGENT_DDOS_BOOTSTRAP_TOKEN"),
    ("AGENT_VULN_ID", "AGENT_VULN_BOOTSTRAP_TOKEN"),
]

def _abs(path_str: str) -> Path:
    p = Path(path_str)
    return p if p.is_absolute() else _env.root() / p


def _trust_anchors() -> list[Path]:
    anchors: list[Path] = []
    for key, default in (
        ("SEAGULL_AGENT_SERVER_CA_FILE", "./secrets/tls/ca.crt"),
        ("SEAGULL_TLS_CERT_FILE", "./secrets/tls/tls.crt"),
    ):
        raw = _env.read(key, default)
        if not raw:
            continue
        candidate = _abs(raw)
        if candidate.is_file() and candidate not in anchors:
            anchors.append(candidate)
    return anchors


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    for anchor in _trust_anchors():
        try:
            context.load_verify_locations(cafile=str(anchor))
        except (ssl.SSLError, OSError):
            continue
    return context


def _context_for(url: str) -> Optional[ssl.SSLContext]:
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        return None
    return _tls_context()


def _post_json(
    url: str, payload: dict, headers: Optional[dict[str, str]] = None
) -> tuple[int, dict]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, context=_context_for(url), timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            data = json.loads(exc.read())
        except Exception:
            data = {}
        return exc.code, data
    except Exception:
        return 0, {}


def _try_login(base: str, prefix: str, username: str, password: str) -> Optional[str]:
    code, data = _post_json(
        f"{base}{prefix}/auth/login",
        {"username": username, "password": password},
    )
    if code == 200:
        token = data.get("access_token", "")
        if token:
            return token
    return None


def _login(
    edge_base: str,
    backend_base: str,
    username: str,
    password: str,
    timeout: int,
    retry_interval: float,
) -> tuple[str, str, str]:
    candidates = [
        (edge_base, ""),
        (edge_base, "/api"),
        (backend_base, ""),
        (backend_base, "/api"),
    ]

    for base, prefix in candidates:
        token = _try_login(base, prefix, username, password)
        if token:
            return token, base, prefix

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for base, prefix in candidates:
            token = _try_login(base, prefix, username, password)
            if token:
                return token, base, prefix
        time.sleep(retry_interval)

    raise RuntimeError(f"failed to login as {username!r} after {timeout}s")


def _write_token_file(agent_id: str, token: str, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.chmod(0o700)
    token_file = output_dir / f"{agent_id}.token"
    token_file.write_text(token + "\n")
    token_file.chmod(0o600)


def default_output_dir() -> Path:
    return _env.root() / "secrets" / "bootstrap"


def mint(output_dir: Optional[Path] = None) -> None:
    ev = _env.read
    output_dir = output_dir or default_output_dir()

    def _port_of(value: str, default: str) -> str:
        # Compose port vars may carry a bind address ("127.0.0.1:8000").
        return (value or default).rsplit(":", 1)[-1] or default

    edge_port = _port_of(ev("SEAGULL_EDGE_HTTPS_PORT", "443"), "443")
    backend_port = _port_of(ev("SEAGULL_BACKEND_PORT", "8000"), "8000")
    admin_user = ev("SEAGULL_BOOTSTRAP_ADMIN_USERNAME", "admin")
    admin_pass = ev("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD", "")
    ttl = int(ev("SEAGULL_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS", "900"))
    max_uses = int(ev("SEAGULL_MINT_TOKENS_MAX_USES", "1"))
    login_timeout = int(ev("SEAGULL_MINT_TOKENS_LOGIN_TIMEOUT_SECONDS", "180"))
    login_retry = float(ev("SEAGULL_MINT_TOKENS_LOGIN_RETRY_SECONDS", "2"))

    if not admin_pass:
        raise ValueError("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD is empty in .env")

    caddy_domain = ev("SEAGULL_CADDY_DOMAIN", "")
    edge_host = ev("SEAGULL_MINT_TOKENS_EDGE_HOST", "") or caddy_domain or "127.0.0.1"
    edge_base = ev("SEAGULL_MINT_TOKENS_EDGE_BASE", f"https://{edge_host}:{edge_port}")
    backend_base = ev("SEAGULL_MINT_TOKENS_BACKEND_BASE", f"http://127.0.0.1:{backend_port}")

    print(f"[tokens] authenticating as {admin_user!r}...")
    access_token, api_base, api_prefix = _login(
        edge_base, backend_base, admin_user, admin_pass, login_timeout, login_retry,
    )
    print(f"[tokens] authenticated via {api_base}{api_prefix}")

    for agent_key, token_key in _AGENT_MAP:
        agent_id = ev(agent_key, "")
        if not agent_id:
            print(f"[tokens] skipping {token_key}: {agent_key} not set")
            continue

        url = f"{api_base}{api_prefix}/agents/{agent_id}/bootstrap-tokens"
        code, data = _post_json(
            url,
            {"ttl_seconds": ttl, "max_uses": max_uses, "description": f"auto bootstrap for {agent_id}"},
            {"Authorization": f"Bearer {access_token}"},
        )
        token = data.get("bootstrap_token", "")
        if not token:
            raise RuntimeError(
                f"failed to mint token for {agent_id} (HTTP {code}): {data}"
            )

        _write_token_file(agent_id, token, output_dir)
        print(f"[tokens] minted {agent_id} -> {output_dir}/{agent_id}.token")

    print(f"[tokens] updated bootstrap token files in {output_dir}")
