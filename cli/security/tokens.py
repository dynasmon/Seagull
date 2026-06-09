from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from . import env as _env


_AGENT_MAP: list[tuple[str, str]] = [
    ("AGENT_CORE_ID", "AGENT_CORE_BOOTSTRAP_TOKEN"),
    ("AGENT_SENSOR_ID", "AGENT_SENSOR_BOOTSTRAP_TOKEN"),
    ("AGENT_LATERAL_ID", "AGENT_LATERAL_BOOTSTRAP_TOKEN"),
    ("AGENT_PROC_ID", "AGENT_PROC_BOOTSTRAP_TOKEN"),
    ("AGENT_SCAN_ID", "AGENT_SCAN_BOOTSTRAP_TOKEN"),
    ("AGENT_DDOS_ID", "AGENT_DDOS_BOOTSTRAP_TOKEN"),
    ("AGENT_VULN_ID", "AGENT_VULN_BOOTSTRAP_TOKEN"),
]


def _insecure_ssl() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post_json(
    url: str, payload: dict, headers: Optional[dict[str, str]] = None
) -> tuple[int, dict]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, context=_insecure_ssl(), timeout=10) as resp:
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


def mint(output_dir: Optional[Path] = None) -> None:
    ev = _env.read
    edge_port = ev("SEAGULL_EDGE_HTTPS_PORT", "443")
    backend_port = ev("SEAGULL_BACKEND_PORT", "8000")
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

        if output_dir:
            _write_token_file(agent_id, token, output_dir)
            print(f"[tokens] minted {agent_id} -> {output_dir}/{agent_id}.token")
        else:
            _env.upsert(token_key, token)
            print(f"[tokens] minted {token_key} for {agent_id}")

    if output_dir:
        print(f"[tokens] updated bootstrap token files in {output_dir}")
    else:
        print("[tokens] updated .env with AGENT_*_BOOTSTRAP_TOKEN values")
