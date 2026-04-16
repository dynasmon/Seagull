#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def env_str(name: str, default: str = "") -> str:
    value = os.getenv(name)
    return value.strip() if value is not None else default


def env_int(name: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = env_str(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        value = default
    if minimum is not None and value < minimum:
        value = minimum
    if maximum is not None and value > maximum:
        value = maximum
    return value


def parse_agent_ids(raw: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in raw.split(","):
        agent_id = item.strip()
        if not agent_id or agent_id in seen:
            continue
        seen.add(agent_id)
        out.append(agent_id)
    return out


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = raw.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc)
    except ValueError:
        return None


def atomic_write(path: Path, data: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp_path.write_text(data, encoding="utf-8")
    os.chmod(tmp_path, mode)
    tmp_path.replace(path)


@dataclass(frozen=True)
class ApiEndpoint:
    base: str
    prefix: str

    @property
    def login_url(self) -> str:
        return f"{self.base}{self.prefix}/auth/login"

    def bootstrap_url(self, agent_id: str) -> str:
        return f"{self.base}{self.prefix}/agents/{agent_id}/bootstrap-tokens"


class BootstrapRotator:
    def __init__(self) -> None:
        self.admin_username = env_str("SEAGULL_BOOTSTRAP_ADMIN_USERNAME", "admin")
        self.admin_password = env_str("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD")
        self.ca_file = env_str("SEAGULL_BOOTSTRAP_ROTATOR_CA_FILE", "")
        self.edge_base = env_str("SEAGULL_BOOTSTRAP_ROTATOR_EDGE_BASE", "").rstrip("/")
        self.backend_base = env_str("SEAGULL_BOOTSTRAP_ROTATOR_BACKEND_BASE", "http://seagull-backend:8000").rstrip("/")
        self.agent_ids = parse_agent_ids(
            env_str(
                "SEAGULL_BOOTSTRAP_ROTATOR_AGENT_IDS",
                "agent-core-1,agent-sensor-1,agent-lateral-1,agent-proc-1,agent-scan-1,agent-ddos-1,agent-vuln-1",
            )
        )
        self.token_ttl_seconds = env_int(
            "SEAGULL_BOOTSTRAP_ROTATOR_TOKEN_TTL_SECONDS", 86400, minimum=60, maximum=86400
        )
        self.token_max_uses = env_int(
            "SEAGULL_BOOTSTRAP_ROTATOR_TOKEN_MAX_USES", 5, minimum=1, maximum=100
        )
        self.every_seconds = env_int("SEAGULL_BOOTSTRAP_ROTATOR_EVERY_SECONDS", 900, minimum=60)
        self.refresh_before_seconds = env_int(
            "SEAGULL_BOOTSTRAP_ROTATOR_REFRESH_BEFORE_SECONDS", 21600, minimum=60
        )
        self.output_dir = Path(env_str("SEAGULL_BOOTSTRAP_ROTATOR_OUTPUT_DIR", "/etc/seagull/bootstrap"))
        self.state_dir = Path(
            env_str("SEAGULL_BOOTSTRAP_ROTATOR_STATE_DIR", "/var/lib/seagull/bootstrap-rotator")
        )
        self.timeout_seconds = env_int(
            "SEAGULL_BOOTSTRAP_ROTATOR_HTTP_TIMEOUT_SECONDS", 15, minimum=3
        )
        self.success_marker = self.state_dir / "last_success_at"
        self.metadata_path = self.state_dir / "state.json"
        self.endpoints = self._build_endpoints()
        self.https_context = self._build_https_context()
        self.state = self._load_state()

    def _build_endpoints(self) -> list[ApiEndpoint]:
        endpoints: list[ApiEndpoint] = []
        for base, prefixes in ((self.edge_base, ("/api", "")), (self.backend_base, ("", "/api"))):
            if not base:
                continue
            for prefix in prefixes:
                endpoint = ApiEndpoint(base=base, prefix=prefix)
                if endpoint not in endpoints:
                    endpoints.append(endpoint)
        return endpoints

    def _build_https_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if self.ca_file and Path(self.ca_file).is_file():
            context.load_verify_locations(cafile=self.ca_file)
        return context

    def _load_state(self) -> dict[str, Any]:
        if not self.metadata_path.exists():
            return {"agents": {}}
        try:
            data = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except Exception:
            return {"agents": {}}
        if not isinstance(data, dict):
            return {"agents": {}}
        if not isinstance(data.get("agents"), dict):
            data["agents"] = {}
        return data

    def _save_state(self) -> None:
        payload = json.dumps(self.state, indent=2, sort_keys=True)
        atomic_write(self.metadata_path, payload + "\n", 0o600)

    def _touch_success_marker(self) -> None:
        atomic_write(self.success_marker, utc_now().isoformat().replace("+00:00", "Z") + "\n", 0o600)

    def _request(
        self,
        method: str,
        url: str,
        *,
        body: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> tuple[int, str]:
        data = None
        headers = {"accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["content-type"] = "application/json"
        if token:
            headers["authorization"] = f"Bearer {token}"
        request = urllib.request.Request(url=url, data=data, headers=headers, method=method)
        context = self.https_context if url.startswith("https://") else None
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds, context=context) as response:
                return response.getcode(), response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            return exc.code, body_text

    def _login(self) -> tuple[ApiEndpoint, str]:
        if not self.admin_password:
            raise RuntimeError("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD is empty")
        payload = {"username": self.admin_username, "password": self.admin_password}
        last_error = "no login endpoints attempted"
        for endpoint in self.endpoints:
            status_code, body = self._request("POST", endpoint.login_url, body=payload)
            if status_code == 200:
                try:
                    parsed = json.loads(body)
                except json.JSONDecodeError:
                    last_error = f"login endpoint {endpoint.login_url} returned invalid JSON"
                    continue
                access_token = str(parsed.get("access_token") or "").strip()
                if access_token:
                    return endpoint, access_token
                last_error = f"login endpoint {endpoint.login_url} did not include access_token"
                continue
            last_error = f"login endpoint {endpoint.login_url} returned status={status_code} body={body[:200]}"
        raise RuntimeError(last_error)

    def _agent_state(self, agent_id: str) -> dict[str, Any]:
        agents = self.state.setdefault("agents", {})
        entry = agents.get(agent_id)
        if not isinstance(entry, dict):
            entry = {}
            agents[agent_id] = entry
        return entry

    def _token_file(self, agent_id: str) -> Path:
        return self.output_dir / f"{agent_id}.token"

    def _needs_refresh(self, agent_id: str) -> bool:
        token_path = self._token_file(agent_id)
        if not token_path.is_file() or token_path.stat().st_size == 0:
            return True
        state = self._agent_state(agent_id)
        expires_at = parse_datetime(state.get("expires_at"))
        if expires_at is None:
            return True
        return expires_at - utc_now() <= timedelta(seconds=self.refresh_before_seconds)

    def _mint_for_agent(self, endpoint: ApiEndpoint, access_token: str, agent_id: str) -> None:
        payload = {
            "ttl_seconds": self.token_ttl_seconds,
            "max_uses": self.token_max_uses,
            "description": f"bootstrap rotator for {agent_id}",
        }
        status_code, body = self._request(
            "POST",
            endpoint.bootstrap_url(agent_id),
            body=payload,
            token=access_token,
        )
        if status_code != 201:
            raise RuntimeError(
                f"bootstrap token creation failed for {agent_id}: status={status_code} body={body[:300]}"
            )
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"bootstrap token response for {agent_id} was not valid JSON") from exc
        token = str(parsed.get("bootstrap_token") or "").strip()
        expires_at = str(parsed.get("expires_at") or "").strip()
        if not token or not expires_at:
            raise RuntimeError(f"bootstrap token response for {agent_id} missing token or expires_at")
        atomic_write(self._token_file(agent_id), token + "\n", 0o600)
        state = self._agent_state(agent_id)
        state.update(
            {
                "expires_at": expires_at,
                "max_uses": int(parsed.get("max_uses") or self.token_max_uses),
                "rotated_at": utc_now().isoformat().replace("+00:00", "Z"),
            }
        )

    def rotate_once(self) -> None:
        endpoint, access_token = self._login()
        rotated: list[str] = []
        for agent_id in self.agent_ids:
            if not self._needs_refresh(agent_id):
                continue
            self._mint_for_agent(endpoint, access_token, agent_id)
            rotated.append(agent_id)
        self.state["last_success_at"] = utc_now().isoformat().replace("+00:00", "Z")
        self.state["last_login_base"] = endpoint.base
        self.state["last_login_prefix"] = endpoint.prefix
        self._save_state()
        self._touch_success_marker()
        if rotated:
            print(f"[bootstrap-rotator] rotated tokens for: {', '.join(rotated)}", flush=True)
        else:
            print("[bootstrap-rotator] no rotation required", flush=True)

    def run_forever(self) -> None:
        while True:
            try:
                self.rotate_once()
            except Exception as exc:
                print(f"[bootstrap-rotator] rotation failed: {exc}", file=sys.stderr, flush=True)
            time.sleep(self.every_seconds)


if __name__ == "__main__":
    BootstrapRotator().run_forever()
