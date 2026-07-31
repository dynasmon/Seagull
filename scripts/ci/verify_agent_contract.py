from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"unable to load contract {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"contract {path} must contain an object")
    return value


def _mapping(source: dict[str, Any], key: str) -> dict[str, Any]:
    value = source.get(key)
    if not isinstance(value, dict):
        raise RuntimeError(f"contract field {key} must contain an object")
    return value


def _positive_int(source: dict[str, Any], key: str) -> int:
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RuntimeError(f"contract field {key} must be a positive integer")
    return value


def _range(source: dict[str, Any], key: str) -> tuple[int, int]:
    value = _mapping(source, key)
    minimum = _positive_int(value, "min")
    maximum = _positive_int(value, "max")
    if minimum > maximum:
        raise RuntimeError(f"contract range {key} is inverted")
    return minimum, maximum


def _require_between(value: int, window: tuple[int, int], label: str) -> None:
    if not window[0] <= value <= window[1]:
        raise RuntimeError(
            f"{label} {value} is outside the supported window {window[0]}-{window[1]}"
        )


def _verify_endpoint_stability(
    platform_contract: dict[str, Any], agent_contract: dict[str, Any]
) -> None:
    platform_endpoints = _mapping(platform_contract, "endpoints")
    agent_endpoints = _mapping(agent_contract, "endpoints")
    if not agent_endpoints:
        raise RuntimeError("platform and agent contracts have no common endpoints")
    missing = sorted(set(agent_endpoints) - set(platform_endpoints))
    if missing:
        raise RuntimeError(
            f"platform removed agent endpoints: {', '.join(missing)}"
        )
    for name in sorted(agent_endpoints):
        platform_endpoint = _mapping(platform_endpoints, name)
        agent_endpoint = _mapping(agent_endpoints, name)
        for key in ("method", "path", "listener", "request", "response"):
            platform_value = platform_endpoint.get(key)
            agent_value = agent_endpoint.get(key)
            if platform_value != agent_value:
                raise RuntimeError(
                    f"endpoint {name} changed {key}: platform={platform_value!r} "
                    f"agent={agent_value!r}"
                )


def verify(platform_dir: Path, agent_dir: Path, require_exact: bool) -> None:
    platform_contract = _load(platform_dir / "protocol-v1.json")
    platform_compatibility = _load(platform_dir / "compatibility.json")
    agent_contract = _load(agent_dir / "protocol-v1.json")
    agent_compatibility = _load(agent_dir / "compatibility.json")

    platform_protocol = _positive_int(platform_contract, "protocol_version")
    platform_event_schema = _positive_int(platform_contract, "event_schema_version")
    agent_protocol = _positive_int(agent_contract, "protocol_version")
    agent_event_schema = _positive_int(agent_contract, "event_schema_version")
    if _positive_int(platform_compatibility, "protocol_version") != platform_protocol:
        raise RuntimeError("platform contract and compatibility protocol versions differ")
    if _positive_int(platform_compatibility, "event_schema_version") != platform_event_schema:
        raise RuntimeError("platform contract and compatibility event schema versions differ")
    if _positive_int(agent_compatibility, "protocol_version") != agent_protocol:
        raise RuntimeError("agent contract and compatibility protocol versions differ")
    if _positive_int(agent_compatibility, "event_schema_version") != agent_event_schema:
        raise RuntimeError("agent contract and compatibility event schema versions differ")

    platform_server = _mapping(platform_compatibility, "server")
    agent_policy = _mapping(agent_compatibility, "agent")
    server_protocol_window = (
        _positive_int(platform_server, "oldest_supported_agent_protocol"),
        _positive_int(platform_server, "newest_supported_agent_protocol"),
    )
    if server_protocol_window[0] > server_protocol_window[1]:
        raise RuntimeError("platform supported agent protocol window is inverted")
    agent_server_window = _range(agent_policy, "accepts_server_protocol")
    server_event_window = _range(platform_server, "accepts_event_schema")
    agent_event_window = _range(agent_policy, "supports_event_schema")
    if _positive_int(agent_policy, "speaks_protocol") != agent_protocol:
        raise RuntimeError("agent compatibility policy advertises a different protocol")
    if _positive_int(agent_policy, "emits_event_schema") != agent_event_schema:
        raise RuntimeError("agent compatibility policy advertises a different event schema")

    _require_between(agent_protocol, server_protocol_window, "agent protocol")
    _require_between(platform_protocol, agent_server_window, "platform protocol")
    _require_between(agent_event_schema, server_event_window, "agent event schema")
    _require_between(platform_event_schema, agent_event_window, "platform event schema")
    _verify_endpoint_stability(platform_contract, agent_contract)

    for compatibility in (platform_compatibility, agent_compatibility):
        policy = _mapping(compatibility, "independent_release")
        if policy.get("server_upgrade_requires_agent_upgrade") is not False:
            raise RuntimeError("server upgrades must not require an agent upgrade")
        if policy.get("agent_upgrade_requires_server_upgrade") is not False:
            raise RuntimeError("agent upgrades must not require a server upgrade")

    if require_exact:
        if platform_contract != agent_contract:
            raise RuntimeError("the current protocol contract differs between repositories")
        if platform_compatibility != agent_compatibility:
            raise RuntimeError("the current compatibility policy differs between repositories")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform-dir", type=Path, required=True)
    parser.add_argument("--agent-dir", type=Path, required=True)
    parser.add_argument("--require-exact", action="store_true")
    args = parser.parse_args()
    try:
        verify(args.platform_dir, args.agent_dir, args.require_exact)
    except RuntimeError as exc:
        parser.exit(1, f"{exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
