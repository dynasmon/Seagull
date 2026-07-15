from pathlib import Path

_DISCOVERY_KEYS = {
    "SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_ENABLED",
    "SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_CIDRS",
    "SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_ALLOW_PUBLIC",
    "SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_INTERVAL",
    "SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_MAX_HOSTS",
    "SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_RATE_LIMIT",
    "SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_TIMEOUT",
}


def test_topology_active_discovery_env_keys_match_docker_and_systemd() -> None:
    root = Path(__file__).resolve().parents[2]
    env_example = (root / ".env.example").read_text()
    compose = (root / "compose.yml").read_text()
    systemd_env = (root / "deploy/systemd/seagull-agent.env.example").read_text()

    for key in _DISCOVERY_KEYS:
        assert key in env_example
        assert key in compose
        assert key in systemd_env
