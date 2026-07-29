from pathlib import Path

_TUNING_KEYS = {
    "SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_ENABLED",
    "SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_CIDRS",
    "SEAGULL_DDOS_MIN_PPS",
    "SEAGULL_VULN_SCAN_EVERY",
    "SEAGULL_RESPONSE_ALLOW_SHELL_EXEC",
}

_BOOTSTRAP_KEYS = {
    "SEAGULL_AGENT_ID",
    "SEAGULL_API_URL",
    "SEAGULL_ENROLL_URL",
    "SEAGULL_AGENT_PROFILE",
    "SEAGULL_TLS_CA_FILE",
    "SEAGULL_TLS_CERT_FILE",
    "SEAGULL_TLS_KEY_FILE",
    "SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE",
    "SEAGULL_AGENT_IDENTITY_STATE_FILE",
    "SEAGULL_AGENT_CREDENTIAL_FILE",
}


def test_agent_packaging_env_covers_bootstrap_keys_only() -> None:
    root = Path(__file__).resolve().parents[2]
    packaged_env = (root / "agent/packaging/seagull-agent.env.example").read_text()

    for key in _BOOTSTRAP_KEYS:
        assert key in packaged_env

    for key in _TUNING_KEYS:
        assert key not in packaged_env


def test_agent_packaging_installer_is_repo_independent() -> None:
    root = Path(__file__).resolve().parents[2]
    installer = (root / "agent/packaging/install.sh").read_text()

    assert "REPO_ROOT" not in installer
    assert "../" not in installer
    assert "secrets/" not in installer
    assert "go build" not in installer
