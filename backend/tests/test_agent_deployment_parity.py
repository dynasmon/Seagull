from pathlib import Path


def test_platform_contains_no_agent_product_source() -> None:
    root = Path(__file__).resolve().parents[2]

    assert not (root / "agent/go.mod").exists()
    assert not (root / "agent/cmd").exists()
    assert not (root / "agent/internal").exists()
    assert not (root / "agent/packaging").exists()
    assert not (root / "deploy/systemd/install-agent.sh").exists()
    assert not (root / "scripts/ci/agent-package-smoke.sh").exists()


def test_platform_deployment_does_not_build_agent_artifacts() -> None:
    root = Path(__file__).resolve().parents[2]
    paths = (
        root / "Makefile",
        root / ".gitlab-ci.yml",
        root / "deploy/install-deps.sh",
        root / "compose.yml",
        root / "cli/main.py",
    )
    forbidden = ("go build", "go test", "libpcap-dev", "install-agent.sh")

    for path in paths:
        text = path.read_text()
        assert all(value not in text for value in forbidden)


def test_platform_pins_an_agent_release() -> None:
    root = Path(__file__).resolve().parents[2]
    env = (root / ".env.example").read_text()

    assert "SEAGULL_AGENT_RELEASE_VERSION=0.1.0" in env
    assert "SEAGULL_AGENT_RELEASE_BASE_URL=https://github.com/dynasmon/seagull-agent/releases/download" in env


def test_agent_listeners_serve_the_managed_edge_certificate() -> None:
    root = Path(__file__).resolve().parents[2]
    caddyfile = (root / "infra/caddy/Caddyfile").read_text()

    assert "{$SEAGULL_CADDY_DOMAIN}:8444" in caddyfile
    assert "{$SEAGULL_CADDY_DOMAIN}:8445" in caddyfile
    assert "/etc/seagull/mtls/server.crt" not in caddyfile
    assert "trust_pool file /etc/seagull/mtls/agent-ca.crt" in caddyfile


def test_the_internal_listener_certificate_excludes_the_edge_hostname() -> None:
    root = Path(__file__).resolve().parents[2]
    pki = (root / "cli/security/pki.py").read_text()

    assert "SEAGULL_CADDY_DOMAIN" not in pki
    assert "SEAGULL_AGENT_PUBLIC_HOST" not in pki
