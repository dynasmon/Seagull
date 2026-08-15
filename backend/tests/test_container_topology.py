from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "compose.yml"
DEV_RELOAD_FILE = ROOT / "compose.dev-reload.yml"
PROMETHEUS_FILE = ROOT / "infra" / "prometheus" / "prometheus.yml"

CA_KEY = "secrets/pki/agent-ca.key"
EDGE_FACING = {"caddy", "seagull-portal"}
DATA_STORES = {"postgres", "redis", "elasticsearch", "clickhouse", "redpanda"}
PUBLIC_LISTENERS = {"caddy"}
_DEFAULTED = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*:-(.*)\}$")


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load(COMPOSE_FILE.read_text())


def _networks_of(compose: dict, service: str) -> set[str]:
    return set(compose["services"][service].get("networks") or [])


def _publish_host(entry: str) -> str:
    spec, _, _ = str(entry).rpartition(":")
    match = _DEFAULTED.match(spec)
    if match:
        spec = match.group(1)
    host, separator, _ = spec.rpartition(":")
    return host.strip("[]") if separator else ""


def _is_loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1", "localhost")


class TestNetworkSegmentation:
    def test_every_service_declares_its_networks(self, compose):
        undeclared = [name for name in compose["services"] if not _networks_of(compose, name)]
        assert undeclared == []

    def test_every_declared_network_exists(self, compose):
        declared = set(compose["networks"])
        used = set().union(*(_networks_of(compose, name) for name in compose["services"]))
        assert used <= declared

    def test_the_edge_cannot_reach_the_data_stores(self, compose):
        for service in EDGE_FACING:
            reachable = _networks_of(compose, service)
            for store in DATA_STORES:
                assert not reachable & _networks_of(compose, store), f"{service} can reach {store}"

    def test_the_edge_cannot_reach_the_certificate_authority(self, compose):
        for service in EDGE_FACING:
            assert not _networks_of(compose, service) & _networks_of(compose, "seagull-pki")

    def test_only_the_backend_shares_a_network_with_the_certificate_authority(self, compose):
        authority = _networks_of(compose, "seagull-pki")
        neighbours = {
            name
            for name in compose["services"]
            if name != "seagull-pki" and _networks_of(compose, name) & authority
        }
        assert neighbours == {"seagull-backend"}

    def test_prometheus_reaches_every_target_it_scrapes(self, compose):
        scrape_config = yaml.safe_load(PROMETHEUS_FILE.read_text())
        observability = _networks_of(compose, "prometheus")
        for job in scrape_config["scrape_configs"]:
            for entry in job["static_configs"]:
                for target in entry["targets"]:
                    host = target.split(":")[0]
                    if host == "localhost":
                        continue
                    assert host in compose["services"], f"{host} is scraped but is not a service"
                    assert _networks_of(compose, host) & observability, f"prometheus cannot reach {host}"


class TestCertificateAuthorityIsolation:
    def test_only_the_authority_mounts_the_signing_key(self, compose):
        holders = {
            name
            for name, service in compose["services"].items()
            if any(CA_KEY in str(volume) for volume in service.get("volumes") or [])
        }
        assert holders == {"seagull-pki"}

    def test_the_backend_reaches_the_authority_over_http(self, compose):
        environment = compose["services"]["seagull-backend"]["environment"]
        assert "seagull-pki" in environment["SEAGULL_PKI_SIGNER_URL"]
        assert "SEAGULL_AGENT_MTLS_CA_KEY_FILE" not in environment

    def test_the_authority_keeps_a_read_only_root_filesystem(self, compose):
        authority = compose["services"]["seagull-pki"]
        assert authority["read_only"] is True
        assert authority["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in authority["security_opt"]


class TestHostExposure:
    def test_only_the_edge_publishes_beyond_loopback(self, compose):
        for name, service in compose["services"].items():
            if name in PUBLIC_LISTENERS:
                continue
            for entry in service.get("ports") or []:
                host = _publish_host(entry)
                assert _is_loopback(host), f"{name} publishes {entry} on {host or 'every interface'}"

    def test_the_dev_reload_overlay_keeps_the_same_rule(self):
        overlay = yaml.safe_load(DEV_RELOAD_FILE.read_text())
        for name, service in overlay["services"].items():
            for entry in service.get("ports") or []:
                assert _is_loopback(_publish_host(entry)), f"{name} publishes {entry} beyond loopback"

    def test_a_bare_port_would_be_reported_as_exposed(self):
        assert _publish_host("8080:8080") == ""
        assert _publish_host("${SEAGULL_PORTAL_PORT:-}:8080") == ""
        assert _publish_host("${SEAGULL_PORTAL_PORT:-127.0.0.1:8080}:8080") == "127.0.0.1"
