from __future__ import annotations

import importlib
import os
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_PASSWORD", "test-password")

from app.core.config import settings
from app.features.agents import onboarding
from app.features.agents import service as agents_service
from app.features.agents.schemas import AgentBootstrapTokenOut, AgentEnrollmentTicketIn


def _request(host="siem.example.com", headers=None):
    return SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.10"),
        headers=headers or {},
        url=SimpleNamespace(hostname=host, path="/api/agents/enrollment-tickets"),
    )


@pytest.fixture(autouse=True)
def no_server_ca(monkeypatch):
    monkeypatch.setattr(onboarding.certs, "server_ca_bundle", lambda: None)


class TestDescribe:
    def test_uses_configured_public_host(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        out = onboarding.describe(_request(host="ignored.example"))
        assert out.api_url == "https://siem.corp.example:8444/agent"
        assert out.enroll_url == "https://siem.corp.example:8445"

    def test_falls_back_to_request_host(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "")
        out = onboarding.describe(_request(host="siem.example.com"))
        assert out.api_url.startswith("https://siem.example.com:")

    def test_prefers_forwarded_host_header(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "")
        monkeypatch.setattr(settings, "SEAGULL_TRUST_PROXY_HEADERS", True)
        out = onboarding.describe(_request(host="internal", headers={"x-forwarded-host": "edge.example.com:8443"}))
        assert "edge.example.com" in out.api_url

    def test_ignores_forwarded_host_when_proxy_headers_are_untrusted(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "")
        monkeypatch.setattr(settings, "SEAGULL_TRUST_PROXY_HEADERS", False)
        out = onboarding.describe(_request(host="internal.example", headers={"x-forwarded-host": "attacker.example"}))
        assert out.api_url == "https://internal.example:8444/agent"

    def test_rejects_malformed_forwarded_host(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "")
        monkeypatch.setattr(settings, "SEAGULL_TRUST_PROXY_HEADERS", True)
        out = onboarding.describe(_request(host="internal.example", headers={"x-forwarded-host": "edge.example/path"}))
        assert out.api_url == "https://internal.example:8444/agent"

    def test_preserves_ipv6_request_host(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "")
        monkeypatch.setattr(settings, "SEAGULL_TRUST_PROXY_HEADERS", False)
        out = onboarding.describe(_request(host="2001:db8::10"))
        assert out.api_url == "https://[2001:db8::10]:8444/agent"

    def test_defaults_to_localhost_without_request(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "")
        out = onboarding.describe(None)
        assert out.api_url == "https://localhost:8444/agent"

    def test_exposes_protocol_window_and_profiles(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        out = onboarding.describe(None)
        assert out.default_profile == "sensor"
        assert set(out.profiles) == {"sensor", "managed"}
        assert out.min_supported_protocol <= out.protocol_version <= out.max_supported_protocol

    def test_reports_ca_requirement_and_fingerprint(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        monkeypatch.setattr(onboarding.certs, "server_ca_bundle", lambda: "-----BEGIN CERTIFICATE-----")
        monkeypatch.setattr(onboarding.certs, "certificate_fingerprint", lambda pem: "ab12")
        out = onboarding.describe(None)
        assert out.server_ca_required is True
        assert out.server_ca_fingerprint_sha256 == "ab12"


class TestInstallCommand:
    def test_command_contains_every_required_flag(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        cmd = onboarding.install_command(agent_id="web-01", profile="sensor")
        assert "--agent-id web-01" in cmd
        assert "--api-url https://siem.corp.example:8444/agent" in cmd
        assert "--enroll-url https://siem.corp.example:8445" in cmd
        assert "--profile sensor" in cmd
        assert "--prompt-enroll-token" in cmd
        assert "abt." not in cmd
        assert "--ca-file" not in cmd

    def test_command_includes_ca_when_private_authority(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        monkeypatch.setattr(onboarding.certs, "server_ca_bundle", lambda: "-----BEGIN CERTIFICATE-----")
        monkeypatch.setattr(onboarding.certs, "certificate_fingerprint", lambda pem: "ab12")
        cmd = onboarding.install_command(agent_id="web-01", profile="managed")
        assert "--ca-file ./server-ca.crt" in cmd
        assert "--profile managed" in cmd

    def test_unknown_profile_degrades_to_sensor(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        cmd = onboarding.install_command(agent_id="web-01", profile="root")
        assert "--profile sensor" in cmd


class TestEnrollmentTicket:
    def _stub(self, monkeypatch, row=None):
        expires = datetime.utcnow() + timedelta(minutes=15)
        monkeypatch.setattr(
            agents_service,
            "create_bootstrap_token",
            lambda db, **kwargs: AgentBootstrapTokenOut(
                agent_id=kwargs["agent_id"],
                bootstrap_token="abt.web-01.secret",
                expires_at=expires,
                max_uses=1,
            ),
        )
        monkeypatch.setattr(agents_service.repository, "get_agent_by_agent_id", lambda db, agent_id: row)
        monkeypatch.setattr(agents_service.repository, "save_agent", lambda db, saved: None)
        monkeypatch.setattr(agents_service.repository, "commit", lambda db: None)

    def test_ticket_returns_single_use_token_and_command(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        row = SimpleNamespace(agent_id="web-01", agent_metadata={})
        self._stub(monkeypatch, row)

        out = agents_service.create_enrollment_ticket(
            object(),
            payload=AgentEnrollmentTicketIn(agent_id="web-01", profile="sensor"),
            request=_request(),
            admin=SimpleNamespace(id=1, username="admin"),
            audit_writer=lambda db, **kw: None,
        )

        assert out.max_uses == 1
        assert out.bootstrap_token == "abt.web-01.secret"
        assert out.profile == "sensor"
        assert "--prompt-enroll-token" in out.install_command
        assert out.bootstrap_token not in out.install_command
        assert out.architecture == "amd64"
        assert out.artifact.filename == "seagull-agent_0.1.0_linux_amd64.tar.gz"
        assert row.agent_metadata["profile"] == "sensor"

    def test_ticket_renders_the_endpoint_commands(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        self._stub(monkeypatch, SimpleNamespace(agent_id="web-01", agent_metadata={}))

        out = agents_service.create_enrollment_ticket(
            object(),
            payload=AgentEnrollmentTicketIn(agent_id="web-01", sources=["proc", "authlog"]),
            request=_request(),
            admin=SimpleNamespace(id=1, username="admin"),
            audit_writer=lambda db, **kw: None,
        )

        assert out.sources == ["authlog", "proc"]
        assert out.installer_filename == "seagull-agent-web-01-amd64-installer.sh"
        assert out.installer_command == "sudo bash seagull-agent-web-01-amd64-installer.sh"
        assert out.bootstrap_command.startswith("curl ")
        assert "https://siem.corp.example:8443/api/agents/installer" in out.bootstrap_command
        assert f"X-Agent-Bootstrap-Token: {out.bootstrap_token}" in out.bootstrap_command
        assert out.bootstrap_command.endswith(out.installer_command)
        assert "--sources authlog,proc" in out.install_command

    def test_ticket_rejects_an_unsupported_collector(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        self._stub(monkeypatch, None)

        with pytest.raises(HTTPException) as excinfo:
            agents_service.create_enrollment_ticket(
                object(),
                payload=AgentEnrollmentTicketIn(agent_id="web-01", sources=["authlog", "rootkit"]),
                request=_request(),
                admin=SimpleNamespace(id=1, username="admin"),
                audit_writer=lambda db, **kw: None,
            )
        assert excinfo.value.status_code == 422

    def test_ticket_records_the_provisioning_parameters_on_the_token(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        captured = {}

        def capture(db, **kwargs):
            captured.update(kwargs)
            return AgentBootstrapTokenOut(
                agent_id=kwargs["agent_id"],
                bootstrap_token="abt.web-01.secret",
                expires_at=datetime.utcnow() + timedelta(minutes=15),
                max_uses=1,
            )

        monkeypatch.setattr(agents_service, "create_bootstrap_token", capture)
        monkeypatch.setattr(agents_service.repository, "get_agent_by_agent_id", lambda db, agent_id: None)

        agents_service.create_enrollment_ticket(
            object(),
            payload=AgentEnrollmentTicketIn(agent_id="web-01", profile="managed", architecture="arm64"),
            request=_request(),
            admin=SimpleNamespace(id=1, username="admin"),
            audit_writer=lambda db, **kw: None,
        )

        provisioning = captured["metadata"]["provisioning"]
        assert provisioning["profile"] == "managed"
        assert provisioning["architecture"] == "arm64"
        assert provisioning["version"] == settings.SEAGULL_AGENT_RELEASE_VERSION
        assert provisioning["api_url"] == "https://siem.corp.example:8444/agent"
        assert provisioning["enroll_url"] == "https://siem.corp.example:8445"
        assert provisioning["sources"] == settings.SEAGULL_AGENT_DEFAULT_SOURCES

    def test_ticket_records_managed_profile_on_the_agent(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        row = SimpleNamespace(agent_id="web-01", agent_metadata={"profile": "sensor"})
        self._stub(monkeypatch, row)

        out = agents_service.create_enrollment_ticket(
            object(),
            payload=AgentEnrollmentTicketIn(agent_id="web-01", profile="managed"),
            request=_request(),
            admin=SimpleNamespace(id=1, username="admin"),
            audit_writer=lambda db, **kw: None,
        )

        assert out.profile == "managed"
        assert row.agent_metadata["profile"] == "managed"

    def test_ticket_defaults_to_sensor_profile(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        self._stub(monkeypatch, None)

        out = agents_service.create_enrollment_ticket(
            object(),
            payload=AgentEnrollmentTicketIn(agent_id="web-01"),
            request=_request(),
            admin=SimpleNamespace(id=1, username="admin"),
            audit_writer=lambda db, **kw: None,
        )
        assert out.profile == "sensor"

    def test_agent_id_shape_is_validated(self):
        with pytest.raises(ValueError):
            AgentEnrollmentTicketIn(agent_id="../etc/passwd")


class TestRuntimeValidation:
    def test_agent_public_host_falls_back_to_caddy_domain(self, monkeypatch):
        settings_module = importlib.import_module("app.core.config.settings")
        monkeypatch.delenv("SEAGULL_AGENT_PUBLIC_HOST", raising=False)
        monkeypatch.setenv("SEAGULL_CADDY_DOMAIN", "seagull.example.com")
        assert settings_module._agent_public_host_from_env() == "seagull.example.com"

    def test_agent_public_host_prefers_explicit_value(self, monkeypatch):
        settings_module = importlib.import_module("app.core.config.settings")
        monkeypatch.setenv("SEAGULL_AGENT_PUBLIC_HOST", "agents.example.com")
        monkeypatch.setenv("SEAGULL_CADDY_DOMAIN", "seagull.example.com")
        assert settings_module._agent_public_host_from_env() == "agents.example.com"

    def test_worker_does_not_require_agent_public_host(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_ENV", "production")
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "")
        monkeypatch.setattr(settings, "SEAGULL_AGENT_RELEASE_VERSION", "not-semver")
        monkeypatch.setattr(settings, "SEAGULL_AGENT_RELEASE_BASE_URL", "http://invalid")
        monkeypatch.setattr(settings, "SEAGULL_AGENT_SUPPORTED_ARCHITECTURES", [])
        settings.validate_for_service("worker-ueba")

    def test_backend_requires_agent_public_host_in_production(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_ENV", "production")
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "")
        with pytest.raises(RuntimeError, match="SEAGULL_AGENT_PUBLIC_HOST must be set in prod"):
            settings.validate_for_service("backend-api")

    @pytest.mark.parametrize(
        "public_host",
        [
            "https://siem.example.com",
            "siem.example.com:8444",
            "siem.example.com/agent",
            "operator@siem.example.com",
            "invalid host",
        ],
    )
    def test_backend_rejects_malformed_agent_public_host(self, monkeypatch, public_host):
        monkeypatch.setattr(settings, "SEAGULL_ENV", "dev")
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", public_host)
        with pytest.raises(RuntimeError, match="must be a DNS name or IP address without a port"):
            settings.validate_for_service("backend-api")

    @pytest.mark.parametrize("public_host", ["siem.example.com", "192.0.2.10", "[2001:db8::10]"])
    def test_backend_accepts_valid_agent_public_host(self, monkeypatch, public_host):
        monkeypatch.setattr(settings, "SEAGULL_ENV", "dev")
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", public_host)
        settings.validate_for_service("backend-api")

    @pytest.mark.parametrize(
        "version",
        [
            "v1.0.0",
            "01.0.0",
            "1.01.0",
            "1.0.01",
            "1.0.0-01",
            "1.0.0-",
            "1.0.0-alpha..1",
            "1.0",
        ],
    )
    def test_backend_rejects_invalid_agent_release_version(self, monkeypatch, version):
        monkeypatch.setattr(settings, "SEAGULL_ENV", "dev")
        monkeypatch.setattr(settings, "SEAGULL_AGENT_RELEASE_VERSION", version)
        with pytest.raises(RuntimeError, match="must be a semantic version"):
            settings.validate_for_service("backend-api")

    @pytest.mark.parametrize(
        "version",
        [
            "0.1.0",
            "1.0.0-alpha.1",
            "1.0.0-0A",
            "1.0.0+build.7",
            "1.0.0-rc.1+build.7",
        ],
    )
    def test_backend_accepts_valid_agent_release_version(self, monkeypatch, version):
        monkeypatch.setattr(settings, "SEAGULL_ENV", "dev")
        monkeypatch.setattr(settings, "SEAGULL_AGENT_RELEASE_VERSION", version)
        settings.validate_for_service("backend-api")

    @pytest.mark.parametrize(
        "release_url",
        [
            "http://releases.example.com",
            "https://user:pass@releases.example.com",
            "https://releases.example.com?channel=stable",
            "https://releases.example.com#stable",
            "https://releases.example.com:invalid",
            "https://",
        ],
    )
    def test_backend_rejects_invalid_agent_release_base_url(self, monkeypatch, release_url):
        monkeypatch.setattr(settings, "SEAGULL_ENV", "dev")
        monkeypatch.setattr(settings, "SEAGULL_AGENT_RELEASE_BASE_URL", release_url)
        with pytest.raises(RuntimeError, match="must be an absolute HTTPS URL without credentials"):
            settings.validate_for_service("backend-api")
