from __future__ import annotations

import os
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

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
        out = onboarding.describe(_request(host="internal", headers={"x-forwarded-host": "edge.example.com:8443"}))
        assert "edge.example.com" in out.api_url

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
        cmd = onboarding.install_command(agent_id="web-01", profile="sensor", token="abt.web-01.secret")
        assert "--agent-id web-01" in cmd
        assert "--api-url https://siem.corp.example:8444/agent" in cmd
        assert "--enroll-url https://siem.corp.example:8445" in cmd
        assert "--profile sensor" in cmd
        assert "--enroll-token abt.web-01.secret" in cmd
        assert "--ca-file" not in cmd

    def test_command_includes_ca_when_private_authority(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        monkeypatch.setattr(onboarding.certs, "server_ca_bundle", lambda: "-----BEGIN CERTIFICATE-----")
        monkeypatch.setattr(onboarding.certs, "certificate_fingerprint", lambda pem: "ab12")
        cmd = onboarding.install_command(agent_id="web-01", profile="managed", token="t")
        assert "--ca-file ./server-ca.crt" in cmd
        assert "--profile managed" in cmd

    def test_unknown_profile_degrades_to_sensor(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.corp.example")
        cmd = onboarding.install_command(agent_id="web-01", profile="root", token="t")
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
        assert "--enroll-token abt.web-01.secret" in out.install_command
        assert row.agent_metadata["profile"] == "sensor"

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
