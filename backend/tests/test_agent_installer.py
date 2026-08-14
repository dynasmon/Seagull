from __future__ import annotations

import base64
import gzip
import hashlib
import io
import os
import pwd
import shutil
import subprocess
import tarfile
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_PASSWORD", "test-password")

from app.core.config import settings
from app.features.agents import installer, onboarding, packages
from app.features.agents import service as agents_service
from app.features.agents.auth import generate_bootstrap_token, hash_bootstrap_token

CA_PEM = "-----BEGIN CERTIFICATE-----\nMIIBteststub\n-----END CERTIFICATE-----\n"


def _package_bytes() -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        payload = b"#!/usr/bin/env bash\nexit 0\n"
        info = tarfile.TarInfo("seagull-agent_0.1.0_linux_amd64/install.sh")
        info.size = len(payload)
        info.mode = 0o755
        archive.addfile(info, io.BytesIO(payload))
    return gzip.compress(raw.getvalue(), mtime=0)


PACKAGE = _package_bytes()
REFERENCE = packages.PackageRef(
    version="0.1.0",
    os="linux",
    architecture="amd64",
    filename="seagull-agent_0.1.0_linux_amd64.tar.gz",
    sha256=hashlib.sha256(PACKAGE).hexdigest(),
    size_bytes=len(PACKAGE),
)


def _spec(**overrides) -> installer.InstallerSpec:
    values = dict(
        agent_id="web-01",
        profile="sensor",
        sources=["authlog", "proc"],
        api_url="https://siem.example.com:8444/agent",
        enroll_url="https://siem.example.com:8445",
        enrollment_token="abt.web-01." + "s" * 32,
        package=REFERENCE,
        server_ca_pem=CA_PEM,
    )
    values.update(overrides)
    return installer.InstallerSpec(**values)


def _script(rendered: bytes) -> str:
    return rendered.decode("utf-8").split(f"\n{installer._PAYLOAD_MARKER}\n", 1)[0]


def _payload(rendered: bytes) -> bytes:
    encoded = rendered.decode("utf-8").split(f"\n{installer._PAYLOAD_MARKER}\n", 1)[1]
    return base64.b64decode(encoded)


def _non_root_invocation(script: Path, basetemp: Path) -> dict:
    if os.geteuid() != 0:
        return {}
    for directory in (basetemp.parent, basetemp, script.parent):
        directory.chmod(directory.stat().st_mode | 0o055)
    script.chmod(script.stat().st_mode | 0o055)
    try:
        return {"user": pwd.getpwnam("nobody").pw_uid}
    except KeyError:
        return {"user": 65534}


class TestRender:
    def test_carries_the_endpoint_configuration(self):
        script = _script(installer.render(_spec(), PACKAGE))
        assert "AGENT_ID=web-01" in script
        assert "AGENT_PROFILE=sensor" in script
        assert "AGENT_SOURCES=authlog,proc" in script
        assert "API_URL=https://siem.example.com:8444/agent" in script
        assert "ENROLL_URL=https://siem.example.com:8445" in script
        assert f"PACKAGE_SHA256={REFERENCE.sha256}" in script
        assert "PACKAGE_NAME=seagull-agent_0.1.0_linux_amd64" in script

    def test_embeds_the_package_verbatim(self):
        assert _payload(installer.render(_spec(), PACKAGE)) == PACKAGE

    def test_embeds_the_trust_anchor(self):
        script = _script(installer.render(_spec(), PACKAGE))
        assert "SERVER_CA_INCLUDED=1" in script
        assert CA_PEM.strip() in script
        assert "--ca-file" in script

    def test_omits_the_trust_anchor_when_the_platform_has_none(self):
        script = _script(installer.render(_spec(server_ca_pem=None), PACKAGE))
        assert "SERVER_CA_INCLUDED=0" in script
        assert "BEGIN CERTIFICATE" not in script

    def test_passes_the_token_by_file_and_never_on_a_command_line(self):
        script = _script(installer.render(_spec(), PACKAGE))
        assert "--enroll-token-file" in script
        assert "--enroll-token " not in script
        assert "--prompt-enroll-token" not in script

    def test_allows_overriding_the_embedded_token_from_the_environment(self):
        script = _script(installer.render(_spec(), PACKAGE))
        assert 'ENROLLMENT_TOKEN="${SEAGULL_ENROLLMENT_TOKEN:-${EMBEDDED_ENROLLMENT_TOKEN}}"' in script

    def test_quotes_values_that_need_it(self):
        script = _script(installer.render(_spec(agent_id="web 01"), PACKAGE))
        assert "AGENT_ID='web 01'" in script

    def test_refuses_a_trust_anchor_that_would_break_out_of_the_heredoc(self):
        with pytest.raises(ValueError):
            installer.render(_spec(server_ca_pem=f"x\n{installer._CA_HEREDOC}\ny"), PACKAGE)

    def test_guards_the_target_architecture(self):
        script = _script(installer.render(_spec(), PACKAGE))
        assert "AGENT_ARCH=amd64" in script
        assert "uname -m" in script
        assert "aarch64" in script

    def test_verifies_the_payload_before_extracting_it(self):
        script = _script(installer.render(_spec(), PACKAGE))
        assert script.index("sha256sum --check") < script.index("tar -xzf")

    def test_carries_no_comments(self):
        script = _script(installer.render(_spec(), PACKAGE))
        body = script.split("write_server_ca()", 1)[1]
        commented = [line for line in body.splitlines() if line.strip().startswith("#")]
        assert commented == []

    def test_filename_identifies_the_endpoint_and_architecture(self):
        assert installer.filename(agent_id="web-01", architecture="arm64") == (
            "seagull-agent-web-01-arm64-installer.sh"
        )

    @pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
    def test_rendered_script_is_valid_bash(self, tmp_path):
        path = tmp_path / "installer.sh"
        path.write_bytes(installer.render(_spec(), PACKAGE))
        subprocess.run(["bash", "-n", str(path)], check=True)

    @pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
    def test_rendered_script_refuses_a_non_root_invocation(self, tmp_path, tmp_path_factory):
        path = tmp_path / "installer.sh"
        path.write_bytes(installer.render(_spec(), PACKAGE))
        result = subprocess.run(
            ["bash", str(path)],
            capture_output=True,
            text=True,
            **_non_root_invocation(path, tmp_path_factory.getbasetemp()),
        )
        assert result.returncode == 1
        assert "run this installer as root" in result.stderr

    @pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
    def test_rendered_script_reports_its_identity(self, tmp_path):
        path = tmp_path / "installer.sh"
        path.write_bytes(installer.render(_spec(), PACKAGE))
        result = subprocess.run(["bash", str(path), "--help"], capture_output=True, text=True)
        assert result.returncode == 0
        assert "pre-configured by the Seagull server" in result.stdout


class TestBuildInstaller:
    @pytest.fixture(autouse=True)
    def platform(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PUBLIC_HOST", "siem.example.com")
        monkeypatch.setattr(onboarding.certs, "server_ca_bundle", lambda: CA_PEM)
        monkeypatch.setattr(onboarding.certs, "certificate_fingerprint", lambda pem: "ab12")
        monkeypatch.setattr(onboarding, "package_states", list)
        monkeypatch.setattr(packages, "reference", lambda version=None, architecture="amd64": REFERENCE)
        monkeypatch.setattr(packages, "read", lambda ref: PACKAGE)
        monkeypatch.setattr(agents_service.repository, "commit", lambda db: None)
        monkeypatch.setattr(agents_service, "_within_rate_limit", lambda request, **kwargs: True)

    def _token_row(self, raw_token, **overrides):
        salt = "salt-value"
        values = dict(
            id=1,
            agent_id="web-01",
            token_salt=salt,
            token_hash=hash_bootstrap_token(raw_token, salt),
            token_type="enrollment",
            expires_at=datetime.utcnow() + timedelta(minutes=15),
            revoked_at=None,
            revoked_reason=None,
            max_uses=1,
            used_uses=0,
            token_metadata={
                "provisioning": {
                    "profile": "sensor",
                    "architecture": "amd64",
                    "sources": ["authlog", "proc"],
                    "api_url": "https://siem.example.com:8444/agent",
                    "enroll_url": "https://siem.example.com:8445",
                    "version": "0.1.0",
                }
            },
        )
        values.update(overrides)
        return SimpleNamespace(**values)

    def _install(self, monkeypatch, row, agent=SimpleNamespace(agent_id="web-01", is_revoked=False)):
        monkeypatch.setattr(agents_service.repository, "list_bootstrap_tokens", lambda db, agent_id: [row])
        monkeypatch.setattr(agents_service.repository, "get_agent_by_agent_id", lambda db, agent_id: agent)

    def _request(self):
        return SimpleNamespace(
            client=SimpleNamespace(host="203.0.113.10"),
            headers={},
            method="GET",
            url=SimpleNamespace(hostname="siem.example.com", path="/api/agents/installer"),
        )

    def _build(self, raw, audit=None):
        return agents_service.build_installer(
            object(),
            raw_bootstrap_token=raw,
            request=self._request(),
            audit_writer=audit or (lambda db, **kwargs: None),
        )

    def test_builds_a_pre_configured_installer(self, monkeypatch):
        raw, _, _ = generate_bootstrap_token("web-01")
        self._install(monkeypatch, self._token_row(raw))
        audited = []

        name, body = self._build(raw, audit=lambda db, **kwargs: audited.append(kwargs))

        assert name == "seagull-agent-web-01-amd64-installer.sh"
        script = _script(body)
        assert f"EMBEDDED_ENROLLMENT_TOKEN={raw}" in script
        assert "API_URL=https://siem.example.com:8444/agent" in script
        assert _payload(body) == PACKAGE
        assert audited[0]["action"] == "agents.installer.download"
        assert audited[0]["resource_id"] == "web-01"

    def test_uses_the_urls_frozen_when_the_ticket_was_issued(self, monkeypatch):
        raw, _, _ = generate_bootstrap_token("web-01")
        row = self._token_row(raw)
        row.token_metadata["provisioning"]["api_url"] = "https://frozen.example.com:8444/agent"
        row.token_metadata["provisioning"]["enroll_url"] = "https://frozen.example.com:8445"
        self._install(monkeypatch, row)

        _name, body = self._build(raw)
        assert "API_URL=https://frozen.example.com:8444/agent" in _script(body)

    @pytest.mark.parametrize(
        "overrides,detail",
        [
            ({"expires_at": datetime.utcnow() - timedelta(seconds=1)}, "expired"),
            ({"revoked_at": datetime.utcnow(), "revoked_reason": "superseded"}, "revoked"),
            ({"used_uses": 1, "max_uses": 1}, "already consumed"),
            ({"token_type": "renewal"}, "Invalid enrollment token"),
        ],
    )
    def test_refuses_a_token_that_cannot_enroll(self, monkeypatch, overrides, detail):
        raw, _, _ = generate_bootstrap_token("web-01")
        self._install(monkeypatch, self._token_row(raw, **overrides))
        with pytest.raises(HTTPException) as excinfo:
            self._build(raw)
        assert excinfo.value.status_code == 401
        assert detail in str(excinfo.value.detail)

    def test_refuses_an_unknown_token(self, monkeypatch):
        raw, _, _ = generate_bootstrap_token("web-01")
        other, _, _ = generate_bootstrap_token("web-01")
        self._install(monkeypatch, self._token_row(other))
        with pytest.raises(HTTPException) as excinfo:
            self._build(raw)
        assert excinfo.value.status_code == 401

    @pytest.mark.parametrize("raw", ["", "not-a-token", "abt.web-01.short", "abt..secretsecretsecret"])
    def test_refuses_a_malformed_token_without_touching_the_database(self, raw):
        with pytest.raises(HTTPException) as excinfo:
            self._build(raw)
        assert excinfo.value.status_code == 401

    def test_refuses_a_revoked_agent(self, monkeypatch):
        raw, _, _ = generate_bootstrap_token("web-01")
        self._install(monkeypatch, self._token_row(raw), agent=SimpleNamespace(agent_id="web-01", is_revoked=True))
        with pytest.raises(HTTPException) as excinfo:
            self._build(raw)
        assert excinfo.value.status_code == 403

    def test_refuses_a_token_that_was_not_issued_for_provisioning(self, monkeypatch):
        raw, _, _ = generate_bootstrap_token("web-01")
        self._install(monkeypatch, self._token_row(raw, token_metadata={}))
        with pytest.raises(HTTPException) as excinfo:
            self._build(raw)
        assert excinfo.value.status_code == 409
        assert "enrollment ticket" in str(excinfo.value.detail)

    def test_reports_an_unavailable_package(self, monkeypatch):
        raw, _, _ = generate_bootstrap_token("web-01")
        self._install(monkeypatch, self._token_row(raw))

        def unavailable(ref):
            raise packages.PackageUnavailable("fetch_disabled", "package is not available")

        monkeypatch.setattr(packages, "read", unavailable)
        with pytest.raises(HTTPException) as excinfo:
            self._build(raw)
        assert excinfo.value.status_code == 503

    def test_rate_limits_repeated_downloads(self, monkeypatch):
        raw, _, _ = generate_bootstrap_token("web-01")
        self._install(monkeypatch, self._token_row(raw))
        monkeypatch.setattr(
            agents_service,
            "_within_rate_limit",
            lambda request, **kwargs: False,
        )
        with pytest.raises(HTTPException) as excinfo:
            self._build(raw)
        assert excinfo.value.status_code == 429

    def test_does_not_consume_the_enrollment_token(self, monkeypatch):
        raw, _, _ = generate_bootstrap_token("web-01")
        row = self._token_row(raw)
        self._install(monkeypatch, row)
        self._build(raw)
        assert int(row.used_uses) == 0
        assert row.revoked_at is None
