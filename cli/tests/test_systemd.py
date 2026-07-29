from __future__ import annotations

import json
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cli.stack import systemd


def _configure_systemd_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, env_lines: list[str]) -> dict[str, Path]:
    binary = tmp_path / "seagull-agent"
    service = tmp_path / "seagull-agent.service"
    env_file = tmp_path / "agent.env"
    ca_file = tmp_path / "root_ca.crt"
    token_file = tmp_path / "bootstrap.token"
    credential_file = tmp_path / "agent.credential"
    identity_file = tmp_path / "agent.identity.json"

    binary.write_text("binary\n")
    service.write_text("[Service]\n")
    env_file.write_text("\n".join(env_lines) + "\n")
    ca_file.write_text("ca\n")

    monkeypatch.setattr(systemd, "BINARY", binary)
    monkeypatch.setattr(systemd, "SERVICE_FILE", service)
    monkeypatch.setattr(systemd, "ENV_FILE", env_file)
    monkeypatch.setattr(systemd, "CA_DEFAULT", ca_file)
    monkeypatch.setattr(systemd, "TOKEN_DEFAULT", token_file)
    monkeypatch.setattr(systemd, "CREDENTIAL_DEFAULT", credential_file)
    monkeypatch.setattr(systemd, "IDENTITY_STATE_DEFAULT", identity_file)
    monkeypatch.setattr(systemd, "_service_enabled", lambda: True)

    return {
        "binary": binary,
        "service": service,
        "env_file": env_file,
        "ca_file": ca_file,
        "token_file": token_file,
        "credential_file": credential_file,
        "identity_file": identity_file,
    }


def test_validate_rejects_loopback_tls_server_name_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _configure_systemd_install(
        monkeypatch,
        tmp_path,
        [
            "SEAGULL_API_URL=https://127.0.0.1:8443/agent",
            f"SEAGULL_TLS_CA_FILE={tmp_path / 'root_ca.crt'}",
            "SEAGULL_TLS_SERVER_NAME=hexatek.com.br",
            f"SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE={tmp_path / 'bootstrap.token'}",
        ],
    )
    paths["token_file"].write_text("abt.agent-core-1.token\n")

    with pytest.raises(systemd.ValidationError):
        systemd.validate()

    assert "SEAGULL_TLS_SERVER_NAME='hexatek.com.br' is incompatible with loopback API host '127.0.0.1'" in capsys.readouterr().err


def test_validate_rejects_credential_without_recovery_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _configure_systemd_install(
        monkeypatch,
        tmp_path,
        [
            "SEAGULL_API_URL=http://127.0.0.1:8443/agent",
            f"SEAGULL_TLS_CA_FILE={tmp_path / 'root_ca.crt'}",
            f"SEAGULL_AGENT_CREDENTIAL_FILE={tmp_path / 'agent.credential'}",
            f"SEAGULL_AGENT_IDENTITY_STATE_FILE={tmp_path / 'agent.identity.json'}",
        ],
    )
    paths["credential_file"].write_text("agc.agent-core-1.credential\n")
    paths["identity_file"].write_text(json.dumps({"credential": "agc.agent-core-1.credential"}) + "\n")

    with pytest.raises(systemd.ValidationError):
        systemd.validate()

    assert "credential present but no active bootstrap token or renewal token found" in capsys.readouterr().err


def test_validate_accepts_credential_with_active_renewal_token(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _configure_systemd_install(
        monkeypatch,
        tmp_path,
        [
            "SEAGULL_API_URL=http://127.0.0.1:8443/agent",
            f"SEAGULL_TLS_CA_FILE={tmp_path / 'root_ca.crt'}",
            f"SEAGULL_AGENT_CREDENTIAL_FILE={tmp_path / 'agent.credential'}",
            f"SEAGULL_AGENT_IDENTITY_STATE_FILE={tmp_path / 'agent.identity.json'}",
        ],
    )
    paths["credential_file"].write_text("agc.agent-core-1.credential\n")
    future = datetime.now(timezone.utc) + timedelta(days=7)
    paths["identity_file"].write_text(
        json.dumps(
            {
                "credential": "agc.agent-core-1.credential",
                "renewal_token": "abt.agent-core-1.renewal",
                "renewal_token_expires_at": future.isoformat(),
            }
        )
        + "\n"
    )

    systemd.validate()


def test_installed_agent_id_falls_back_to_repo_env_when_env_file_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(systemd, "_read_agent_env", lambda _key: "")
    monkeypatch.setattr(systemd._env, "read", lambda key, default="": "agent-core-from-repo" if key == "AGENT_CORE_ID" else default)

    assert systemd.installed_agent_id() == "agent-core-from-repo"


def test_repo_bootstrap_token_for_agent_uses_matching_repo_mapping(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "AGENT_CORE_ID": "agent-core-1",
        "AGENT_CORE_BOOTSTRAP_TOKEN": "abt.core.token",
        "AGENT_SENSOR_ID": "agent-sensor-1",
        "AGENT_SENSOR_BOOTSTRAP_TOKEN": "abt.sensor.token",
    }
    monkeypatch.setattr(systemd._env, "root", lambda: tmp_path)
    monkeypatch.setattr(systemd._env, "read", lambda key, default="", path=None: values.get(key, default))

    assert systemd.repo_bootstrap_token_for_agent("agent-core-1") == "abt.core.token"
    assert systemd.repo_bootstrap_token_for_agent("agent-sensor-1") == "abt.sensor.token"
    assert systemd.repo_bootstrap_token_for_agent("agent-missing") == ""


def test_validate_live_tls_ignores_transient_loopback_eof(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ca_file = tmp_path / "root_ca.crt"
    ca_file.write_text("ca\n")
    monkeypatch.setattr(systemd, "_read_agent_env", lambda key: "localhost" if key == "SEAGULL_TLS_SERVER_NAME" else "")

    class _FakeContext:
        def wrap_socket(self, _sock, server_hostname=None):
            raise ssl.SSLError("EOF occurred in violation of protocol (_ssl.c:1033)")

    class _FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(systemd.ssl, "create_default_context", lambda cafile=None: _FakeContext())
    monkeypatch.setattr(systemd.socket, "create_connection", lambda *args, **kwargs: _FakeSocket())

    assert systemd._validate_live_tls("https://127.0.0.1:8443/agent", ca_file) is None
