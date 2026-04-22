from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cli import systemd


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
