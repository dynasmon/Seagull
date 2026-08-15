from __future__ import annotations

import pytest

from cli.config import env as _env
from cli.stack import preflight as _preflight


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    monkeypatch.setattr(_env, "ROOT", tmp_path)
    path = tmp_path / ".env"
    path.write_text("SEAGULL_ENV=dev\n")
    return path


class TestLoopbackPublish:
    @pytest.mark.parametrize(
        "value",
        ["", "127.0.0.1:8000", "127.0.0.2:8000", "[::1]:8000", "localhost:8000"],
    )
    def test_accepts_loopback_and_unset(self, value):
        assert _preflight._is_loopback_publish(value) is True

    @pytest.mark.parametrize("value", ["8000", "0.0.0.0:8000", "192.168.1.10:8000", ":8000"])
    def test_rejects_every_other_bind(self, value):
        assert _preflight._is_loopback_publish(value) is False


class TestExposedInternalPorts:
    def test_reports_nothing_for_a_loopback_stack(self, env_file):
        for name in _preflight.INTERNAL_PORT_VARS:
            _env.upsert(name, "127.0.0.1:1", path=env_file)
        assert _preflight.exposed_internal_ports() == []

    def test_reports_each_service_published_to_the_network(self, env_file):
        _env.upsert("SEAGULL_BACKEND_PORT", "0.0.0.0:8000", path=env_file)
        _env.upsert("ELASTICSEARCH_PORT", "9200", path=env_file)
        assert _preflight.exposed_internal_ports() == ["SEAGULL_BACKEND_PORT", "ELASTICSEARCH_PORT"]

    def test_an_empty_value_is_not_an_exposure(self, env_file):
        _env.upsert("CLICKHOUSE_HTTP_PORT", "", path=env_file)
        assert _preflight.exposed_internal_ports() == []


class TestInternalExposureGate:
    def test_production_refuses_to_start(self, env_file, monkeypatch):
        monkeypatch.setenv("SEAGULL_ENV", "prod")
        _env.upsert("SEAGULL_BACKEND_PORT", "0.0.0.0:8000", path=env_file)
        with pytest.raises(RuntimeError) as exc:
            _preflight._check_internal_exposure()
        assert "SEAGULL_BACKEND_PORT" in str(exc.value)

    def test_development_only_warns(self, env_file, capsys):
        _env.upsert("SEAGULL_PORTAL_PORT", "8080", path=env_file)
        _preflight._check_internal_exposure()
        assert "SEAGULL_PORTAL_PORT" in capsys.readouterr().out

    def test_a_loopback_production_stack_passes(self, env_file, monkeypatch):
        monkeypatch.setenv("SEAGULL_ENV", "prod")
        _env.upsert("SEAGULL_BACKEND_PORT", "127.0.0.1:8000", path=env_file)
        _preflight._check_internal_exposure()


class TestSignerToken:
    def test_generates_a_token_when_absent(self, env_file):
        _preflight._ensure_signer_token()
        token = _env.read("SEAGULL_PKI_SIGNER_TOKEN", path=env_file)
        assert len(token) >= _preflight.MIN_SIGNER_TOKEN_LENGTH

    def test_keeps_an_existing_token(self, env_file):
        _env.upsert("SEAGULL_PKI_SIGNER_TOKEN", "k" * 48, path=env_file)
        _preflight._ensure_signer_token()
        assert _env.read("SEAGULL_PKI_SIGNER_TOKEN", path=env_file) == "k" * 48

    def test_refuses_a_short_token(self, env_file):
        _env.upsert("SEAGULL_PKI_SIGNER_TOKEN", "short", path=env_file)
        with pytest.raises(RuntimeError):
            _preflight._ensure_signer_token()

    def test_accepts_a_token_file(self, env_file, tmp_path):
        token_file = tmp_path / "signer.token"
        token_file.write_text("f" * 48)
        _env.upsert("SEAGULL_PKI_SIGNER_TOKEN_FILE", str(token_file), path=env_file)
        _preflight._ensure_signer_token()
        assert _env.read("SEAGULL_PKI_SIGNER_TOKEN", path=env_file) == ""

    def test_refuses_a_missing_token_file(self, env_file, tmp_path):
        _env.upsert("SEAGULL_PKI_SIGNER_TOKEN_FILE", str(tmp_path / "absent"), path=env_file)
        with pytest.raises(RuntimeError):
            _preflight._ensure_signer_token()
