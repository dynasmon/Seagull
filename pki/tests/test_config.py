from __future__ import annotations

import pytest

from signer import config as _config

TOKEN = "t" * 40


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for name in (
        "SEAGULL_PKI_SIGNER_TOKEN",
        "SEAGULL_PKI_SIGNER_TOKEN_FILE",
        "SEAGULL_PKI_SIGNER_HOST",
        "SEAGULL_PKI_SIGNER_PORT",
        "SEAGULL_PKI_SIGNER_MAX_BODY_BYTES",
        "SEAGULL_AGENT_MTLS_CA_CERT_FILE",
        "SEAGULL_AGENT_MTLS_CA_KEY_FILE",
        "SEAGULL_AGENT_CERT_VALIDITY_DAYS",
    ):
        monkeypatch.delenv(name, raising=False)


class TestLoad:
    def test_refuses_a_missing_token(self):
        with pytest.raises(_config.ConfigurationError) as exc:
            _config.load()
        assert "SEAGULL_PKI_SIGNER_TOKEN" in str(exc.value)

    def test_refuses_a_short_token(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_TOKEN", "short")
        with pytest.raises(_config.ConfigurationError):
            _config.load()

    def test_reads_the_token_from_a_file(self, tmp_path, monkeypatch):
        token_file = tmp_path / "signer.token"
        token_file.write_text(f"{TOKEN}\n")
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_TOKEN_FILE", str(token_file))
        assert _config.load().token == TOKEN

    def test_reports_an_unreadable_token_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_TOKEN_FILE", str(tmp_path / "absent"))
        with pytest.raises(_config.ConfigurationError) as exc:
            _config.load()
        assert "SEAGULL_PKI_SIGNER_TOKEN_FILE" in str(exc.value)

    def test_defaults_stay_on_the_documented_values(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_TOKEN", TOKEN)
        settings = _config.load()
        assert settings.host == _config.DEFAULT_HOST
        assert settings.port == _config.DEFAULT_PORT
        assert settings.validity_days == _config.DEFAULT_VALIDITY_DAYS
        assert settings.max_body_bytes == _config.DEFAULT_MAX_BODY_BYTES
        assert str(settings.ca_key_file) == _config.DEFAULT_CA_KEY_FILE

    def test_refuses_a_non_numeric_port(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_TOKEN", TOKEN)
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_PORT", "eight thousand")
        with pytest.raises(_config.ConfigurationError):
            _config.load()

    def test_refuses_a_zero_validity(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_TOKEN", TOKEN)
        monkeypatch.setenv("SEAGULL_AGENT_CERT_VALIDITY_DAYS", "0")
        with pytest.raises(_config.ConfigurationError):
            _config.load()
