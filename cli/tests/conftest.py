from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def default_dev_environment(monkeypatch):
    monkeypatch.setenv("SEAGULL_ENV", "dev")
    monkeypatch.setenv("SEAGULL_AGENT_CA_VALIDITY_DAYS", "3650")
    monkeypatch.setenv("SEAGULL_SERVER_CA_VALIDITY_DAYS", "3650")
    monkeypatch.setenv("SEAGULL_SERVER_CERT_KEY_SIZE", "2048")
    monkeypatch.setenv("SEAGULL_SERVER_CERT_VALIDITY_DAYS", "365")
    monkeypatch.setenv("SEAGULL_SERVER_CERT_RENEW_BEFORE_DAYS", "30")
