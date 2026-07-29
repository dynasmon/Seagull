from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def default_dev_environment(monkeypatch):
    monkeypatch.setenv("SEAGULL_ENV", "dev")
