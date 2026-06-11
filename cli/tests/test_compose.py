from __future__ import annotations

import os

from cli.stack import compose as _compose


def test_pki_group_id_returns_agent_ca_key_group(tmp_path, monkeypatch):
    pki_dir = tmp_path / "secrets" / "pki"
    pki_dir.mkdir(parents=True)
    key = pki_dir / "agent-ca.key"
    key.write_text("x")
    monkeypatch.setattr(_compose._env, "root", lambda: tmp_path)
    assert _compose.pki_group_id() == os.stat(key).st_gid


def test_pki_group_id_falls_back_to_process_gid(tmp_path, monkeypatch):
    monkeypatch.setattr(_compose._env, "root", lambda: tmp_path)
    assert _compose.pki_group_id() == os.getgid()


def test_run_injects_pki_gid(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, cwd, env, check):
        captured["env"] = env
        return None

    monkeypatch.setattr(_compose._env, "root", lambda: tmp_path)
    monkeypatch.setattr(_compose.subprocess, "run", fake_run)
    _compose.run(["compose.yml"], ["config", "-q"])
    assert captured["env"]["SEAGULL_PKI_GID"] == str(os.getgid())


def test_run_respects_preset_pki_gid(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, cwd, env, check):
        captured["env"] = env
        return None

    monkeypatch.setattr(_compose._env, "root", lambda: tmp_path)
    monkeypatch.setattr(_compose.subprocess, "run", fake_run)
    monkeypatch.setenv("SEAGULL_PKI_GID", "4242")
    _compose.run(["compose.yml"], ["config", "-q"])
    assert captured["env"]["SEAGULL_PKI_GID"] == "4242"
