from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

from cli.config import env as _env
from cli.stack import compose as _compose

COMPOSE_FILES = ("compose.yml", "compose.dev-reload.yml")

_INTERP_RE = re.compile(r"(?<!\$)\$\{([^}]+)\}")
_BARE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _bare_vars(text: str) -> set[str]:
    bare: set[str] = set()
    for expr in _INTERP_RE.findall(text):
        if _BARE_RE.match(expr):
            bare.add(expr)
    return bare


def _env_example_keys() -> set[str]:
    keys: set[str] = set()
    for line in _env.env_path(".env.example").read_text().splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line)
        if m:
            keys.add(m.group(1))
    return keys


class TestComposeVariableDefaults:
    def test_every_defaultless_compose_var_is_in_env_example(self):
        keys = _env_example_keys()
        offenders: dict[str, set[str]] = {}
        for fname in COMPOSE_FILES:
            path = _env.env_path(fname)
            if not path.exists():
                continue
            missing = {v for v in _bare_vars(path.read_text()) if v not in keys}
            if missing:
                offenders[fname] = missing
        assert not offenders, (
            "compose vars without a ${VAR:-default} that are also absent from "
            f".env.example (would interpolate to empty on a fresh machine): {offenders}"
        )

    def test_bare_var_detection_ignores_escaped_dollar(self):
        assert _bare_vars('cmd "$${SHELL_VAR}" and "${REAL_VAR}"') == {"REAL_VAR"}

    def test_bare_var_detection_ignores_defaulted(self):
        assert _bare_vars("${A:-x} ${B:?err} ${C-y} ${D}") == {"D"}


class TestDockerComposeConfig:
    def _docker_ready(self) -> bool:
        if not shutil.which("docker"):
            return False
        return subprocess.run(["docker", "info"], capture_output=True).returncode == 0

    def test_compose_config_valid_with_env_example(self):
        if not self._docker_ready():
            pytest.skip("docker daemon not available")
        root = _env.root()
        env = {**os.environ}
        env.setdefault("SEAGULL_PKI_GID", "0")
        result = subprocess.run(
            ["docker", "compose", "--env-file", ".env.example", "-f", "compose.yml", "config", "-q"],
            cwd=str(root),
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

    def test_run_injects_pki_gid_for_every_command(self, tmp_path, monkeypatch):
        captured = {}
        monkeypatch.setattr(_compose._env, "root", lambda: tmp_path)
        monkeypatch.setattr(
            _compose.subprocess, "run",
            lambda cmd, cwd, env, check: captured.update(env=env),
        )
        _compose.run(["compose.yml"], ["ps"])
        assert "SEAGULL_PKI_GID" in captured["env"]
