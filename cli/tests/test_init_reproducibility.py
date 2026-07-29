from __future__ import annotations

import os

import pytest

from cli.config import env as _env
from cli.security import pki, secrets as _secrets, tls
from cli.stack import compose as _compose


def _write_min_template(path):
    path.write_text(
        "SEAGULL_MODE=dev\n"
        "POSTGRES_DB=seagull\n"
        "POSTGRES_USER=seagull\n"
        "POSTGRES_PASSWORD=seagull123\n"
        "SEAGULL_JWT_SECRET=change_me_dev_jwt_secret_at_least_32_chars_long\n"
        "SEAGULL_BOOTSTRAP_ADMIN_PASSWORD=NwPortal!9342Qx\n"
    )


class TestEnvBootstrap:
    def test_creates_env_from_template_on_fresh_machine(self, tmp_path):
        tmpl = tmp_path / ".env.example"
        env = tmp_path / ".env"
        _write_min_template(tmpl)
        _env.bootstrap(env_file=env, template=tmpl)
        assert env.exists()
        assert _env.read("POSTGRES_DB", path=env) == "seagull"

    def test_is_idempotent(self, tmp_path):
        tmpl = tmp_path / ".env.example"
        env = tmp_path / ".env"
        _write_min_template(tmpl)
        _env.bootstrap(env_file=env, template=tmpl)
        first = env.read_text()
        _env.bootstrap(env_file=env, template=tmpl)
        assert env.read_text() == first

    def test_syncs_missing_keys_into_existing_env(self, tmp_path):
        tmpl = tmp_path / ".env.example"
        env = tmp_path / ".env"
        _write_min_template(tmpl)
        env.write_text("POSTGRES_DB=custom\n")
        _env.bootstrap(env_file=env, template=tmpl)
        assert _env.read("POSTGRES_DB", path=env) == "custom"
        assert _env.read("SEAGULL_JWT_SECRET", path=env) != ""

    def test_missing_template_raises_clearly(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            _env.bootstrap(env_file=tmp_path / ".env", template=tmp_path / "nope.example")


class TestShippedTemplatePassesDevPreflight:
    def test_jwt_secret_long_enough(self):
        tmpl = _env.env_path(".env.example")
        jwt = _env.read("SEAGULL_JWT_SECRET", path=tmpl)
        assert len(jwt) >= 32

    def test_admin_password_passes_policy(self):
        tmpl = _env.env_path(".env.example")
        user = _env.read("SEAGULL_BOOTSTRAP_ADMIN_USERNAME", "admin", path=tmpl)
        pw = _env.read("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD", path=tmpl)
        assert pw, "shipped .env.example must set a dev admin password"
        assert _secrets.validate_password_policy("admin", user, pw) is None


class TestFreshHostArtifacts:
    def test_full_pki_and_tls_init_produces_no_world_readable_keys(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        pki_dir = tmp_path / "secrets" / "pki"
        tls_dir = tmp_path / "secrets" / "tls"

        pki.ensure_agent_ca(pki_dir)
        pki.ensure_server_pki(pki_dir)
        tls.generate_dev_cert(tls_dir / "tls.crt", tls_dir / "tls.key", "localhost")

        mounted = [
            pki_dir / "agent-ca.crt",
            pki_dir / "agent-ca.key",
            pki_dir / "server" / "mtls.crt",
            pki_dir / "server" / "mtls.key",
            tls_dir / "tls.crt",
            tls_dir / "tls.key",
        ]
        for path in mounted:
            assert path.exists(), f"fresh init must produce {path}"

        private_keys = [
            pki_dir / "agent-ca.key",
            pki_dir / "server" / "mtls.key",
            pki_dir / "server-ca.key",
            tls_dir / "tls.key",
        ]
        for key in private_keys:
            mode = key.stat().st_mode & 0o777
            assert not (mode & 0o004), f"{key} is world-readable ({oct(mode)})"

    def test_pki_group_id_matches_generated_key_group(self, tmp_path, monkeypatch):
        pki_dir = tmp_path / "secrets" / "pki"
        pki.ensure_agent_ca(pki_dir)
        monkeypatch.setattr(_compose._env, "root", lambda: tmp_path)
        assert _compose.pki_group_id() == os.stat(pki_dir / "agent-ca.key").st_gid

    def test_pki_group_id_safe_before_any_generation(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_compose._env, "root", lambda: tmp_path)
        assert _compose.pki_group_id() == os.getgid()

    def test_pki_init_is_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        pki_dir = tmp_path / "secrets" / "pki"
        pki.ensure_agent_ca(pki_dir)
        pki.ensure_server_pki(pki_dir)
        ca_mtime = (pki_dir / "agent-ca.key").stat().st_mtime_ns
        assert pki.ensure_server_pki(pki_dir) is False
        pki.ensure_agent_ca(pki_dir)
        assert (pki_dir / "agent-ca.key").stat().st_mtime_ns == ca_mtime


class TestEnvironmentMode:
    def _clear_process_env(self, monkeypatch):
        monkeypatch.delenv("SEAGULL_ENV", raising=False)
        monkeypatch.delenv("SEAGULL_MODE", raising=False)

    def test_defaults_to_dev_without_env_file(self, tmp_path, monkeypatch):
        self._clear_process_env(monkeypatch)
        assert _env.environment(path=tmp_path / ".env") == "dev"
        assert _env.is_production(path=tmp_path / ".env") is False

    def test_reads_production_from_env_file(self, tmp_path, monkeypatch):
        self._clear_process_env(monkeypatch)
        env = tmp_path / ".env"
        env.write_text("SEAGULL_ENV=production\n")
        assert _env.is_production(path=env) is True

    def test_accepts_prod_alias(self, tmp_path, monkeypatch):
        self._clear_process_env(monkeypatch)
        env = tmp_path / ".env"
        env.write_text("SEAGULL_ENV=Prod\n")
        assert _env.is_production(path=env) is True

    def test_process_env_overrides_env_file(self, tmp_path, monkeypatch):
        env = tmp_path / ".env"
        env.write_text("SEAGULL_ENV=production\n")
        monkeypatch.setenv("SEAGULL_ENV", "dev")
        assert _env.is_production(path=env) is False

    def test_falls_back_to_legacy_mode_key(self, tmp_path, monkeypatch):
        self._clear_process_env(monkeypatch)
        env = tmp_path / ".env"
        env.write_text("SEAGULL_MODE=prod\n")
        assert _env.is_production(path=env) is True

    def test_env_key_wins_over_legacy_mode_key(self, tmp_path, monkeypatch):
        self._clear_process_env(monkeypatch)
        env = tmp_path / ".env"
        env.write_text("SEAGULL_ENV=dev\nSEAGULL_MODE=prod\n")
        assert _env.is_production(path=env) is False
