from __future__ import annotations

import ssl
import subprocess

import pytest

from cli.config import env as _env
from cli.security import tokens as _tokens
from cli.stack import prepare as _prepare
from cli.stack import systemd as _systemd


def _mode(path) -> int:
    return path.stat().st_mode & 0o777


class TestEnvFileSecureWrites:
    def test_upsert_creates_env_owner_only(self, tmp_path):
        env = tmp_path / ".env"
        _env.upsert("POSTGRES_PASSWORD", "s3cret-value-1234", path=env)
        assert _mode(env) == 0o600
        assert _env.read("POSTGRES_PASSWORD", path=env) == "s3cret-value-1234"

    def test_upsert_tightens_previously_loose_env(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("EXISTING=1\n")
        env.chmod(0o644)
        _env.upsert("EXISTING", "2", path=env)
        assert _mode(env) == 0o600
        assert _env.read("EXISTING", path=env) == "2"

    def test_bootstrap_creates_env_owner_only(self, tmp_path):
        tmpl = tmp_path / ".env.example"
        env = tmp_path / ".env"
        tmpl.write_text("POSTGRES_DB=seagull\nSEAGULL_JWT_SECRET=abc\n")
        tmpl.chmod(0o644)
        _env.bootstrap(env_file=env, template=tmpl)
        assert _mode(env) == 0o600

    def test_bootstrap_sync_preserves_owner_only_mode(self, tmp_path):
        tmpl = tmp_path / ".env.example"
        env = tmp_path / ".env"
        tmpl.write_text("POSTGRES_DB=seagull\nNEWKEY=added\n")
        env.write_text("POSTGRES_DB=custom\n")
        env.chmod(0o644)
        _env.bootstrap(env_file=env, template=tmpl)
        assert _mode(env) == 0o600
        assert _env.read("POSTGRES_DB", path=env) == "custom"
        assert _env.read("NEWKEY", path=env) == "added"

    def test_bootstrap_is_idempotent_after_hardening(self, tmp_path):
        tmpl = tmp_path / ".env.example"
        env = tmp_path / ".env"
        tmpl.write_text("POSTGRES_DB=seagull\nSEAGULL_JWT_SECRET=abc\n")
        _env.bootstrap(env_file=env, template=tmpl)
        first = env.read_text()
        _env.bootstrap(env_file=env, template=tmpl)
        assert env.read_text() == first

    def test_write_secure_is_atomic_and_leaves_no_temp(self, tmp_path):
        env = tmp_path / ".env"
        _env.write_secure(env, "A=1\n")
        assert env.read_text() == "A=1\n"
        assert _mode(env) == 0o600
        leftovers = list(tmp_path.glob(".*.tmp.*"))
        assert leftovers == []

    def test_enforce_secure_mode_tightens_existing(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("A=1\n")
        env.chmod(0o640)
        _env.enforce_secure_mode(env)
        assert _mode(env) == 0o600

    def test_enforce_secure_mode_missing_file_is_noop(self, tmp_path):
        _env.enforce_secure_mode(tmp_path / "absent.env")


class TestTokenClientTLS:
    def test_https_uses_verifying_context(self, monkeypatch):
        monkeypatch.setattr(_tokens._env, "read", lambda key, default="": "")
        ctx = _tokens._context_for("https://agents.example.com:8444/agent")
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    def test_plain_http_needs_no_context(self, monkeypatch):
        monkeypatch.setattr(_tokens._env, "read", lambda key, default="": "")
        assert _tokens._context_for("http://127.0.0.1:8000") is None

    def test_trust_anchors_include_present_ca(self, tmp_path, monkeypatch):
        ca = tmp_path / "ca.crt"
        ca.write_text("dummy")
        monkeypatch.setattr(_tokens._env, "root", lambda: tmp_path)
        monkeypatch.setattr(
            _tokens._env,
            "read",
            lambda key, default="": "./ca.crt" if key == "SEAGULL_AGENT_SERVER_CA_FILE" else "",
        )
        anchors = _tokens._trust_anchors()
        assert ca in anchors


class TestMintWritesFilesNotEnv:
    def test_mint_writes_token_files_and_never_touches_env(self, tmp_path, monkeypatch):
        values = {
            "SEAGULL_BOOTSTRAP_ADMIN_USERNAME": "admin",
            "SEAGULL_BOOTSTRAP_ADMIN_PASSWORD": "Str0ng!Pass1234",
            "AGENT_CORE_ID": "agent-core-1",
        }
        monkeypatch.setattr(_tokens._env, "read", lambda key, default="": values.get(key, default))
        monkeypatch.setattr(
            _tokens, "_login", lambda *a, **k: ("access-token", "http://127.0.0.1:8000", "")
        )
        monkeypatch.setattr(
            _tokens, "_post_json", lambda *a, **k: (201, {"bootstrap_token": "abt.agent-core-1.secret"})
        )

        def _fail_upsert(*a, **k):
            raise AssertionError("mint must not write tokens into .env")

        monkeypatch.setattr(_tokens._env, "upsert", _fail_upsert)

        out = tmp_path / "bootstrap"
        _tokens.mint(output_dir=out)

        token_file = out / "agent-core-1.token"
        assert token_file.read_text().strip() == "abt.agent-core-1.secret"
        assert _mode(token_file) == 0o600
        assert _mode(out) == 0o700


class TestSystemdTokenHandling:
    def test_repo_token_prefers_bootstrap_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_systemd._env, "root", lambda: tmp_path)
        bootstrap = tmp_path / "secrets" / "bootstrap"
        bootstrap.mkdir(parents=True)
        (bootstrap / "agent-core-1.token").write_text("abt.file.token\n")
        assert _systemd.repo_bootstrap_token_for_agent("agent-core-1") == "abt.file.token"

    def test_repo_token_legacy_env_fallback(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_systemd._env, "root", lambda: tmp_path)
        legacy = {"AGENT_CORE_ID": "agent-core-1", "AGENT_CORE_BOOTSTRAP_TOKEN": "abt.legacy.token"}
        monkeypatch.setattr(_systemd._env, "read", lambda key, default="": legacy.get(key, default))
        assert _systemd.repo_bootstrap_token_for_agent("agent-core-1") == "abt.legacy.token"

    def test_install_keeps_token_out_of_argv(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_systemd._env, "root", lambda: tmp_path)
        captured = {}

        def _fake_run(cmd, cwd=None, env=None):
            captured["cmd"] = cmd
            captured["env"] = env
            return subprocess.CompletedProcess(cmd, 0)

        monkeypatch.setattr(_systemd.subprocess, "run", _fake_run)
        _systemd.install(bootstrap_token="abt.super.secret")

        assert all("abt.super.secret" not in part for part in captured["cmd"])
        assert captured["env"]["SEAGULL_AGENT_BOOTSTRAP_TOKEN"] == "abt.super.secret"
        assert any(part.startswith("--preserve-env=") and "SEAGULL_AGENT_BOOTSTRAP_TOKEN" in part for part in captured["cmd"])


class TestProdPrepareGuards:
    def _use_env_values(self, monkeypatch, values):
        monkeypatch.delenv("SEAGULL_ENV", raising=False)
        monkeypatch.delenv("SEAGULL_MODE", raising=False)
        monkeypatch.setattr(
            _prepare._env, "read", lambda key, default="", path=None: values.get(key, default)
        )

    def test_es_guard_rejects_disabled_security_in_prod(self, monkeypatch):
        values = {"SEAGULL_ENV": "prod", "SEAGULL_SEARCH_BACKEND": "auto", "SEAGULL_ES_SECURITY_ENABLED": "false"}
        self._use_env_values(monkeypatch, values)
        with pytest.raises(RuntimeError, match="Elasticsearch authentication is disabled"):
            _prepare._enforce_es_production_security()

    def test_es_guard_allows_enabled_security(self, monkeypatch):
        values = {"SEAGULL_ENV": "prod", "SEAGULL_SEARCH_BACKEND": "elasticsearch", "SEAGULL_ES_SECURITY_ENABLED": "true"}
        self._use_env_values(monkeypatch, values)
        _prepare._enforce_es_production_security()

    def test_es_guard_skips_postgres_backend(self, monkeypatch):
        values = {"SEAGULL_ENV": "prod", "SEAGULL_SEARCH_BACKEND": "postgres", "SEAGULL_ES_SECURITY_ENABLED": "false"}
        self._use_env_values(monkeypatch, values)
        _prepare._enforce_es_production_security()

    def test_es_guard_skips_dev(self, monkeypatch):
        values = {"SEAGULL_ENV": "dev", "SEAGULL_SEARCH_BACKEND": "auto", "SEAGULL_ES_SECURITY_ENABLED": "false"}
        self._use_env_values(monkeypatch, values)
        _prepare._enforce_es_production_security()

    def test_es_guard_honours_process_environment_over_env_file(self, monkeypatch):
        values = {"SEAGULL_ENV": "dev", "SEAGULL_SEARCH_BACKEND": "auto", "SEAGULL_ES_SECURITY_ENABLED": "false"}
        self._use_env_values(monkeypatch, values)
        monkeypatch.setenv("SEAGULL_ENV", "production")
        with pytest.raises(RuntimeError, match="Elasticsearch authentication is disabled"):
            _prepare._enforce_es_production_security()

    def test_env_file_guard_tightens_loose_mode(self, tmp_path, monkeypatch):
        env = tmp_path / ".env"
        env.write_text("POSTGRES_PASSWORD=x\n")
        env.chmod(0o644)
        monkeypatch.setattr(_prepare._env, "env_path", lambda name=".env": env)
        _prepare._enforce_env_file_security()
        assert _mode(env) == 0o600

    def test_env_file_guard_rejects_foreign_ownership(self, tmp_path, monkeypatch):
        import os

        env = tmp_path / ".env"
        env.write_text("POSTGRES_PASSWORD=x\n")
        real_uid = os.getuid()
        monkeypatch.setattr(_prepare._env, "env_path", lambda name=".env": env)
        monkeypatch.setattr(_prepare.os, "getuid", lambda: real_uid + 1)
        with pytest.raises(RuntimeError, match="owned by uid"):
            _prepare._enforce_env_file_security()


class TestReplicationSecretDelivery:
    def test_replica_start_uses_passfile_not_inline_password(self):
        script = (_env.root() / "infra" / "postgres" / "replica-start.sh").read_text()
        assert "passfile=" in script
        assert "password=$POSTGRES_REPLICATION_PASSWORD" not in script
        assert 'PGPASSFILE="$PASSFILE"' in script

