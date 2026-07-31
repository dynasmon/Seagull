from __future__ import annotations

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from cli.security import pki


class TestGenerateCA:
    def test_creates_ca_files(self, tmp_path):
        key, cert = pki.generate_ca(tmp_path)
        assert (tmp_path / "agent-ca.key").exists()
        assert (tmp_path / "agent-ca.crt").exists()
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "Seagull Agent CA"

    def test_ca_is_marked_as_ca(self, tmp_path):
        _, cert = pki.generate_ca(tmp_path)
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert constraints.value.ca is True
        assert constraints.value.path_length == 0

    def test_ca_key_is_group_readable_not_world(self, tmp_path):
        pki.generate_ca(tmp_path)
        assert ((tmp_path / "agent-ca.key").stat().st_mode & 0o777) == 0o640

    def test_ensure_agent_ca_normalizes_world_readable_ca_key(self, tmp_path):
        pki.generate_ca(tmp_path)
        (tmp_path / "agent-ca.key").chmod(0o644)
        pki.ensure_agent_ca(tmp_path)
        assert ((tmp_path / "agent-ca.key").stat().st_mode & 0o777) == 0o640

    def test_idempotent_does_not_overwrite(self, tmp_path):
        pki.generate_ca(tmp_path)
        mtime1 = (tmp_path / "agent-ca.key").stat().st_mtime_ns
        pki.ensure_agent_ca(tmp_path)
        mtime2 = (tmp_path / "agent-ca.key").stat().st_mtime_ns
        assert mtime1 == mtime2


class TestLoadCA:
    def test_round_trip(self, tmp_path):
        _, cert = pki.generate_ca(tmp_path)
        _, loaded = pki.load_ca(tmp_path)
        assert loaded.subject == cert.subject
        assert loaded.serial_number == cert.serial_number

    def test_rejects_non_ca(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        pki.ensure_server_pki(tmp_path)
        leaf_bytes = (tmp_path / "server" / "mtls.crt").read_bytes()
        pki.generate_ca(tmp_path)
        (tmp_path / "agent-ca.crt").write_bytes(leaf_bytes)
        try:
            pki.load_ca(tmp_path)
            raised = False
        except ValueError:
            raised = True
        assert raised


class TestEnsureAgentCA:
    def test_creates_ca_when_missing(self, tmp_path):
        sub = tmp_path / "pki"
        assert pki.ensure_agent_ca(sub) is True
        assert (sub / "agent-ca.crt").exists()
        assert (sub / "agent-ca.key").exists()
        assert (sub.stat().st_mode & 0o777) == 0o700

    def test_second_run_is_idempotent(self, tmp_path):
        pki.ensure_agent_ca(tmp_path)
        assert pki.ensure_agent_ca(tmp_path) is False

    def test_does_not_issue_agent_client_keys(self, tmp_path):
        pki.ensure_agent_ca(tmp_path)
        assert not (tmp_path / "agents").exists()


class TestCertRenewal:
    def test_fresh_cert_does_not_need_renewal(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        pki.ensure_server_pki(tmp_path)
        assert not pki.cert_needs_renewal(tmp_path / "server" / "mtls.crt", 30)

    def test_short_lived_cert_needs_renewal(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        monkeypatch.setenv("SEAGULL_SERVER_CERT_VALIDITY_DAYS", "10")
        pki.ensure_server_pki(tmp_path)
        assert pki.cert_needs_renewal(tmp_path / "server" / "mtls.crt", 30)


class TestServerPki:
    def test_creates_server_ca_and_cert(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost,127.0.0.1")
        assert pki.ensure_server_pki(tmp_path) is True
        assert (tmp_path / "server-ca.crt").exists()
        assert (tmp_path / "server-ca.key").exists()
        assert (tmp_path / "server" / "mtls.crt").exists()
        assert (tmp_path / "server" / "mtls.key").exists()

    def test_server_auth_eku_only(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        pki.ensure_server_pki(tmp_path)
        cert = x509.load_pem_x509_certificate(
            (tmp_path / "server" / "mtls.crt").read_bytes()
        )
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value
        assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value

    def test_san_matches_server_names(self, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "SEAGULL_AGENT_MTLS_SERVER_NAMES", "agents.example.com,127.0.0.1"
        )
        pki.ensure_server_pki(tmp_path)
        cert = x509.load_pem_x509_certificate(
            (tmp_path / "server" / "mtls.crt").read_bytes()
        )
        assert pki._cert_san_names(cert) == {"agents.example.com", "127.0.0.1"}

    def test_server_cert_chains_to_server_ca(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        pki.ensure_server_pki(tmp_path)
        assert pki.validate_cert_chain(
            tmp_path / "server" / "mtls.crt", tmp_path / "server-ca.crt"
        )

    def test_server_cert_not_signed_by_agent_ca(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        pki.ensure_agent_ca(tmp_path)
        pki.ensure_server_pki(tmp_path)
        assert not pki.validate_cert_chain(
            tmp_path / "server" / "mtls.crt", tmp_path / "agent-ca.crt"
        )

    def test_server_key_is_group_readable_in_locked_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        pki.ensure_server_pki(tmp_path)
        key_mode = (tmp_path / "server" / "mtls.key").stat().st_mode & 0o777
        dir_mode = (tmp_path / "server").stat().st_mode & 0o777
        assert key_mode == 0o640
        assert dir_mode == 0o700

    def test_server_ca_key_stays_owner_only(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        pki.ensure_server_pki(tmp_path)
        assert ((tmp_path / "server-ca.key").stat().st_mode & 0o777) == 0o600

    def test_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        pki.ensure_server_pki(tmp_path)
        assert pki.ensure_server_pki(tmp_path) is False

    def test_reissues_on_san_change(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        pki.ensure_server_pki(tmp_path)
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "agents.example.com")
        assert pki.ensure_server_pki(tmp_path) is True
        cert = x509.load_pem_x509_certificate(
            (tmp_path / "server" / "mtls.crt").read_bytes()
        )
        assert pki._cert_san_names(cert) == {"agents.example.com"}


class TestProductionServerNames:
    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pki._env, "ROOT", tmp_path)
        for key in (
            "SEAGULL_CADDY_DOMAIN",
            "SEAGULL_AGENT_PUBLIC_HOST",
            "SEAGULL_AGENT_MTLS_SERVER_NAMES",
            "SEAGULL_MODE",
        ):
            monkeypatch.delenv(key, raising=False)

    def test_dev_ignores_the_edge_hostname(self, tmp_path, monkeypatch):
        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setenv("SEAGULL_CADDY_DOMAIN", "seagull.example.com")
        assert pki.resolve_server_names() == ["localhost", "127.0.0.1"]

    def test_production_leads_with_the_edge_hostname(self, tmp_path, monkeypatch):
        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setenv("SEAGULL_ENV", "production")
        monkeypatch.setenv("SEAGULL_CADDY_DOMAIN", "seagull.example.com")
        assert pki.resolve_server_names() == [
            "seagull.example.com",
            "localhost",
            "127.0.0.1",
        ]

    def test_production_covers_the_agent_public_host(self, tmp_path, monkeypatch):
        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setenv("SEAGULL_ENV", "prod")
        monkeypatch.setenv("SEAGULL_AGENT_PUBLIC_HOST", "agents.example.com")
        assert "agents.example.com" in pki.resolve_server_names()

    def test_production_normalizes_bracketed_ipv6_for_certificate_san(
        self, tmp_path, monkeypatch
    ):
        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setenv("SEAGULL_ENV", "prod")
        monkeypatch.setenv("SEAGULL_AGENT_PUBLIC_HOST", "[2001:db8::10]")
        pki_dir = tmp_path / "pki"
        pki.ensure_server_pki(pki_dir)
        cert = x509.load_pem_x509_certificate(
            (pki_dir / "server" / "mtls.crt").read_bytes()
        )
        assert "2001:db8::10" in pki._cert_san_names(cert)

    def test_production_does_not_duplicate_configured_names(
        self, tmp_path, monkeypatch
    ):
        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setenv("SEAGULL_ENV", "production")
        monkeypatch.setenv("SEAGULL_CADDY_DOMAIN", "seagull.example.com")
        monkeypatch.setenv("SEAGULL_AGENT_PUBLIC_HOST", "seagull.example.com")
        monkeypatch.setenv(
            "SEAGULL_AGENT_MTLS_SERVER_NAMES", "seagull.example.com,localhost"
        )
        assert pki.resolve_server_names() == ["seagull.example.com", "localhost"]

    def test_production_cert_is_issued_for_the_edge_hostname(
        self, tmp_path, monkeypatch
    ):
        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setenv("SEAGULL_ENV", "production")
        monkeypatch.setenv("SEAGULL_CADDY_DOMAIN", "seagull.example.com")
        pki_dir = tmp_path / "pki"
        pki.ensure_server_pki(pki_dir)
        cert = x509.load_pem_x509_certificate(
            (pki_dir / "server" / "mtls.crt").read_bytes()
        )
        assert "seagull.example.com" in pki._cert_san_names(cert)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "seagull.example.com"

    def test_localhost_only_cert_is_reissued_after_switching_to_production(
        self, tmp_path, monkeypatch
    ):
        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setenv("SEAGULL_CADDY_DOMAIN", "seagull.example.com")
        pki_dir = tmp_path / "pki"
        pki.ensure_server_pki(pki_dir)
        monkeypatch.setenv("SEAGULL_ENV", "production")
        assert pki.ensure_server_pki(pki_dir) is True
        cert = x509.load_pem_x509_certificate(
            (pki_dir / "server" / "mtls.crt").read_bytes()
        )
        assert "seagull.example.com" in pki._cert_san_names(cert)


class TestValidateEdgeCoverage:
    def test_dev_without_edge_hostname_is_allowed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pki._env, "ROOT", tmp_path)
        for key in ("SEAGULL_CADDY_DOMAIN", "SEAGULL_AGENT_PUBLIC_HOST"):
            monkeypatch.delenv(key, raising=False)
        pki.validate_edge_coverage("preflight")

    def test_production_without_edge_hostname_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pki._env, "ROOT", tmp_path)
        for key in ("SEAGULL_CADDY_DOMAIN", "SEAGULL_AGENT_PUBLIC_HOST"):
            monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("SEAGULL_ENV", "production")
        try:
            pki.validate_edge_coverage("prod-prepare")
            raised = False
        except RuntimeError as exc:
            raised = "SEAGULL_AGENT_PUBLIC_HOST" in str(exc)
        assert raised
