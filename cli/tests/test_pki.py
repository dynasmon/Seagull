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

    def test_ensure_agent_pki_normalizes_world_readable_ca_key(self, tmp_path):
        pki.generate_ca(tmp_path)
        (tmp_path / "agent-ca.key").chmod(0o644)
        pki.ensure_agent_pki(tmp_path)
        assert ((tmp_path / "agent-ca.key").stat().st_mode & 0o777) == 0o640

    def test_idempotent_does_not_overwrite(self, tmp_path):
        pki.generate_ca(tmp_path)
        mtime1 = (tmp_path / "agent-ca.key").stat().st_mtime_ns
        pki.ensure_agent_pki(tmp_path)
        mtime2 = (tmp_path / "agent-ca.key").stat().st_mtime_ns
        assert mtime1 == mtime2


class TestLoadCA:
    def test_round_trip(self, tmp_path):
        _, cert = pki.generate_ca(tmp_path)
        _, loaded = pki.load_ca(tmp_path)
        assert loaded.subject == cert.subject
        assert loaded.serial_number == cert.serial_number

    def test_rejects_non_ca(self, tmp_path):
        ca_key, ca_cert = pki.generate_ca(tmp_path)
        pki.issue_agent_cert(ca_key, ca_cert, "agent-x", tmp_path)
        leaf_bytes = (tmp_path / "agents" / "agent-x.crt").read_bytes()
        (tmp_path / "agent-ca.crt").write_bytes(leaf_bytes)
        try:
            pki.load_ca(tmp_path)
            raised = False
        except ValueError:
            raised = True
        assert raised


class TestIssueAgentCert:
    def test_creates_agent_cert(self, tmp_path):
        ca_key, ca_cert = pki.generate_ca(tmp_path)
        cert = pki.issue_agent_cert(ca_key, ca_cert, "agent-core-1", tmp_path)
        assert (tmp_path / "agents" / "agent-core-1.crt").exists()
        assert (tmp_path / "agents" / "agent-core-1.key").exists()
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "agent-core-1"

    def test_client_auth_eku_only(self, tmp_path):
        ca_key, ca_cert = pki.generate_ca(tmp_path)
        cert = pki.issue_agent_cert(ca_key, ca_cert, "agent-core-1", tmp_path)
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value
        assert ExtendedKeyUsageOID.SERVER_AUTH not in eku.value

    def test_agent_cert_is_not_ca(self, tmp_path):
        ca_key, ca_cert = pki.generate_ca(tmp_path)
        cert = pki.issue_agent_cert(ca_key, ca_cert, "agent-x", tmp_path)
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert constraints.value.ca is False

    def test_agent_key_is_owner_only(self, tmp_path):
        ca_key, ca_cert = pki.generate_ca(tmp_path)
        pki.issue_agent_cert(ca_key, ca_cert, "agent-core-1", tmp_path)
        assert ((tmp_path / "agents" / "agent-core-1.key").stat().st_mode & 0o777) == 0o600

    def test_cert_signed_by_ca(self, tmp_path):
        ca_key, ca_cert = pki.generate_ca(tmp_path)
        pki.issue_agent_cert(ca_key, ca_cert, "agent-test-1", tmp_path)
        assert pki.validate_cert_chain(
            tmp_path / "agents" / "agent-test-1.crt", tmp_path / "agent-ca.crt"
        )

    def test_cert_not_signed_by_unrelated_ca(self, tmp_path, tmp_path_factory):
        ca_key, ca_cert = pki.generate_ca(tmp_path)
        pki.issue_agent_cert(ca_key, ca_cert, "agent-test-1", tmp_path)
        other = tmp_path_factory.mktemp("other")
        pki.generate_ca(other)
        assert not pki.validate_cert_chain(
            tmp_path / "agents" / "agent-test-1.crt", other / "agent-ca.crt"
        )


class TestCertRenewal:
    def test_fresh_cert_does_not_need_renewal(self, tmp_path):
        ca_key, ca_cert = pki.generate_ca(tmp_path)
        pki.issue_agent_cert(ca_key, ca_cert, "agent-core-1", tmp_path)
        assert not pki.cert_needs_renewal(tmp_path / "agents" / "agent-core-1.crt", 30)

    def test_short_lived_cert_needs_renewal(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_CERT_VALIDITY_DAYS", "10")
        ca_key, ca_cert = pki.generate_ca(tmp_path)
        pki.issue_agent_cert(ca_key, ca_cert, "agent-core-1", tmp_path)
        assert pki.cert_needs_renewal(tmp_path / "agents" / "agent-core-1.crt", 30)


class TestResolveAgentIds:
    def test_default_ids(self, monkeypatch):
        monkeypatch.delenv("SEAGULL_BOOTSTRAP_ROTATOR_AGENT_IDS", raising=False)
        monkeypatch.setattr(pki._env, "read", lambda key, default="", path=None: default)
        ids = pki.resolve_agent_ids()
        assert "agent-core-1" in ids
        assert "agent-sensor-1" in ids
        assert "agent-vuln-1" in ids

    def test_custom_ids_are_trimmed_and_deduped(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_BOOTSTRAP_ROTATOR_AGENT_IDS", "a-1, b-1 ,a-1,")
        assert pki.resolve_agent_ids() == ["a-1", "b-1"]


class TestEnsureAgentPki:
    def test_full_flow(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_BOOTSTRAP_ROTATOR_AGENT_IDS", "agent-core-1,agent-sensor-1")
        renewed = pki.ensure_agent_pki(tmp_path)
        assert renewed == ["agent-core-1", "agent-sensor-1"]
        assert (tmp_path / "agent-ca.crt").exists()
        for agent_id in ("agent-core-1", "agent-sensor-1"):
            assert (tmp_path / "agents" / f"{agent_id}.crt").exists()
            assert (tmp_path / "agents" / f"{agent_id}.key").exists()
            assert pki.validate_cert_chain(
                tmp_path / "agents" / f"{agent_id}.crt", tmp_path / "agent-ca.crt"
            )

    def test_second_run_is_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_BOOTSTRAP_ROTATOR_AGENT_IDS", "agent-core-1,agent-sensor-1")
        pki.ensure_agent_pki(tmp_path)
        assert pki.ensure_agent_pki(tmp_path) == []

    def test_creates_dirs_with_owner_only_perms(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_BOOTSTRAP_ROTATOR_AGENT_IDS", "agent-core-1")
        sub = tmp_path / "pki"
        pki.ensure_agent_pki(sub)
        assert (sub.stat().st_mode & 0o777) == 0o700
        assert ((sub / "agents").stat().st_mode & 0o777) == 0o700

    def test_reissues_when_ca_is_replaced(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_BOOTSTRAP_ROTATOR_AGENT_IDS", "agent-core-1")
        pki.ensure_agent_pki(tmp_path)
        (tmp_path / "agent-ca.crt").unlink()
        (tmp_path / "agent-ca.key").unlink()
        assert pki.ensure_agent_pki(tmp_path) == ["agent-core-1"]
        assert pki.validate_cert_chain(
            tmp_path / "agents" / "agent-core-1.crt", tmp_path / "agent-ca.crt"
        )


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
        cert = x509.load_pem_x509_certificate((tmp_path / "server" / "mtls.crt").read_bytes())
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value
        assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value

    def test_san_matches_server_names(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "agents.example.com,127.0.0.1")
        pki.ensure_server_pki(tmp_path)
        cert = x509.load_pem_x509_certificate((tmp_path / "server" / "mtls.crt").read_bytes())
        assert pki._cert_san_names(cert) == {"agents.example.com", "127.0.0.1"}

    def test_server_cert_chains_to_server_ca(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        pki.ensure_server_pki(tmp_path)
        assert pki.validate_cert_chain(
            tmp_path / "server" / "mtls.crt", tmp_path / "server-ca.crt"
        )

    def test_server_cert_not_signed_by_agent_ca(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_NAMES", "localhost")
        monkeypatch.setenv("SEAGULL_BOOTSTRAP_ROTATOR_AGENT_IDS", "agent-core-1")
        pki.ensure_agent_pki(tmp_path)
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
        cert = x509.load_pem_x509_certificate((tmp_path / "server" / "mtls.crt").read_bytes())
        assert pki._cert_san_names(cert) == {"agents.example.com"}
