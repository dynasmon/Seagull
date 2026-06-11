from __future__ import annotations

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from cli.security import tls


class TestCertHasSan:
    def test_detects_dns_san(self, tmp_path):
        cert_path = tmp_path / "test.crt"
        key_path = tmp_path / "test.key"
        tls.generate_dev_cert(cert_path, key_path, "myhost.local")
        assert tls.cert_has_san(cert_path, "myhost.local")
        assert tls.cert_has_san(cert_path, "localhost")
        assert not tls.cert_has_san(cert_path, "other.host")

    def test_detects_ip_san(self, tmp_path):
        cert_path = tmp_path / "test.crt"
        key_path = tmp_path / "test.key"
        tls.generate_dev_cert(cert_path, key_path, "192.168.1.100")
        assert tls.cert_has_san(cert_path, "192.168.1.100")
        assert tls.cert_has_san(cert_path, "127.0.0.1")
        assert not tls.cert_has_san(cert_path, "10.0.0.1")

    def test_missing_file_returns_false(self, tmp_path):
        assert not tls.cert_has_san(tmp_path / "nope.crt", "localhost")


class TestGenerateDevCert:
    def test_creates_files(self, tmp_path):
        cert_path = tmp_path / "tls.crt"
        key_path = tmp_path / "tls.key"
        tls.generate_dev_cert(cert_path, key_path, "localhost")
        assert cert_path.exists()
        assert key_path.exists()

    def test_cert_is_self_signed_server_cert(self, tmp_path):
        cert_path = tmp_path / "tls.crt"
        key_path = tmp_path / "tls.key"
        tls.generate_dev_cert(cert_path, key_path, "localhost")
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        assert cert.subject == cert.issuer
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value

    def test_cert_world_readable_key_group_only(self, tmp_path):
        cert_path = tmp_path / "tls.crt"
        key_path = tmp_path / "tls.key"
        tls.generate_dev_cert(cert_path, key_path, "localhost")
        assert tls.is_group_or_world_readable(cert_path)
        key_mode = key_path.stat().st_mode & 0o777
        assert key_mode == 0o640
        assert not (key_mode & 0o004)


class TestPermissionHelpers:
    def test_ensure_readable_makes_readable(self, tmp_path):
        p = tmp_path / "f"
        p.write_text("x")
        p.chmod(0o600)
        tls.ensure_readable(p)
        assert tls.is_group_or_world_readable(p)

    def test_harden_key_perms_tightens_world_readable_key(self, tmp_path):
        p = tmp_path / "k"
        p.write_text("x")
        p.chmod(0o644)
        tls.harden_key_perms(p)
        assert (p.stat().st_mode & 0o777) == 0o640

    def test_harden_key_perms_grants_group_read(self, tmp_path):
        p = tmp_path / "k"
        p.write_text("x")
        p.chmod(0o600)
        tls.harden_key_perms(p)
        assert (p.stat().st_mode & 0o777) == 0o640

    def test_harden_key_perms_idempotent(self, tmp_path):
        p = tmp_path / "k"
        p.write_text("x")
        p.chmod(0o640)
        tls.harden_key_perms(p)
        assert (p.stat().st_mode & 0o777) == 0o640
