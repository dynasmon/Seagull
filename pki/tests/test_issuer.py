from __future__ import annotations

import base64
from datetime import timedelta

import pytest
from conftest import make_csr, write_authority
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from signer import issuer


def _tampered(csr_pem: str) -> str:
    der = bytearray(x509.load_pem_x509_csr(csr_pem.encode()).public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0xFF
    body = base64.encodebytes(bytes(der)).decode()
    return f"-----BEGIN CERTIFICATE REQUEST-----\n{body}-----END CERTIFICATE REQUEST-----\n"


class TestAuthorityLoad:
    def test_missing_material_is_unavailable(self, tmp_path):
        with pytest.raises(issuer.AuthorityUnavailable):
            issuer.Authority.load(tmp_path / "absent.crt", tmp_path / "absent.key")

    def test_unparseable_material_is_unavailable(self, tmp_path):
        (tmp_path / "agent-ca.crt").write_text("not a certificate")
        (tmp_path / "agent-ca.key").write_text("not a key")
        with pytest.raises(issuer.AuthorityUnavailable):
            issuer.Authority.load(tmp_path / "agent-ca.crt", tmp_path / "agent-ca.key")

    def test_leaf_certificate_is_rejected(self, tmp_path):
        write_authority(tmp_path, is_ca=False)
        with pytest.raises(issuer.AuthorityUnavailable):
            issuer.Authority.load(tmp_path / "agent-ca.crt", tmp_path / "agent-ca.key")


class TestIssue:
    def _authority(self, authority_dir):
        return issuer.Authority.load(authority_dir / "agent-ca.crt", authority_dir / "agent-ca.key")

    def test_issues_a_client_certificate(self, authority_dir):
        csr_pem, key = make_csr("agent-core-1")
        issued = self._authority(authority_dir).issue("agent-core-1", csr_pem, 365)
        certificate = x509.load_pem_x509_certificate(issued.certificate_pem.encode())
        ca = x509.load_pem_x509_certificate((authority_dir / "agent-ca.crt").read_bytes())

        assert issued.agent_id == "agent-core-1"
        assert certificate.issuer == ca.subject
        assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "agent-core-1"
        assert certificate.public_key().public_numbers() == key.public_key().public_numbers()
        assert ExtendedKeyUsageOID.CLIENT_AUTH in certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
        assert certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is False

    def test_certificate_verifies_against_the_authority(self, authority_dir):
        csr_pem, _ = make_csr("agent-core-1")
        issued = self._authority(authority_dir).issue("agent-core-1", csr_pem, 365)
        certificate = x509.load_pem_x509_certificate(issued.certificate_pem.encode())
        ca = x509.load_pem_x509_certificate(issued.ca_pem.encode())

        ca.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )

    def test_reported_identity_matches_the_certificate(self, authority_dir):
        csr_pem, _ = make_csr("agent-core-1")
        issued = self._authority(authority_dir).issue("agent-core-1", csr_pem, 365)
        certificate = x509.load_pem_x509_certificate(issued.certificate_pem.encode())

        assert issued.serial_hex == format(certificate.serial_number, "x")
        assert issued.fingerprint_sha256 == certificate.fingerprint(hashes.SHA256()).hex()
        assert issued.subject == certificate.subject.rfc4514_string()

    def test_validity_window_follows_the_configured_days(self, authority_dir):
        csr_pem, _ = make_csr("agent-core-1")
        issued = self._authority(authority_dir).issue("agent-core-1", csr_pem, 7)
        assert timedelta(days=6) < issued.not_after - issued.not_before <= timedelta(days=7, minutes=2)

    def test_accepts_rsa_2048(self, authority_dir):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr_pem, _ = make_csr("agent-core-1", key=key)
        issued = self._authority(authority_dir).issue("agent-core-1", csr_pem, 365)
        assert "BEGIN CERTIFICATE" in issued.certificate_pem

    def test_rejects_a_common_name_the_caller_did_not_ask_for(self, authority_dir):
        csr_pem, _ = make_csr("agent-evil")
        with pytest.raises(issuer.CertificateRequestError) as exc:
            self._authority(authority_dir).issue("agent-core-1", csr_pem, 365)
        assert exc.value.reason == "subject_mismatch"

    def test_rejects_an_agent_id_outside_the_enrollment_pattern(self, authority_dir):
        csr_pem, _ = make_csr("agent core 1")
        with pytest.raises(issuer.CertificateRequestError) as exc:
            self._authority(authority_dir).issue("agent core 1", csr_pem, 365)
        assert exc.value.reason == "invalid_agent_id"

    def test_rejects_invalid_pem(self, authority_dir):
        with pytest.raises(issuer.CertificateRequestError) as exc:
            self._authority(authority_dir).issue("agent-core-1", "not a csr", 365)
        assert exc.value.reason == "invalid_pem"

    def test_rejects_a_forged_signature(self, authority_dir):
        csr_pem, _ = make_csr("agent-core-1")
        with pytest.raises(issuer.CertificateRequestError) as exc:
            self._authority(authority_dir).issue("agent-core-1", _tampered(csr_pem), 365)
        assert exc.value.reason == "invalid_signature"

    def test_rejects_weak_rsa(self, authority_dir):
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        csr_pem, _ = make_csr("agent-core-1", key=key)
        with pytest.raises(issuer.CertificateRequestError) as exc:
            self._authority(authority_dir).issue("agent-core-1", csr_pem, 365)
        assert exc.value.reason == "weak_key"

    def test_rejects_an_unlisted_curve(self, authority_dir):
        key = ec.generate_private_key(ec.SECP224R1())
        csr_pem, _ = make_csr("agent-core-1", key=key)
        with pytest.raises(issuer.CertificateRequestError) as exc:
            self._authority(authority_dir).issue("agent-core-1", csr_pem, 365)
        assert exc.value.reason == "weak_key"

    def test_rejects_an_unsupported_key_type(self, authority_dir):
        key = ed25519.Ed25519PrivateKey.generate()
        csr_pem, _ = make_csr("agent-core-1", key=key)
        with pytest.raises(issuer.CertificateRequestError) as exc:
            self._authority(authority_dir).issue("agent-core-1", csr_pem, 365)
        assert exc.value.reason == "unsupported_key"
