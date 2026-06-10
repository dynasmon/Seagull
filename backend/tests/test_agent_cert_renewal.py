from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import HTTPException

from app.features.agents import auth, certs


def _make_ca(tmp_path, common_name="Seagull Agent CA"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "agent-ca.crt"
    key_path = tmp_path / "agent-ca.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert, cert_path, key_path


def _make_csr_pem(agent_id, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Seagull Agents"),
                    x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"), key


@pytest.fixture
def signing_ca(tmp_path, monkeypatch):
    cert, cert_path, key_path = _make_ca(tmp_path)
    monkeypatch.setenv("SEAGULL_AGENT_MTLS_CA_CERT_FILE", str(cert_path))
    monkeypatch.setenv("SEAGULL_AGENT_MTLS_CA_KEY_FILE", str(key_path))
    monkeypatch.delenv("SEAGULL_AGENT_CERT_RENEWAL", raising=False)
    monkeypatch.delenv("SEAGULL_AGENT_CERT_VALIDITY_DAYS", raising=False)
    return cert


class TestValidateCsr:
    def test_accepts_ec_p256(self):
        csr_pem, _ = _make_csr_pem("agent-core-1")
        csr = certs.validate_csr(csr_pem, "agent-core-1")
        assert isinstance(csr.public_key(), ec.EllipticCurvePublicKey)

    def test_accepts_rsa_2048(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr_pem, _ = _make_csr_pem("agent-core-1", key=key)
        csr = certs.validate_csr(csr_pem, "agent-core-1")
        assert isinstance(csr.public_key(), rsa.RSAPublicKey)

    def test_rejects_invalid_pem(self):
        with pytest.raises(certs.CertificateRequestError) as exc:
            certs.validate_csr("not a csr", "agent-core-1")
        assert exc.value.reason == "invalid_pem"

    def test_rejects_cn_mismatch(self):
        csr_pem, _ = _make_csr_pem("agent-evil")
        with pytest.raises(certs.CertificateRequestError) as exc:
            certs.validate_csr(csr_pem, "agent-core-1")
        assert exc.value.reason == "subject_mismatch"

    def test_rejects_weak_rsa(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        csr_pem, _ = _make_csr_pem("agent-core-1", key=key)
        with pytest.raises(certs.CertificateRequestError) as exc:
            certs.validate_csr(csr_pem, "agent-core-1")
        assert exc.value.reason == "weak_key"

    def test_rejects_unlisted_curve(self):
        key = ec.generate_private_key(ec.SECP224R1())
        csr_pem, _ = _make_csr_pem("agent-core-1", key=key)
        with pytest.raises(certs.CertificateRequestError) as exc:
            certs.validate_csr(csr_pem, "agent-core-1")
        assert exc.value.reason == "weak_key"


class TestRenewAgentCertificate:
    def test_issues_client_cert(self, signing_ca):
        csr_pem, key = _make_csr_pem("agent-core-1")
        issued = certs.renew_agent_certificate("agent-core-1", csr_pem)
        cert = x509.load_pem_x509_certificate(issued.certificate_pem.encode())

        assert issued.agent_id == "agent-core-1"
        assert cert.issuer == signing_ca.subject
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "agent-core-1"
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert constraints.ca is False
        assert cert.public_key().public_numbers() == key.public_key().public_numbers()
        assert format(cert.serial_number, "x") == issued.serial_hex
        assert "BEGIN CERTIFICATE" in issued.ca_pem

    def test_validity_days_override(self, signing_ca, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_CERT_VALIDITY_DAYS", "7")
        csr_pem, _ = _make_csr_pem("agent-core-1")
        issued = certs.renew_agent_certificate("agent-core-1", csr_pem)
        lifetime = issued.not_after - issued.not_before
        assert timedelta(days=6) < lifetime <= timedelta(days=7, minutes=2)

    def test_disabled_renewal(self, signing_ca, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_CERT_RENEWAL", "disabled")
        csr_pem, _ = _make_csr_pem("agent-core-1")
        with pytest.raises(certs.CertificateRenewalDisabled):
            certs.renew_agent_certificate("agent-core-1", csr_pem)

    def test_ca_missing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_CA_CERT_FILE", str(tmp_path / "missing.crt"))
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_CA_KEY_FILE", str(tmp_path / "missing.key"))
        monkeypatch.delenv("SEAGULL_AGENT_CERT_RENEWAL", raising=False)
        csr_pem, _ = _make_csr_pem("agent-core-1")
        with pytest.raises(certs.CertificateAuthorityUnavailable):
            certs.renew_agent_certificate("agent-core-1", csr_pem)

    def test_non_ca_certificate_rejected(self, tmp_path, monkeypatch, signing_ca):
        csr_pem, _ = _make_csr_pem("agent-core-1")
        issued = certs.renew_agent_certificate("agent-core-1", csr_pem)
        leaf_path = tmp_path / "leaf.crt"
        leaf_path.write_text(issued.certificate_pem)
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_CA_CERT_FILE", str(leaf_path))
        with pytest.raises(certs.CertificateAuthorityUnavailable):
            certs.renew_agent_certificate("agent-core-1", csr_pem)


class _StubRequest:
    def __init__(self, headers):
        self.headers = headers


class TestRequireCertIdentity:
    def test_match_passes(self):
        auth.require_cert_identity(_StubRequest({"X-Agent-Cert-CN": "CN=agent-core-1,O=Seagull Agents"}), "agent-core-1")

    def test_missing_header_rejected(self):
        with pytest.raises(HTTPException) as exc:
            auth.require_cert_identity(_StubRequest({}), "agent-core-1")
        assert exc.value.status_code == 403

    def test_mismatch_rejected(self):
        with pytest.raises(HTTPException) as exc:
            auth.require_cert_identity(_StubRequest({"X-Agent-Cert-CN": "CN=agent-evil"}), "agent-core-1")
        assert exc.value.status_code == 403
