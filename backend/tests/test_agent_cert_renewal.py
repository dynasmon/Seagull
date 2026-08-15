import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import HTTPException

from app.features.agents import auth, certs
from tests import agent_signing_stub


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
def signing_service(monkeypatch):
    with agent_signing_stub.serving() as stub:
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_URL", stub.url)
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_TOKEN", agent_signing_stub.TOKEN)
        monkeypatch.delenv("SEAGULL_AGENT_CERT_RENEWAL", raising=False)
        yield stub


class TestRenewAgentCertificate:
    def test_returns_the_certificate_the_authority_issued(self, signing_service):
        csr_pem, key = _make_csr_pem("agent-core-1")
        issued = certs.renew_agent_certificate("agent-core-1", csr_pem)
        certificate = x509.load_pem_x509_certificate(issued.certificate_pem.encode())

        assert issued.agent_id == "agent-core-1"
        assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "agent-core-1"
        assert certificate.public_key().public_numbers() == key.public_key().public_numbers()
        assert ExtendedKeyUsageOID.CLIENT_AUTH in certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        assert format(certificate.serial_number, "x") == issued.serial_hex
        assert "BEGIN CERTIFICATE" in issued.ca_pem

    def test_asks_the_authority_for_the_authenticated_identity(self, signing_service):
        csr_pem, _ = _make_csr_pem("agent-core-1")
        certs.renew_agent_certificate("agent-core-1", csr_pem)
        assert signing_service.requests == ["agent-core-1"]

    def test_records_the_issued_certificate(self, signing_service, monkeypatch):
        rows = []
        monkeypatch.setattr(certs.repository, "save_certificate", lambda db, row: rows.append(row))
        csr_pem, _ = _make_csr_pem("agent-core-1")
        issued = certs.renew_agent_certificate("agent-core-1", csr_pem, db=object())

        assert len(rows) == 1
        assert rows[0].agent_id == "agent-core-1"
        assert rows[0].serial_hex == issued.serial_hex
        assert rows[0].fingerprint_sha256 == issued.fingerprint_sha256
        assert rows[0].subject.startswith("CN=agent-core-1")
        assert rows[0].issued_at == issued.not_before
        assert rows[0].expires_at == issued.not_after

    def test_disabled_renewal_never_reaches_the_authority(self, signing_service, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_CERT_RENEWAL", "disabled")
        csr_pem, _ = _make_csr_pem("agent-core-1")
        with pytest.raises(certs.CertificateRenewalDisabled):
            certs.renew_agent_certificate("agent-core-1", csr_pem)
        assert signing_service.requests == []

    def test_reports_a_rejected_request(self, signing_service):
        csr_pem, _ = _make_csr_pem("agent-evil")
        with pytest.raises(certs.CertificateRequestError) as exc:
            certs.renew_agent_certificate("agent-core-1", csr_pem)
        assert exc.value.reason == "subject_mismatch"

    def test_reports_an_authority_that_cannot_sign(self, signing_service):
        signing_service.unavailable = True
        csr_pem, _ = _make_csr_pem("agent-core-1")
        with pytest.raises(certs.CertificateAuthorityUnavailable):
            certs.renew_agent_certificate("agent-core-1", csr_pem)

    def test_reports_an_authority_that_is_not_reachable(self, signing_service, monkeypatch):
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_URL", "http://127.0.0.1:1")
        csr_pem, _ = _make_csr_pem("agent-core-1")
        with pytest.raises(certs.CertificateAuthorityUnavailable):
            certs.renew_agent_certificate("agent-core-1", csr_pem)


class TestIssueEnrollmentCertificate:
    def test_issues_while_renewal_is_disabled(self, signing_service, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_CERT_RENEWAL", "disabled")
        csr_pem, _ = _make_csr_pem("agent-core-1")
        issued = certs.issue_enrollment_certificate("agent-core-1", csr_pem)
        assert "BEGIN CERTIFICATE" in issued.certificate_pem


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
