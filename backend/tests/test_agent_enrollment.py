from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_PASSWORD", "test-password")

from app.features.agents import certs
from app.features.agents import service as agents_service
from app.features.agents.schemas import AgentEnrollIn


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


def _make_csr_pem(agent_id):
    key = ec.generate_private_key(ec.SECP256R1())
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
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


@pytest.fixture
def signing_ca(tmp_path, monkeypatch):
    cert, cert_path, key_path = _make_ca(tmp_path)
    monkeypatch.setenv("SEAGULL_AGENT_MTLS_CA_CERT_FILE", str(cert_path))
    monkeypatch.setenv("SEAGULL_AGENT_MTLS_CA_KEY_FILE", str(key_path))
    monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_CA_CERT_FILE", str(cert_path))
    return cert


class TestIssueEnrollmentCertificate:
    def test_issues_even_when_renewal_disabled(self, signing_ca, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_CERT_RENEWAL", "disabled")
        issued = certs.issue_enrollment_certificate("agent-x", _make_csr_pem("agent-x"))
        assert issued.agent_id == "agent-x"
        cert = x509.load_pem_x509_certificate(issued.certificate_pem.encode())
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "agent-x"

    def test_rejects_cn_mismatch(self, signing_ca):
        with pytest.raises(certs.CertificateRequestError):
            certs.issue_enrollment_certificate("agent-x", _make_csr_pem("agent-y"))

    def test_ca_unavailable(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_CA_CERT_FILE", str(tmp_path / "missing.crt"))
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_CA_KEY_FILE", str(tmp_path / "missing.key"))
        with pytest.raises(certs.CertificateAuthorityUnavailable):
            certs.issue_enrollment_certificate("agent-x", _make_csr_pem("agent-x"))


class TestServerCaBundle:
    def test_returns_pem_when_present(self, signing_ca):
        bundle = certs.server_ca_bundle()
        assert bundle is not None
        assert "BEGIN CERTIFICATE" in bundle

    def test_returns_none_when_missing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_CA_CERT_FILE", str(tmp_path / "absent.crt"))
        assert certs.server_ca_bundle() is None

    def test_returns_none_for_invalid_pem(self, tmp_path, monkeypatch):
        bad = tmp_path / "bad.crt"
        bad.write_text("not a certificate")
        monkeypatch.setenv("SEAGULL_AGENT_MTLS_SERVER_CA_CERT_FILE", str(bad))
        assert certs.server_ca_bundle() is None


def _allow_rate_limit(monkeypatch, allowed=True):
    monkeypatch.setattr(
        agents_service,
        "rate_limit",
        lambda key, *, limit, window_seconds: SimpleNamespace(
            allowed=allowed, remaining=1, reset_seconds=1
        ),
    )


def _fake_request(host="203.0.113.10"):
    return SimpleNamespace(client=SimpleNamespace(host=host), headers={}, url=SimpleNamespace(path="/agents/enroll"))


def _stub_enroll_persistence(monkeypatch):
    saved = {"agents": [], "credentials": [], "tokens": [], "commits": 0}
    now = datetime.utcnow()
    bootstrap = SimpleNamespace(id=7, token_type="enrollment")

    monkeypatch.setattr(agents_service, "_consume_bootstrap_token", lambda db, agent_id, raw: bootstrap)
    monkeypatch.setattr(agents_service.repository, "get_agent_by_agent_id", lambda db, agent_id: None)
    monkeypatch.setattr(agents_service.repository, "save_agent", lambda db, row: saved["agents"].append(row))
    monkeypatch.setattr(agents_service.repository, "save_credential", lambda db, row: saved["credentials"].append(row))
    monkeypatch.setattr(agents_service.repository, "save_bootstrap_token", lambda db, row: saved["tokens"].append(row))
    monkeypatch.setattr(agents_service.repository, "save_certificate", lambda db, row: None, raising=False)
    monkeypatch.setattr(agents_service.repository, "flush", lambda db: None)
    monkeypatch.setattr(agents_service.repository, "commit", lambda db: saved.__setitem__("commits", saved["commits"] + 1))
    monkeypatch.setattr(
        agents_service.repository,
        "list_active_credentials",
        lambda db, agent_id: [],
    )
    monkeypatch.setattr(
        agents_service.repository,
        "list_active_renewal_tokens_for_update",
        lambda db, agent_id: [],
    )
    monkeypatch.setattr(agents_service.certs.repository, "save_certificate", lambda db, row: None)

    def _fake_issue_credential(db, *, agent_id, issued_from_bootstrap_token_id, replaces_credential_id):
        row = SimpleNamespace(
            id=11,
            expires_at=now + timedelta(hours=1),
            max_uses=100,
            used_uses=0,
        )
        return "agc.test", row

    def _fake_issue_renewal(db, *, agent_id):
        row = SimpleNamespace(id=12, expires_at=now + timedelta(days=30))
        return "abt.renewal", row

    monkeypatch.setattr(agents_service, "_issue_agent_credential", _fake_issue_credential)
    monkeypatch.setattr(agents_service, "_issue_renewal_token", _fake_issue_renewal)
    return saved


class TestEnrollService:
    def test_enroll_with_csr_returns_certificate(self, signing_ca, monkeypatch):
        _allow_rate_limit(monkeypatch)
        _stub_enroll_persistence(monkeypatch)
        audits = []

        out = agents_service.enroll(
            object(),
            payload=AgentEnrollIn(agent_id="agent-x", hostname="h1", csr_pem=_make_csr_pem("agent-x")),
            raw_bootstrap_token="abt.agent-x.secret",
            request=_fake_request(),
            audit_writer=lambda db, **kw: audits.append(kw),
        )

        assert out.agent_id == "agent-x"
        assert out.certificate is not None
        assert "BEGIN CERTIFICATE" in out.certificate.certificate_pem
        assert out.certificate.server_ca_pem is not None
        assert out.credential.credential == "agc.test"
        assert len(audits) == 1
        assert audits[0]["action"] == "agents.enroll"
        assert audits[0]["after"]["certificate_issued"] is True

    def test_enroll_without_csr_keeps_previous_shape(self, monkeypatch):
        _allow_rate_limit(monkeypatch)
        _stub_enroll_persistence(monkeypatch)

        out = agents_service.enroll(
            object(),
            payload=AgentEnrollIn(agent_id="agent-x", hostname="h1"),
            raw_bootstrap_token="abt.agent-x.secret",
            request=_fake_request(),
            audit_writer=lambda db, **kw: None,
        )

        assert out.certificate is None
        assert out.credential.renewal_token == "abt.renewal"

    def test_enroll_rejects_bad_csr_subject(self, signing_ca, monkeypatch):
        _allow_rate_limit(monkeypatch)
        _stub_enroll_persistence(monkeypatch)

        with pytest.raises(HTTPException) as exc:
            agents_service.enroll(
                object(),
                payload=AgentEnrollIn(agent_id="agent-x", csr_pem=_make_csr_pem("agent-other")),
                raw_bootstrap_token="abt.agent-x.secret",
                request=_fake_request(),
                audit_writer=lambda db, **kw: None,
            )
        assert exc.value.status_code == 422

    def test_enroll_rate_limited(self, monkeypatch):
        _allow_rate_limit(monkeypatch, allowed=False)

        with pytest.raises(HTTPException) as exc:
            agents_service.enroll(
                object(),
                payload=AgentEnrollIn(agent_id="agent-x"),
                raw_bootstrap_token="abt.agent-x.secret",
                request=_fake_request(),
                audit_writer=lambda db, **kw: None,
            )
        assert exc.value.status_code == 429
