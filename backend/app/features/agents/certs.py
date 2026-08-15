from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from sqlalchemy.orm import Session

from app.core.config.env_secrets import getenv_compat
from app.core.pki import signer
from app.features.agents import repository
from app.features.agents.models import AgentCertificateModel, AgentCertificateStatus

DEFAULT_SERVER_CA_CERT_FILE = "/etc/seagull/pki/server-ca.crt"


class CertificateRenewalDisabled(Exception):
    pass


class CertificateAuthorityUnavailable(Exception):
    pass


class CertificateRequestError(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class IssuedCertificate:
    agent_id: str
    certificate_pem: str
    ca_pem: str
    serial_hex: str
    fingerprint_sha256: str
    public_key_sha256: str
    not_before: datetime
    not_after: datetime


def renewal_enabled() -> bool:
    raw = (getenv_compat("SEAGULL_AGENT_CERT_RENEWAL", "enabled") or "enabled").strip().lower()
    return raw not in ("disabled", "false", "0", "off")


def _record_issued_certificate(db: Session, signed: signer.SignedCertificate) -> None:
    repository.save_certificate(
        db,
        AgentCertificateModel(
            agent_id=signed.agent_id,
            serial_hex=signed.serial_hex,
            fingerprint_sha256=signed.fingerprint_sha256,
            subject=signed.subject,
            public_key_sha256=signed.public_key_sha256,
            issued_at=signed.not_before,
            expires_at=signed.not_after,
            status=AgentCertificateStatus.active.value,
        ),
    )


def _issue(agent_id: str, csr_pem: str, db: Optional[Session]) -> IssuedCertificate:
    try:
        signed = signer.sign_agent_certificate(agent_id, csr_pem)
    except signer.SignerUnavailable as exc:
        raise CertificateAuthorityUnavailable(str(exc)) from exc
    except signer.SignerRejected as exc:
        raise CertificateRequestError(exc.reason, exc.detail) from exc
    if db is not None:
        _record_issued_certificate(db, signed)
    return IssuedCertificate(
        agent_id=signed.agent_id,
        certificate_pem=signed.certificate_pem,
        ca_pem=signed.ca_pem,
        serial_hex=signed.serial_hex,
        fingerprint_sha256=signed.fingerprint_sha256,
        public_key_sha256=signed.public_key_sha256,
        not_before=signed.not_before,
        not_after=signed.not_after,
    )


def issue_enrollment_certificate(
    agent_id: str,
    csr_pem: str,
    db: Optional[Session] = None,
) -> IssuedCertificate:
    return _issue(agent_id, csr_pem, db)


def renew_agent_certificate(
    agent_id: str,
    csr_pem: str,
    db: Optional[Session] = None,
) -> IssuedCertificate:
    if not renewal_enabled():
        raise CertificateRenewalDisabled("agent certificate renewal is disabled")
    return _issue(agent_id, csr_pem, db)


def certificate_fingerprint(pem: str) -> Optional[str]:
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except (ValueError, AttributeError):
        return None
    return cert.fingerprint(hashes.SHA256()).hex()


def server_ca_bundle() -> Optional[str]:
    path = (getenv_compat("SEAGULL_AGENT_MTLS_SERVER_CA_CERT_FILE", DEFAULT_SERVER_CA_CERT_FILE) or "").strip()
    if not path:
        return None
    try:
        pem = Path(path).read_bytes()
    except OSError:
        return None
    try:
        decoded = pem.decode("ascii")
        certificates = x509.load_pem_x509_certificates(pem)
    except (UnicodeDecodeError, ValueError):
        return None
    if not certificates:
        return None
    canonical = b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in certificates)
    if pem.replace(b"\r\n", b"\n").strip() != canonical.strip():
        return None
    for certificate in certificates:
        try:
            constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            return None
        if not constraints.value.ca:
            return None
    return decoded
