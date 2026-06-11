from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy.orm import Session

from app.core.config.env_secrets import getenv_compat
from app.features.agents import repository
from app.features.agents.models import AgentCertificateModel, AgentCertificateStatus

DEFAULT_CA_CERT_FILE = "/etc/seagull/pki/agent-ca.crt"
DEFAULT_CA_KEY_FILE = "/etc/seagull/pki/agent-ca.key"
MIN_RSA_KEY_SIZE = 2048
ALLOWED_EC_CURVES = ("secp256r1", "secp384r1")


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


def _validity_days() -> int:
    raw = (getenv_compat("SEAGULL_AGENT_CERT_VALIDITY_DAYS", "365") or "365").strip()
    try:
        value = int(raw)
    except ValueError:
        return 365
    return value if value > 0 else 365


def _ca_paths() -> Tuple[Path, Path]:
    cert_file = (getenv_compat("SEAGULL_AGENT_MTLS_CA_CERT_FILE", DEFAULT_CA_CERT_FILE) or DEFAULT_CA_CERT_FILE).strip()
    key_file = (getenv_compat("SEAGULL_AGENT_MTLS_CA_KEY_FILE", DEFAULT_CA_KEY_FILE) or DEFAULT_CA_KEY_FILE).strip()
    return Path(cert_file), Path(key_file)


def load_signing_ca() -> Tuple[object, x509.Certificate, str]:
    cert_path, key_path = _ca_paths()
    try:
        ca_cert_bytes = cert_path.read_bytes()
        ca_key_bytes = key_path.read_bytes()
    except OSError as exc:
        raise CertificateAuthorityUnavailable(f"agent CA material unavailable: {exc}") from exc
    try:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes)
        ca_key = serialization.load_pem_private_key(ca_key_bytes, password=None)
    except ValueError as exc:
        raise CertificateAuthorityUnavailable(f"agent CA material invalid: {exc}") from exc
    try:
        constraints = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        raise CertificateAuthorityUnavailable("agent CA certificate is not a CA") from None
    if not constraints.value.ca:
        raise CertificateAuthorityUnavailable("agent CA certificate is not a CA")
    return ca_key, ca_cert, ca_cert_bytes.decode("utf-8", errors="replace")


def _csr_common_name(csr: x509.CertificateSigningRequest) -> str:
    attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return ""
    return str(attrs[0].value).strip()


def _validate_public_key(csr: x509.CertificateSigningRequest) -> None:
    public_key = csr.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < MIN_RSA_KEY_SIZE:
            raise CertificateRequestError("weak_key", f"RSA key must be >= {MIN_RSA_KEY_SIZE} bits")
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name.lower() not in ALLOWED_EC_CURVES:
            raise CertificateRequestError("weak_key", f"EC curve must be one of {ALLOWED_EC_CURVES}")
        return
    raise CertificateRequestError("unsupported_key", "CSR public key must be RSA or EC")


def validate_csr(csr_pem: str, agent_id: str) -> x509.CertificateSigningRequest:
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise CertificateRequestError("invalid_pem", f"CSR is not valid PEM: {exc}") from exc
    if not csr.is_signature_valid:
        raise CertificateRequestError("invalid_signature", "CSR signature verification failed")
    common_name = _csr_common_name(csr)
    if common_name != agent_id:
        raise CertificateRequestError(
            "subject_mismatch",
            "CSR common name does not match the authenticated agent id",
        )
    _validate_public_key(csr)
    return csr


def _public_key_sha256(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _record_issued_certificate(db: Session, cert: x509.Certificate, issued: IssuedCertificate) -> None:
    repository.save_certificate(
        db,
        AgentCertificateModel(
            agent_id=issued.agent_id,
            serial_hex=issued.serial_hex,
            fingerprint_sha256=issued.fingerprint_sha256,
            subject=cert.subject.rfc4514_string(),
            public_key_sha256=issued.public_key_sha256,
            issued_at=issued.not_before,
            expires_at=issued.not_after,
            status=AgentCertificateStatus.active.value,
        ),
    )


def sign_agent_csr(
    csr: x509.CertificateSigningRequest,
    agent_id: str,
    db: Optional[Session] = None,
) -> IssuedCertificate:
    ca_key, ca_cert, ca_pem = load_signing_ca()
    public_key = csr.public_key()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Seagull Agents"),
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        ]
    )
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(minutes=1)
    not_after = now + timedelta(days=_validity_days())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    issued = IssuedCertificate(
        agent_id=agent_id,
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        ca_pem=ca_pem,
        serial_hex=format(cert.serial_number, "x"),
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        public_key_sha256=_public_key_sha256(public_key),
        not_before=not_before,
        not_after=not_after,
    )
    if db is not None:
        _record_issued_certificate(db, cert, issued)
    return issued


def renew_agent_certificate(
    agent_id: str,
    csr_pem: str,
    db: Optional[Session] = None,
) -> IssuedCertificate:
    if not renewal_enabled():
        raise CertificateRenewalDisabled("agent certificate renewal is disabled")
    csr = validate_csr(csr_pem, agent_id)
    return sign_agent_csr(csr, agent_id, db=db)
