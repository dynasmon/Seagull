from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MIN_RSA_KEY_SIZE = 2048
ALLOWED_EC_CURVES = ("secp256r1", "secp384r1")
ORGANIZATION_NAME = "Seagull Agents"
BACKDATE = timedelta(minutes=1)


class AuthorityUnavailable(Exception):
    pass


class CertificateRequestError(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class IssuedCertificate:
    agent_id: str
    certificate_pem: str
    ca_pem: str
    subject: str
    serial_hex: str
    fingerprint_sha256: str
    public_key_sha256: str
    not_before: datetime
    not_after: datetime


def validated_agent_id(agent_id: str) -> str:
    candidate = (agent_id or "").strip()
    if not AGENT_ID_PATTERN.fullmatch(candidate):
        raise CertificateRequestError("invalid_agent_id", "agent id is not a valid identifier")
    return candidate


def _common_name(csr: x509.CertificateSigningRequest) -> str:
    attributes = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        return ""
    return str(attributes[0].value).strip()


def _validated_public_key(csr: x509.CertificateSigningRequest) -> Any:
    public_key = csr.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < MIN_RSA_KEY_SIZE:
            raise CertificateRequestError("weak_key", f"RSA key must be >= {MIN_RSA_KEY_SIZE} bits")
        return public_key
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name.lower() not in ALLOWED_EC_CURVES:
            raise CertificateRequestError("weak_key", f"EC curve must be one of {ALLOWED_EC_CURVES}")
        return public_key
    raise CertificateRequestError("unsupported_key", "CSR public key must be RSA or EC")


def validate_csr(csr_pem: str, agent_id: str) -> x509.CertificateSigningRequest:
    try:
        csr = x509.load_pem_x509_csr((csr_pem or "").encode("utf-8"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise CertificateRequestError("invalid_pem", f"CSR is not valid PEM: {exc}") from exc
    if not csr.is_signature_valid:
        raise CertificateRequestError("invalid_signature", "CSR signature verification failed")
    if _common_name(csr) != agent_id:
        raise CertificateRequestError(
            "subject_mismatch",
            "CSR common name does not match the requested agent id",
        )
    _validated_public_key(csr)
    return csr


def _public_key_sha256(public_key: Any) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


class Authority:
    def __init__(self, key: Any, certificate: x509.Certificate, pem: str) -> None:
        self._key = key
        self._certificate = certificate
        self._pem = pem

    @classmethod
    def load(cls, ca_cert_file: Path, ca_key_file: Path) -> "Authority":
        try:
            cert_bytes = ca_cert_file.read_bytes()
            key_bytes = ca_key_file.read_bytes()
        except OSError as exc:
            raise AuthorityUnavailable(f"agent CA material unavailable: {exc}") from exc
        try:
            certificate = x509.load_pem_x509_certificate(cert_bytes)
            key = serialization.load_pem_private_key(key_bytes, password=None)
        except (TypeError, ValueError) as exc:
            raise AuthorityUnavailable(f"agent CA material invalid: {exc}") from exc
        try:
            constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            raise AuthorityUnavailable("agent CA certificate is not a CA") from None
        if not constraints.value.ca:
            raise AuthorityUnavailable("agent CA certificate is not a CA")
        return cls(key, certificate, cert_bytes.decode("utf-8", errors="replace"))

    def issue(self, agent_id: str, csr_pem: str, validity_days: int) -> IssuedCertificate:
        subject_id = validated_agent_id(agent_id)
        csr = validate_csr(csr_pem, subject_id)
        public_key = csr.public_key()
        now = datetime.now(timezone.utc)
        not_before = now - BACKDATE
        not_after = now + timedelta(days=validity_days)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME),
                        x509.NameAttribute(NameOID.COMMON_NAME, subject_id),
                    ]
                )
            )
            .issuer_name(self._certificate.subject)
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
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._certificate.public_key()),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )
        return IssuedCertificate(
            agent_id=subject_id,
            certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            ca_pem=self._pem,
            subject=certificate.subject.rfc4514_string(),
            serial_hex=format(certificate.serial_number, "x"),
            fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
            public_key_sha256=_public_key_sha256(public_key),
            not_before=not_before,
            not_after=not_after,
        )
