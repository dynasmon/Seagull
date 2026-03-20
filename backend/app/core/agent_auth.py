import hashlib
import os
import ssl
import re
import secrets
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple

from fastapi import HTTPException, Request, status

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.agent_identities import AgentIdentityModel
from app.models.agents import AgentModel


_CN_RE = re.compile(r"(?:^|[,/])\s*CN\s*=\s*([^,/]+)")


@dataclass(frozen=True)
class AgentPrincipal:
    """Authenticated agent context."""

    id: int
    agent_id: str
    auth_method: str
    identity_id: Optional[int] = None
    identity_fingerprint: Optional[str] = None


@dataclass(frozen=True)
class MTLSIdentityHeaders:
    verified: str
    agent_id: str
    fingerprint_sha256: str
    serial_number: str
    subject_dn: str
    issuer_dn: str


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_bootstrap_token(agent_id: str) -> Tuple[str, str, str]:
    """Generate one-time/short-lived bootstrap token for mTLS enrollment."""

    secret = secrets.token_urlsafe(32)
    token = f"abt.{agent_id}.{secret}"
    salt = secrets.token_urlsafe(16)
    token_hash = _sha256_hex((salt + token).encode("utf-8"))
    return token, salt, token_hash


def hash_bootstrap_token(raw_token: str, salt: str) -> str:
    return _sha256_hex((salt + (raw_token or "")).encode("utf-8"))


def _parse_agent_id_from_subject(subject_dn: str) -> str:
    m = _CN_RE.search(subject_dn or "")
    if not m:
        return ""
    return (m.group(1) or "").strip()


def _extract_mtls_headers(request: Request) -> Optional[MTLSIdentityHeaders]:
    verified = (request.headers.get("X-Agent-TLS-Verified") or "").strip()
    if not verified:
        return None

    subject_dn = (request.headers.get("X-Agent-TLS-Subject") or "").strip()
    issuer_dn = (request.headers.get("X-Agent-TLS-Issuer") or "").strip()
    fingerprint = (request.headers.get("X-Agent-TLS-Fingerprint") or "").strip().lower()
    cert_escaped = (request.headers.get("X-Agent-TLS-Cert") or "").strip()
    serial = (request.headers.get("X-Agent-TLS-Serial") or "").strip().lower()
    agent_id = (request.headers.get("X-Agent-TLS-Agent-ID") or "").strip()

    if not agent_id and subject_dn:
        agent_id = _parse_agent_id_from_subject(subject_dn)

    if cert_escaped:
        try:
            pem = urllib.parse.unquote(cert_escaped)
            der = ssl.PEM_cert_to_DER_cert(pem)
            fingerprint = hashlib.sha256(der).hexdigest()
        except Exception:
            pass

    if not fingerprint or not serial or not subject_dn or not agent_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incomplete mTLS identity headers",
        )

    return MTLSIdentityHeaders(
        verified=verified,
        agent_id=agent_id,
        fingerprint_sha256=fingerprint,
        serial_number=serial,
        subject_dn=subject_dn,
        issuer_dn=issuer_dn,
    )


def _expected_issuer_fragment() -> str:
    return (os.getenv("NETWATCH_AGENT_MTLS_ISSUER_CONTAINS") or "").strip()


def get_presented_mtls_identity(request: Request, require_verified: bool = True) -> Optional[MTLSIdentityHeaders]:
    mtls = _extract_mtls_headers(request)
    if mtls is None:
        return None
    if require_verified and mtls.verified.lower() != "success":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="mTLS verification failed")
    expected_issuer = _expected_issuer_fragment()
    if expected_issuer and expected_issuer not in mtls.issuer_dn:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="mTLS issuer mismatch")
    return mtls


def _get_current_agent_mtls(request: Request, *, strict: bool) -> Optional[AgentPrincipal]:
    mtls = get_presented_mtls_identity(request, require_verified=strict)
    if mtls is None:
        return None

    db = SessionLocal()
    try:
        agent: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == mtls.agent_id).first()
        if not agent or agent.is_revoked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")

        identity: AgentIdentityModel | None = (
            db.query(AgentIdentityModel)
            .filter(
                AgentIdentityModel.agent_id == mtls.agent_id,
                AgentIdentityModel.fingerprint_sha256 == mtls.fingerprint_sha256,
            )
            .first()
        )
        if not identity or identity.is_revoked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unbound or revoked agent certificate")

        now = datetime.utcnow()
        if settings.NETWATCH_AGENT_MTLS_ENFORCE_EXPIRY and identity.not_after is not None and identity.not_after <= now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent certificate expired")

        if (identity.serial_number or "").strip().lower() != mtls.serial_number:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent certificate serial mismatch")

        # Keep mTLS metadata in sync for auditability.
        metadata = dict(identity.identity_metadata or {})
        metadata["subject_dn"] = mtls.subject_dn
        metadata["issuer_dn"] = mtls.issuer_dn
        identity.identity_metadata = metadata
        identity.last_seen_at = now
        agent.last_seen_at = now

        db.add(identity)
        db.add(agent)
        db.commit()

        return AgentPrincipal(
            id=agent.id,
            agent_id=agent.agent_id,
            auth_method="mtls",
            identity_id=identity.id,
            identity_fingerprint=identity.fingerprint_sha256,
        )
    finally:
        db.close()


def get_current_agent(request: Request) -> AgentPrincipal:
    principal = _get_current_agent_mtls(request, strict=True)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing mTLS identity")
    return principal
