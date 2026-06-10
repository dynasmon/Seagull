import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple

from fastapi import HTTPException, Request, status
from sqlalchemy import or_

from app.core.config.env_secrets import getenv_compat
from app.core.db import SessionLocal
from app.core.observability import incr_counter
from app.features.agents.models import AgentCredentialModel, AgentModel

_CERT_CN_RE = re.compile(r"CN\s*=\s*([^,/]+)")


def _identity_binding_mode() -> str:
    mode = (getenv_compat("SEAGULL_AGENT_MTLS_IDENTITY_BINDING", "warn") or "warn").strip().lower()
    if mode not in ("off", "warn", "enforce"):
        return "warn"
    return mode


def _extract_cert_cn(request: Request) -> Optional[str]:
    raw = (request.headers.get("X-Agent-Cert-CN") or "").strip()
    if not raw:
        return None
    match = _CERT_CN_RE.search(raw)
    value = match.group(1) if match else raw
    return value.strip() or None


def _enforce_cert_identity(request: Request, agent_id: str) -> None:
    mode = _identity_binding_mode()
    if mode == "off":
        return
    cert_cn = _extract_cert_cn(request)
    if cert_cn is None or cert_cn == agent_id:
        return
    incr_counter("agent_auth_requests_total", outcome="failure", reason="cert_identity_mismatch")
    if mode == "enforce":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent certificate identity does not match agent id",
        )


def require_cert_identity(request: Request, agent_id: str) -> None:
    cert_cn = _extract_cert_cn(request)
    if cert_cn is None:
        incr_counter("agent_auth_requests_total", outcome="failure", reason="cert_identity_missing")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A verified client certificate is required for this operation",
        )
    if cert_cn != agent_id:
        incr_counter("agent_auth_requests_total", outcome="failure", reason="cert_identity_mismatch")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent certificate identity does not match agent id",
        )


@dataclass(frozen=True)
class AgentPrincipal:
    """Authenticated agent context."""

    id: int
    agent_id: str
    auth_method: str
    credential_id: Optional[int] = None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_bootstrap_token(agent_id: str) -> Tuple[str, str, str]:
    """Generate one-time/short-lived bootstrap token for agent enrollment."""

    secret = secrets.token_urlsafe(32)
    token = f"abt.{agent_id}.{secret}"
    salt = secrets.token_urlsafe(16)
    token_hash = _sha256_hex((salt + token).encode("utf-8"))
    return token, salt, token_hash


def hash_bootstrap_token(raw_token: str, salt: str) -> str:
    return _sha256_hex((salt + (raw_token or "")).encode("utf-8"))


def generate_agent_credential(agent_id: str) -> Tuple[str, str, str]:
    """Generate a rotating agent credential and its salted hash."""

    secret = secrets.token_urlsafe(48)
    credential = f"agc.{agent_id}.{secret}"
    salt = secrets.token_urlsafe(16)
    credential_hash = _sha256_hex((salt + credential).encode("utf-8"))
    return credential, salt, credential_hash


def hash_agent_credential(raw_credential: str, salt: str) -> str:
    return _sha256_hex((salt + (raw_credential or "")).encode("utf-8"))


def _extract_agent_headers(request: Request) -> tuple[str, str]:
    agent_id = (request.headers.get("X-Agent-ID") or "").strip()
    credential = (request.headers.get("X-Agent-Credential") or "").strip()
    if not agent_id or not credential:
        incr_counter("agent_auth_requests_total", outcome="failure", reason="missing_headers")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing agent credentials")
    return agent_id, credential


def get_current_agent(request: Request) -> AgentPrincipal:
    agent_id, raw_credential = _extract_agent_headers(request)

    db = SessionLocal()
    try:
        agent: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if not agent or agent.is_revoked:
            incr_counter("agent_auth_requests_total", outcome="failure", reason="unknown_or_revoked_agent")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")

        now = datetime.utcnow()
        candidates: list[AgentCredentialModel] = (
            db.query(AgentCredentialModel)
            .filter(
                AgentCredentialModel.agent_id == agent_id,
                or_(AgentCredentialModel.revoked_at.is_(None), AgentCredentialModel.revoked_at > now),
            )
            .all()
        )

        matched: AgentCredentialModel | None = None
        for cred in candidates:
            got = hash_agent_credential(raw_credential, cred.credential_salt)
            if not secrets.compare_digest(got, cred.credential_hash):
                continue
            matched = cred
            break

        if matched is None:
            incr_counter("agent_auth_requests_total", outcome="failure", reason="invalid_credential")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent credential")

        if matched.expires_at <= now:
            incr_counter("agent_auth_requests_total", outcome="failure", reason="expired")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent credential expired")
        if int(matched.used_uses or 0) >= int(matched.max_uses or 1):
            incr_counter("agent_auth_requests_total", outcome="failure", reason="exhausted")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent credential exhausted")

        _enforce_cert_identity(request, agent_id)

        matched.used_uses = int(matched.used_uses or 0) + 1
        matched.last_used_at = now
        agent.last_seen_at = now

        db.add(matched)
        db.add(agent)
        db.commit()
        incr_counter("agent_auth_requests_total", outcome="success", method="credential")

        return AgentPrincipal(
            id=agent.id,
            agent_id=agent.agent_id,
            auth_method="credential",
            credential_id=matched.id,
        )
    finally:
        db.close()
