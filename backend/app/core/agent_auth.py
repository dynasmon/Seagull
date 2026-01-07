import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple

from fastapi import HTTPException, Request, status

from app.core.db import SessionLocal
from app.models.agents import AgentModel


@dataclass(frozen=True)
class AgentPrincipal:
    """Authenticated agent context.

    We intentionally return a lightweight object instead of a SQLAlchemy model
    instance to avoid detached-instance errors across request boundaries.
    """

    id: int
    agent_id: str


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_agent_token(agent_id: str) -> Tuple[str, str, str]:
    """
    Token format: <agent_id>.<secret>

    Returns:
      token, salt, secret_hash
    """
    secret = secrets.token_urlsafe(32)
    salt = secrets.token_urlsafe(16)
    secret_hash = _sha256_hex((salt + secret).encode("utf-8"))
    return f"{agent_id}.{secret}", salt, secret_hash


def _parse_bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth:
        return None
    parts = auth.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0].strip().lower(), parts[1].strip()
    if scheme != "bearer" or not token:
        return None
    return token


def _split_token(token: str) -> Tuple[Optional[str], Optional[str]]:
    if "." not in token:
        return None, None
    agent_id, secret = token.split(".", 1)
    agent_id = agent_id.strip()
    secret = secret.strip()
    if not agent_id or not secret:
        return None, None
    return agent_id, secret


def get_current_agent(request: Request) -> AgentPrincipal:
    token = _parse_bearer(request)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing agent token")

    agent_id, secret = _split_token(token)
    if not agent_id or not secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")

    db = SessionLocal()
    try:
        agent: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if not agent or agent.is_revoked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")

        expected = agent.key_hash
        got = _sha256_hex((agent.key_salt + secret).encode("utf-8"))

        if not secrets.compare_digest(expected, got):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")

        # Update last seen best-effort.
        agent.last_seen_at = datetime.utcnow()
        db.add(agent)
        db.commit()

        return AgentPrincipal(id=agent.id, agent_id=agent.agent_id)
    finally:
        db.close()
