from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, status

from app.features.agents.models import AgentBootstrapTokenModel
from app.features.agents.schemas import AgentEnrollIn, AgentEnrollOut

_METADATA_KEY = "enrollment_replays_v1"
_KEY_CONTEXT = b"seagull-agent-enrollment-replay-v1"
_MAX_RECORDS = 32


def request_digest(payload: AgentEnrollIn) -> str:
    body = payload.model_dump(mode="json", exclude_none=True)
    encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _key(raw_token: str, enrollment_id: str) -> bytes:
    material = _KEY_CONTEXT + b"\x00" + raw_token.encode("utf-8") + b"\x00" + enrollment_id.encode("ascii")
    return hashlib.sha256(material).digest()


def _associated_data(
    token: AgentBootstrapTokenModel,
    payload: AgentEnrollIn,
    digest: str,
) -> bytes:
    values = (
        str(token.id),
        str(payload.agent_id),
        str(payload.enrollment_id),
        digest,
    )
    return "\x00".join(values).encode("utf-8")


def _records(token: AgentBootstrapTokenModel) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata = dict(token.token_metadata) if isinstance(token.token_metadata, dict) else {}
    existing = metadata.get(_METADATA_KEY)
    records = dict(existing) if isinstance(existing, dict) else {}
    return metadata, records


def load(
    token: AgentBootstrapTokenModel,
    payload: AgentEnrollIn,
    raw_token: str,
) -> AgentEnrollOut | None:
    enrollment_id = str(payload.enrollment_id or "").strip()
    if not enrollment_id:
        return None
    _, records = _records(token)
    record = records.get(enrollment_id)
    if record is None:
        return None
    if not isinstance(record, dict):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Enrollment replay state is unavailable",
        )
    digest = request_digest(payload)
    stored_digest = str(record.get("request_sha256") or "")
    if not hmac.compare_digest(stored_digest, digest):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Enrollment transaction does not match the original request",
        )
    try:
        nonce = base64.b64decode(str(record["nonce"]), validate=True)
        ciphertext = base64.b64decode(str(record["ciphertext"]), validate=True)
        plaintext = AESGCM(_key(raw_token, enrollment_id)).decrypt(
            nonce,
            ciphertext,
            _associated_data(token, payload, digest),
        )
        return AgentEnrollOut.model_validate_json(plaintext)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Enrollment replay state is unavailable",
        ) from exc


def store(
    token: AgentBootstrapTokenModel,
    payload: AgentEnrollIn,
    raw_token: str,
    response: AgentEnrollOut,
) -> None:
    enrollment_id = str(payload.enrollment_id or "").strip()
    if not enrollment_id:
        return
    digest = request_digest(payload)
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key(raw_token, enrollment_id)).encrypt(
        nonce,
        response.model_dump_json().encode("utf-8"),
        _associated_data(token, payload, digest),
    )
    metadata, records = _records(token)
    records[enrollment_id] = {
        "request_sha256": digest,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if len(records) > _MAX_RECORDS:
        ordered = sorted(
            records.items(),
            key=lambda item: str(item[1].get("created_at") or "") if isinstance(item[1], dict) else "",
            reverse=True,
        )
        records = dict(ordered[:_MAX_RECORDS])
    metadata[_METADATA_KEY] = records
    token.token_metadata = metadata
