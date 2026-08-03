from __future__ import annotations

import ipaddress
import json
import re
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.audit import audit_actor, write_audit_event
from app.core.config import settings
from app.core.observability import incr_counter
from app.core.security.rate_limit import rate_limit
from app.features.agents import (
    certs,
    collectors,
    configuration,
    enrollment_replay,
    installer,
    onboarding,
    packages,
    profiles,
    protocol,
    repository,
)
from app.features.agents.auth import (
    AgentPrincipal,
    bootstrap_token_agent_id,
    generate_agent_credential,
    generate_bootstrap_token,
    hash_agent_credential,
    hash_bootstrap_token,
    require_cert_identity,
)
from app.features.agents.models import AgentBootstrapTokenModel, AgentCredentialModel, AgentModel
from app.features.agents.schemas import (
    AgentBootstrapTokenCreateIn,
    AgentBootstrapTokenOut,
    AgentCertificateRenewIn,
    AgentCertificateRenewOut,
    AgentConfigUpdateIn,
    AgentCredentialOut,
    AgentDetail,
    AgentEnrollCertificateOut,
    AgentEnrollIn,
    AgentEnrollmentTicketIn,
    AgentEnrollmentTicketOut,
    AgentEnrollOut,
    AgentHeartbeatIn,
    AgentProtocolOut,
    AgentPublic,
    AgentUpdateIn,
)
from app.features.auth.session import PortalPrincipal
from app.features.realtime.projectors import project_agent_presence_patch
from app.features.realtime.service import publish_realtime

_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,31}$")


def _normalize_tags(tags: Optional[List[str]]) -> List[str]:
    if not tags:
        return []
    out: List[str] = []
    seen = set()
    for t in tags:
        if t is None:
            continue
        s = str(t).strip()
        if not s:
            continue
        if not _TAG_RE.match(s):
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= 50:
            break
    return out


def client_address(request) -> str | None:
    if request is None:
        return None
    host = str(getattr(request.client, "host", "") or "").strip()
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host.split("%", 1)[0]))
    except ValueError:
        return None


def _track_observed_address(row: AgentModel, request, *, seen_at: datetime) -> None:
    address = client_address(request)
    if not address:
        return
    row.observed_address = address
    row.observed_address_at = seen_at


def _safe_json_size(obj: Any, max_bytes: int, field_name: str) -> None:
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(raw) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"{field_name} exceeds {max_bytes} bytes",
        )


def _build_agent_heartbeat_payload(*, row: AgentModel, status_text: str) -> Dict[str, Any]:
    return project_agent_presence_patch(
        agent_id=str(row.agent_id or "").strip(),
        status=str(status_text or "").strip()[:32],
        is_revoked=bool(row.is_revoked),
        last_seen_at=row.last_seen_at.isoformat() if row.last_seen_at is not None else None,
    )


def _publish_agent_heartbeat_realtime(*, row: AgentModel, status_text: str) -> None:
    payload = _build_agent_heartbeat_payload(row=row, status_text=status_text)
    if not payload.get("agent_id"):
        return
    try:
        publish_realtime("ui.agents.presence.patch", payload)
    except Exception:
        return


def _agent_to_public(a: AgentModel) -> AgentPublic:
    tags = a.tags if isinstance(a.tags, list) else []
    tags = [str(x) for x in tags if x is not None]
    metadata = a.agent_metadata if isinstance(a.agent_metadata, dict) else {}
    metrics = a.metrics if isinstance(a.metrics, dict) else {}
    return AgentPublic(
        agent_id=a.agent_id,
        display_name=a.display_name,
        description=a.description,
        tags=tags,
        created_at=a.created_at,
        last_seen_at=a.last_seen_at,
        observed_address=a.observed_address,
        observed_address_at=a.observed_address_at,
        is_revoked=a.is_revoked,
        metadata=metadata,
        metrics=metrics,
    )


def _agent_to_detail(a: AgentModel) -> AgentDetail:
    pub = _agent_to_public(a)
    return AgentDetail(**pub.dict(), config=configuration.normalize(a.config))


def _credential_overlap_until(now: datetime | None = None) -> datetime:
    base = now or datetime.utcnow()
    overlap_seconds = max(0, int(settings.SEAGULL_AGENT_CREDENTIAL_OVERLAP_SECONDS or 0))
    return base + timedelta(seconds=overlap_seconds)


def _match_bootstrap_token(
    candidates: list[AgentBootstrapTokenModel],
    raw_token: str,
) -> AgentBootstrapTokenModel | None:
    for tok in candidates:
        got = hash_bootstrap_token(raw_token, tok.token_salt)
        if secrets.compare_digest(got, tok.token_hash):
            return tok
    return None


def _authorize_enrollment_token(
    db: Session,
    payload: AgentEnrollIn,
    raw_token: str,
) -> tuple[AgentBootstrapTokenModel, AgentEnrollOut | None]:
    now = datetime.utcnow()
    candidates = repository.list_bootstrap_tokens_for_update(db, payload.agent_id)
    tok = _match_bootstrap_token(candidates, raw_token)
    if tok is not None:
        if tok.expires_at <= now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bootstrap token expired")
        if tok.revoked_at is not None and str(tok.revoked_reason or "") != "consumed":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bootstrap token revoked")
        replay = enrollment_replay.load(tok, payload, raw_token)
        if replay is not None:
            if not _enrollment_replay_is_current(db, tok, replay, now):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Enrollment transaction is no longer active",
                )
            incr_counter("agent_identity_enroll_total", outcome="replayed", token_type=str(tok.token_type or "enrollment"))
            return tok, replay
        if int(tok.used_uses or 0) >= int(tok.max_uses or 1):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bootstrap token already consumed")
        return tok, None
    incr_counter("agent_bootstrap_token_consumed_total", outcome="invalid")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bootstrap token")


def _enrollment_replay_is_current(
    db: Session,
    token: AgentBootstrapTokenModel,
    replay: AgentEnrollOut,
    now: datetime,
) -> bool:
    raw_credential = str(replay.credential.credential or "")
    for credential in repository.list_active_credentials(db, replay.agent_id):
        if credential.issued_from_bootstrap_token_id != token.id:
            continue
        if credential.expires_at <= now:
            continue
        if int(credential.used_uses or 0) >= int(credential.max_uses or 1):
            continue
        got = hash_agent_credential(raw_credential, credential.credential_salt)
        if secrets.compare_digest(got, credential.credential_hash):
            return True
    return False


def _consume_enrollment_token(db: Session, token: AgentBootstrapTokenModel) -> None:
    now = datetime.utcnow()
    token.used_uses = int(token.used_uses or 0) + 1
    token.last_used_at = now
    if int(token.used_uses or 0) >= int(token.max_uses or 1):
        token.revoked_at = now
        token.revoked_reason = "consumed"
    repository.save_bootstrap_token(db, token)
    incr_counter("agent_bootstrap_token_consumed_total", token_type=str(token.token_type or "enrollment"))


def _revoke_active_credentials(
    db: Session,
    agent_id: str,
    reason: str,
    *,
    rotated_at: datetime | None = None,
    overlap_until: datetime | None = None,
) -> None:
    active = repository.list_active_credentials(db, agent_id)
    now = datetime.utcnow()
    for row in active:
        target_revoked_at = overlap_until if overlap_until is not None else now
        if overlap_until is not None and row.revoked_at is not None and row.revoked_at > now and row.revoked_at < target_revoked_at:
            target_revoked_at = row.revoked_at
        row.revoked_at = target_revoked_at
        row.rotated_at = rotated_at
        row.revoked_reason = reason
        repository.save_credential(db, row)


def _revoke_active_bootstrap_tokens(db: Session, agent_id: str, reason: str, *, token_type: str | None = None) -> None:
    active = repository.list_active_bootstrap_tokens_for_update(db, agent_id, token_type=token_type)
    now = datetime.utcnow()
    for row in active:
        row.revoked_at = now
        row.revoked_reason = reason
        repository.save_bootstrap_token(db, row)


def _prune_active_renewal_tokens(db: Session, agent_id: str) -> None:
    active = repository.list_active_renewal_tokens_for_update(db, agent_id)
    if not active:
        return
    keep = max(1, int(settings.SEAGULL_AGENT_RENEWAL_TOKEN_MAX_ACTIVE or 1))
    now = datetime.utcnow()
    for idx, row in enumerate(active):
        if row.expires_at <= now:
            row.revoked_at = now
            row.revoked_reason = "expired"
            repository.save_bootstrap_token(db, row)
            continue
        if idx >= keep:
            row.revoked_at = now
            row.revoked_reason = "superseded"
            repository.save_bootstrap_token(db, row)


def _issue_agent_credential(
    db: Session,
    *,
    agent_id: str,
    issued_from_bootstrap_token_id: int | None,
    replaces_credential_id: int | None,
) -> tuple[str, AgentCredentialModel]:
    ttl_seconds = max(300, int(settings.SEAGULL_AGENT_CREDENTIAL_TTL_SECONDS or 0))
    max_uses = max(1, int(settings.SEAGULL_AGENT_CREDENTIAL_MAX_USES or 0))
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
    credential, salt, credential_hash = generate_agent_credential(agent_id)
    row = AgentCredentialModel(
        agent_id=agent_id,
        credential_salt=salt,
        credential_hash=credential_hash,
        expires_at=expires_at,
        max_uses=max_uses,
        used_uses=0,
        issued_from_bootstrap_token_id=issued_from_bootstrap_token_id,
        replaces_credential_id=replaces_credential_id,
    )
    repository.save_credential(db, row)
    repository.flush(db)
    return credential, row


def _issue_bootstrap_token(
    db: Session,
    *,
    agent_id: str,
    token_type: str,
    expires_at: datetime,
    max_uses: int,
    created_by_user_id: int | None = None,
    description: str | None = None,
    metadata: Dict[str, Any] | None = None,
) -> tuple[str, AgentBootstrapTokenModel]:
    token, salt, token_hash = generate_bootstrap_token(agent_id)
    row = AgentBootstrapTokenModel(
        agent_id=agent_id,
        token_salt=salt,
        token_hash=token_hash,
        token_type=token_type,
        expires_at=expires_at,
        max_uses=max_uses,
        used_uses=0,
        created_by_user_id=created_by_user_id,
        description=description,
        token_metadata=metadata or {},
    )
    repository.save_bootstrap_token(db, row)
    repository.flush(db)
    incr_counter("agent_bootstrap_token_issued_total", token_type=token_type)
    return token, row


def _issue_renewal_token(db: Session, *, agent_id: str) -> tuple[str, AgentBootstrapTokenModel]:
    ttl_seconds = max(3600, int(settings.SEAGULL_AGENT_RENEWAL_TOKEN_TTL_SECONDS or 0))
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
    token, row = _issue_bootstrap_token(
        db,
        agent_id=agent_id,
        token_type="renewal",
        expires_at=expires_at,
        max_uses=1,
        description="agent-self-renewal",
    )
    _prune_active_renewal_tokens(db, agent_id)
    return token, row


def create_bootstrap_token(
    db: Session,
    *,
    agent_id: str,
    payload: AgentBootstrapTokenCreateIn,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
    metadata: Dict[str, Any] | None = None,
) -> AgentBootstrapTokenOut:
    ttl_seconds = int(payload.ttl_seconds or settings.SEAGULL_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS)
    max_uses = int(payload.max_uses or settings.SEAGULL_AGENT_BOOTSTRAP_TOKEN_MAX_USES)
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        default_cfg = settings.default_agent_config()
        if len(json.dumps(default_cfg, separators=(",", ":")).encode("utf-8")) > settings.SEAGULL_MAX_AGENT_CONFIG_BYTES:
            default_cfg = {"revision": 1}
        row = AgentModel(
            agent_id=agent_id,
            agent_metadata={},
            display_name=agent_id[:128],
            description=None,
            tags=[],
            config=default_cfg,
            metrics={},
            created_at=datetime.utcnow(),
            last_seen_at=None,
            is_revoked=False,
        )
        repository.save_agent(db, row)

    _revoke_active_bootstrap_tokens(db, agent_id, "superseded_by_admin_issue", token_type="enrollment")
    token, _rec = _issue_bootstrap_token(
        db,
        agent_id=agent_id,
        token_type="enrollment",
        expires_at=expires_at,
        max_uses=max_uses,
        created_by_user_id=admin.id,
        description=payload.description,
        metadata=metadata,
    )
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="agents.bootstrap_token.create",
        resource_type="agent",
        resource_id=agent_id,
        outcome="success",
        before={},
        after={
            "agent_id": agent_id,
            "expires_at": expires_at.isoformat(),
            "max_uses": max_uses,
            "description": payload.description,
        },
    )
    repository.commit(db)
    incr_counter("agent_bootstrap_token_admin_issue_total", outcome="success")
    return AgentBootstrapTokenOut(
        agent_id=agent_id,
        bootstrap_token=token,
        expires_at=expires_at,
        max_uses=max_uses,
    )


def create_enrollment_ticket(
    db: Session,
    *,
    payload: AgentEnrollmentTicketIn,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> AgentEnrollmentTicketOut:
    profile = profiles.normalize(payload.profile) or profiles.SENSOR
    described = onboarding.describe(request)
    artifact = onboarding.artifact_for(described.release, payload.architecture)
    sources = collectors.resolve(payload.sources, default=settings.SEAGULL_AGENT_DEFAULT_SOURCES)
    try:
        packages.reference(described.release.version, payload.architecture)
    except packages.PackageError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=exc.detail) from None
    provisioning = {
        "profile": profile,
        "architecture": payload.architecture,
        "sources": sources,
        "api_url": described.api_url,
        "enroll_url": described.enroll_url,
        "version": described.release.version,
    }
    token = create_bootstrap_token(
        db,
        agent_id=payload.agent_id,
        payload=AgentBootstrapTokenCreateIn(
            ttl_seconds=payload.ttl_seconds,
            max_uses=1,
            description=payload.description,
        ),
        request=request,
        admin=admin,
        audit_writer=audit_writer,
        metadata={"provisioning": provisioning},
    )

    row = repository.get_agent_by_agent_id(db, payload.agent_id)
    if row is not None:
        meta = row.agent_metadata if isinstance(row.agent_metadata, dict) else {}
        row.agent_metadata = {**meta, "profile": profile}
        repository.save_agent(db, row)
        repository.commit(db)

    installer_filename = installer.filename(agent_id=token.agent_id, architecture=payload.architecture)
    return AgentEnrollmentTicketOut(
        agent_id=token.agent_id,
        profile=profile,
        sources=sources,
        bootstrap_token=token.bootstrap_token,
        expires_at=token.expires_at,
        max_uses=token.max_uses,
        api_url=described.api_url,
        enroll_url=described.enroll_url,
        architecture=payload.architecture,
        artifact=artifact,
        release=described.release,
        server_ca_required=described.server_ca_required,
        server_ca_fingerprint_sha256=described.server_ca_fingerprint_sha256,
        server_ca_pem=described.server_ca_pem,
        install_command=onboarding.install_command(
            agent_id=token.agent_id,
            profile=profile,
            sources=sources,
            request=request,
        ),
        installer_filename=installer_filename,
        installer_command=onboarding.installer_command(filename=installer_filename),
        bootstrap_command=onboarding.bootstrap_command(
            token=token.bootstrap_token,
            filename=installer_filename,
            request=request,
        ),
    )


def _within_rate_limit(request, *, scope: str, agent_id: str, ip_limit: int, agent_limit: int) -> bool:
    if request is None:
        return True
    ip = client_address(request) or "unknown"
    ip_rl = rate_limit(f"rl:{scope}:ip:{ip}", limit=ip_limit, window_seconds=300)
    agent_rl = rate_limit(f"rl:{scope}:agent:{agent_id}", limit=agent_limit, window_seconds=300)
    return ip_rl.allowed and agent_rl.allowed


def _installer_spec(
    db: Session,
    *,
    agent_id: str,
    raw_bootstrap_token: str,
    request,
) -> installer.InstallerSpec:
    now = datetime.utcnow()
    token = _match_bootstrap_token(repository.list_bootstrap_tokens(db, agent_id), raw_bootstrap_token)
    if token is None:
        incr_counter("agent_installer_build_total", outcome="failure", reason="invalid_token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment token")
    if str(token.token_type or "enrollment") != "enrollment":
        incr_counter("agent_installer_build_total", outcome="failure", reason="wrong_token_type")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment token")
    if token.expires_at <= now:
        incr_counter("agent_installer_build_total", outcome="failure", reason="expired")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Enrollment token expired")
    if token.revoked_at is not None:
        incr_counter("agent_installer_build_total", outcome="failure", reason="revoked")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Enrollment token revoked")
    if int(token.used_uses or 0) >= int(token.max_uses or 1):
        incr_counter("agent_installer_build_total", outcome="failure", reason="consumed")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Enrollment token already consumed")

    agent = repository.get_agent_by_agent_id(db, agent_id)
    if agent is not None and agent.is_revoked:
        incr_counter("agent_installer_build_total", outcome="failure", reason="agent_revoked")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is revoked")

    metadata = token.token_metadata if isinstance(token.token_metadata, dict) else {}
    provisioning = metadata.get("provisioning")
    if not isinstance(provisioning, dict):
        incr_counter("agent_installer_build_total", outcome="failure", reason="not_provisioned")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This token was not issued for a pre-configured installer. Issue an enrollment ticket instead.",
        )

    described = onboarding.describe(request)
    architecture = str(provisioning.get("architecture") or "")
    try:
        package = packages.reference(str(provisioning.get("version") or "") or None, architecture)
    except packages.PackageError as exc:
        incr_counter("agent_installer_build_total", outcome="failure", reason=exc.reason)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=exc.detail) from None
    return installer.InstallerSpec(
        agent_id=agent_id,
        profile=profiles.normalize(provisioning.get("profile")) or profiles.SENSOR,
        sources=collectors.resolve(provisioning.get("sources"), default=settings.SEAGULL_AGENT_DEFAULT_SOURCES),
        api_url=str(provisioning.get("api_url") or described.api_url),
        enroll_url=str(provisioning.get("enroll_url") or described.enroll_url),
        enrollment_token=raw_bootstrap_token,
        package=package,
        server_ca_pem=described.server_ca_pem,
    )


def build_installer(
    db: Session,
    *,
    raw_bootstrap_token: str,
    request=None,
    audit_writer=write_audit_event,
) -> tuple[str, bytes]:
    agent_id = bootstrap_token_agent_id(raw_bootstrap_token)
    if not _within_rate_limit(request, scope="agent-installer", agent_id=agent_id, ip_limit=20, agent_limit=10):
        incr_counter("agent_installer_build_total", outcome="failure", reason="rate_limited")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many installer downloads. Try again in a few minutes.",
        )

    spec = _installer_spec(db, agent_id=agent_id, raw_bootstrap_token=raw_bootstrap_token, request=request)
    try:
        payload = packages.read(spec.package)
    except packages.PackageError as exc:
        incr_counter(
            "agent_installer_build_total",
            outcome="failure",
            architecture=spec.package.architecture,
            reason=exc.reason,
        )
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=exc.detail) from None

    body = installer.render(spec, payload)
    name = installer.filename(agent_id=agent_id, architecture=spec.package.architecture)
    if request is not None:
        audit_writer(
            db,
            request=request,
            actor=audit_actor(None, agent_id),
            event_type="agent_action",
            action="agents.installer.download",
            resource_type="agent",
            resource_id=agent_id,
            outcome="success",
            after={
                "agent_id": agent_id,
                "profile": spec.profile,
                "architecture": spec.package.architecture,
                "version": spec.package.version,
                "sources": list(spec.sources),
            },
        )
        repository.commit(db)
    incr_counter(
        "agent_installer_build_total",
        outcome="success",
        architecture=spec.package.architecture,
        reason="",
    )
    return name, body


def sync_packages() -> tuple[str, list]:
    version = settings.SEAGULL_AGENT_RELEASE_VERSION.strip()
    for architecture in settings.SEAGULL_AGENT_SUPPORTED_ARCHITECTURES:
        try:
            packages.ensure(packages.reference(version, architecture))
        except packages.PackageError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=exc.detail) from None
    return version, onboarding.package_states()


def _guard_enroll_rate_limit(request, agent_id: str) -> None:
    if _within_rate_limit(request, scope="agent-enroll", agent_id=agent_id, ip_limit=30, agent_limit=10):
        return
    incr_counter("agent_identity_enroll_total", outcome="rate_limited")
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many enrollment attempts. Try again in a few minutes.",
    )


def _issue_enrollment_certificate(db: Session, *, agent_id: str, csr_pem: str) -> AgentEnrollCertificateOut:
    try:
        issued = certs.issue_enrollment_certificate(agent_id, csr_pem, db=db)
    except certs.CertificateAuthorityUnavailable:
        incr_counter("agent_enroll_cert_issue_total", outcome="failure", reason="ca_unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Certificate authority unavailable",
        ) from None
    except certs.CertificateRequestError as exc:
        incr_counter("agent_enroll_cert_issue_total", outcome="failure", reason=exc.reason)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid certificate request: {exc.detail}",
        ) from exc
    incr_counter("agent_enroll_cert_issue_total", outcome="success")
    return AgentEnrollCertificateOut(
        certificate_pem=issued.certificate_pem,
        ca_pem=issued.ca_pem,
        server_ca_pem=certs.server_ca_bundle(),
        serial_hex=issued.serial_hex,
        not_before=issued.not_before,
        not_after=issued.not_after,
    )


def enroll(
    db: Session,
    *,
    payload: AgentEnrollIn,
    raw_bootstrap_token: str,
    request=None,
    audit_writer=write_audit_event,
) -> AgentEnrollOut:
    _guard_enroll_rate_limit(request, payload.agent_id)
    bootstrap, replay = _authorize_enrollment_token(db, payload, raw_bootstrap_token)
    if replay is not None:
        agent = repository.get_agent_by_agent_id(db, payload.agent_id)
        if not agent or agent.is_revoked:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is revoked")
        return replay
    protocol.ensure_supported(payload.protocol_version, context="enroll")
    _consume_enrollment_token(db, bootstrap)
    rotated_at = datetime.utcnow()
    overlap_until = _credential_overlap_until(rotated_at)
    agent = repository.get_agent_by_agent_id(db, payload.agent_id)
    meta = {
        "hostname": payload.hostname,
        "os": payload.os,
        "arch": payload.arch,
        "version": payload.version,
        "protocol_version": payload.protocol_version,
        "profile": profiles.normalize(payload.profile) or profiles.DEFAULT_PROFILE,
    }
    if not agent:
        default_cfg = settings.default_agent_config()
        if len(json.dumps(default_cfg, separators=(",", ":")).encode("utf-8")) > settings.SEAGULL_MAX_AGENT_CONFIG_BYTES:
            default_cfg = {"revision": 1}
        agent = AgentModel(
            agent_id=payload.agent_id,
            agent_metadata=meta,
            display_name=(payload.hostname or payload.agent_id)[:128],
            description=None,
            tags=[],
            config=default_cfg,
            metrics={},
            created_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
            is_revoked=False,
        )
    else:
        if agent.is_revoked:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is revoked")
        agent.agent_metadata = {**(agent.agent_metadata or {}), **meta}
        agent.config = configuration.normalize(agent.config)
        agent.last_seen_at = datetime.utcnow()
        if not (agent.display_name or "").strip():
            agent.display_name = (payload.hostname or payload.agent_id)[:128]

    _track_observed_address(agent, request, seen_at=agent.last_seen_at or rotated_at)

    _revoke_active_credentials(
        db,
        payload.agent_id,
        "replaced_by_enroll",
        rotated_at=rotated_at,
        overlap_until=overlap_until,
    )

    credential, cred_row = _issue_agent_credential(
        db,
        agent_id=payload.agent_id,
        issued_from_bootstrap_token_id=bootstrap.id,
        replaces_credential_id=None,
    )
    renewal_token, renewal_row = _issue_renewal_token(db, agent_id=payload.agent_id)

    certificate: AgentEnrollCertificateOut | None = None
    if (payload.csr_pem or "").strip():
        certificate = _issue_enrollment_certificate(db, agent_id=payload.agent_id, csr_pem=payload.csr_pem)

    response = AgentEnrollOut(
        agent_id=payload.agent_id,
        config=configuration.normalize(agent.config),
        credential=AgentCredentialOut(
            credential=credential,
            expires_at=cred_row.expires_at,
            max_uses=int(cred_row.max_uses or 1),
            used_uses=int(cred_row.used_uses or 0),
            renewal_token=renewal_token,
            renewal_token_expires_at=renewal_row.expires_at,
        ),
        certificate=certificate,
        protocol=AgentProtocolOut(**protocol.descriptor()),
    )
    enrollment_replay.store(bootstrap, payload, raw_bootstrap_token, response)
    repository.save_bootstrap_token(db, bootstrap)
    repository.save_agent(db, agent)
    if request is not None:
        audit_writer(
            db,
            request=request,
            actor=audit_actor(None, payload.agent_id),
            event_type="agent_action",
            action="agents.enroll",
            resource_type="agent",
            resource_id=payload.agent_id,
            outcome="success",
            after={
                "agent_id": payload.agent_id,
                "token_type": str(bootstrap.token_type or "enrollment"),
                "certificate_issued": certificate is not None,
                "certificate_serial": certificate.serial_hex if certificate else None,
                "hostname": payload.hostname,
                "version": payload.version,
            },
        )
    repository.commit(db)
    incr_counter("agent_identity_enroll_total", outcome="success", token_type=str(bootstrap.token_type or "enrollment"))
    return response


def rotate_credential(db: Session, *, agent: AgentPrincipal) -> AgentCredentialOut:
    row = repository.get_agent_by_id(db, agent.id)
    if not row or row.is_revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")

    rotated_at = datetime.utcnow()
    _revoke_active_credentials(
        db,
        agent.agent_id,
        "rotated",
        rotated_at=rotated_at,
        overlap_until=_credential_overlap_until(rotated_at),
    )

    credential, cred_row = _issue_agent_credential(
        db,
        agent_id=agent.agent_id,
        issued_from_bootstrap_token_id=None,
        replaces_credential_id=agent.credential_id,
    )
    renewal_token, renewal_row = _issue_renewal_token(db, agent_id=agent.agent_id)

    repository.commit(db)
    incr_counter("agent_credential_rotate_total", outcome="success")
    return AgentCredentialOut(
        credential=credential,
        expires_at=cred_row.expires_at,
        max_uses=int(cred_row.max_uses or 1),
        used_uses=int(cred_row.used_uses or 0),
        renewal_token=renewal_token,
        renewal_token_expires_at=renewal_row.expires_at,
    )


def renew_agent_certificate(
    db: Session,
    *,
    payload: AgentCertificateRenewIn,
    request,
    agent: AgentPrincipal,
    audit_writer=write_audit_event,
) -> AgentCertificateRenewOut:
    require_cert_identity(request, agent.agent_id)

    row = repository.get_agent_by_id(db, agent.id)
    if not row or row.is_revoked:
        incr_counter("agent_cert_renew_total", outcome="failure", reason="unknown_or_revoked_agent")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")

    try:
        issued = certs.renew_agent_certificate(agent.agent_id, payload.csr_pem, db=db)
    except certs.CertificateRenewalDisabled:
        incr_counter("agent_cert_renew_total", outcome="failure", reason="disabled")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent certificate renewal is disabled",
        ) from None
    except certs.CertificateAuthorityUnavailable:
        incr_counter("agent_cert_renew_total", outcome="failure", reason="ca_unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Certificate authority unavailable",
        ) from None
    except certs.CertificateRequestError as exc:
        incr_counter("agent_cert_renew_total", outcome="failure", reason=exc.reason)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid certificate request: {exc.detail}",
        ) from exc

    audit_writer(
        db,
        request=request,
        actor=audit_actor(None, agent.agent_id),
        event_type="agent_action",
        action="agents.certificate.renew",
        resource_type="agent",
        resource_id=agent.agent_id,
        outcome="success",
        after={
            "agent_id": agent.agent_id,
            "serial_hex": issued.serial_hex,
            "not_before": issued.not_before.isoformat(),
            "not_after": issued.not_after.isoformat(),
        },
    )
    repository.commit(db)
    incr_counter("agent_cert_renew_total", outcome="success")
    return AgentCertificateRenewOut(
        agent_id=issued.agent_id,
        certificate_pem=issued.certificate_pem,
        ca_pem=issued.ca_pem,
        server_ca_pem=certs.server_ca_bundle(),
        serial_hex=issued.serial_hex,
        not_before=issued.not_before,
        not_after=issued.not_after,
    )


def set_config(
    db: Session,
    *,
    agent_id: str,
    payload: AgentConfigUpdateIn,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> None:
    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    if row.is_revoked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is revoked")
    before = {"agent_id": row.agent_id, "config": row.config if isinstance(row.config, dict) else {}}
    cfg: Dict[str, Any] = configuration.replace(row.config, payload.config)
    _safe_json_size(cfg, settings.SEAGULL_MAX_AGENT_CONFIG_BYTES, "config")
    row.config = cfg
    repository.save_agent(db, row)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="agents.config.update",
        resource_type="agent",
        resource_id=row.agent_id,
        outcome="success",
        before=before,
        after={"agent_id": row.agent_id, "config": row.config},
    )
    repository.commit(db)


def heartbeat(
    db: Session,
    *,
    payload: AgentHeartbeatIn,
    agent: AgentPrincipal,
    request=None,
) -> AgentProtocolOut:
    protocol.ensure_supported(payload.protocol_version, context="heartbeat")
    row = repository.get_agent_by_id(db, agent.id)
    if not row or row.is_revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")
    status_text = str(payload.status or "").strip()[:32]
    row.last_seen_at = datetime.utcnow()
    _track_observed_address(row, request, seen_at=row.last_seen_at)
    current_meta = row.agent_metadata if isinstance(row.agent_metadata, dict) else {}
    effective_profile = profiles.resolve_reported(profiles.of(current_meta), payload.profile)
    if effective_profile != profiles.of(current_meta):
        row.agent_metadata = {**current_meta, "profile": effective_profile}
    row.metrics = {
        **(row.metrics or {}),
        "status": status_text,
        "uptime_seconds": payload.uptime_seconds,
        "agent_version": payload.agent_version,
        "protocol_version": payload.protocol_version,
        "profile": effective_profile,
        "capabilities": payload.capabilities,
        "modules": payload.modules,
        "metrics": payload.metrics,
        "auth_method": agent.auth_method,
        "credential_id": agent.credential_id,
    }
    repository.save_agent(db, row)
    repository.commit(db)
    _publish_agent_heartbeat_realtime(row=row, status_text=status_text)
    return AgentProtocolOut(**protocol.descriptor())


def get_config(db: Session, *, agent: AgentPrincipal) -> dict:
    row = repository.get_agent_by_id(db, agent.id)
    if not row or row.is_revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")
    config = configuration.normalize(row.config)
    if config != row.config:
        row.config = config
        repository.save_agent(db, row)
        repository.commit(db)
    return config


def list_agents(db: Session) -> List[AgentPublic]:
    rows = repository.list_agents(db)
    return [_agent_to_public(a) for a in rows]


def get_agent(db: Session, *, agent_id: str) -> AgentDetail:
    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return _agent_to_detail(row)


def update_agent(
    db: Session,
    *,
    agent_id: str,
    payload: AgentUpdateIn,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> AgentDetail:
    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    before = {
        "agent_id": row.agent_id,
        "display_name": row.display_name,
        "description": row.description,
        "tags": row.tags if isinstance(row.tags, list) else [],
        "metadata": row.agent_metadata if isinstance(row.agent_metadata, dict) else {},
    }
    if payload.display_name is not None:
        dn = payload.display_name.strip()
        row.display_name = dn if dn else None
    if payload.description is not None:
        desc = payload.description.strip()
        row.description = desc if desc else None
    if payload.tags is not None:
        row.tags = _normalize_tags(payload.tags)
        _safe_json_size(row.tags, 8 * 1024, "tags")
    if payload.metadata is not None:
        meta = dict(row.agent_metadata or {})
        patch = dict(payload.metadata or {})
        for k, v in patch.items():
            key = str(k).strip()
            if not key:
                continue
            if v is None:
                meta.pop(key, None)
            elif key == "profile":
                declared = profiles.normalize(v)
                if not declared:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=f"metadata.profile must be one of {', '.join(profiles.VALID_PROFILES)}",
                    )
                meta[key] = declared
            else:
                meta[key] = v
        _safe_json_size(meta, 32 * 1024, "metadata")
        row.agent_metadata = meta
    repository.save_agent(db, row)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="agents.update",
        resource_type="agent",
        resource_id=row.agent_id,
        outcome="success",
        before=before,
        after={
            "agent_id": row.agent_id,
            "display_name": row.display_name,
            "description": row.description,
            "tags": row.tags if isinstance(row.tags, list) else [],
            "metadata": row.agent_metadata if isinstance(row.agent_metadata, dict) else {},
        },
    )
    repository.commit(db)
    repository.refresh(db, row)
    return _agent_to_detail(row)


def reissue_agent_identity(
    db: Session,
    *,
    agent_id: str,
    payload: AgentBootstrapTokenCreateIn,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> AgentBootstrapTokenOut:
    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    if row.is_revoked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is revoked")

    ttl_seconds = int(payload.ttl_seconds or settings.SEAGULL_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS)
    max_uses = int(payload.max_uses or settings.SEAGULL_AGENT_BOOTSTRAP_TOKEN_MAX_USES)
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

    _revoke_active_credentials(db, row.agent_id, "operator_reissue")
    _revoke_active_bootstrap_tokens(db, row.agent_id, "operator_reissue")
    token, _rec = _issue_bootstrap_token(
        db,
        agent_id=row.agent_id,
        token_type="enrollment",
        expires_at=expires_at,
        max_uses=max_uses,
        created_by_user_id=admin.id,
        description=payload.description or "operator-reissue",
    )
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="agents.identity.reissue",
        resource_type="agent",
        resource_id=row.agent_id,
        outcome="success",
        before={"agent_id": row.agent_id, "is_revoked": bool(row.is_revoked)},
        after={
            "agent_id": row.agent_id,
            "bootstrap_token_expires_at": expires_at.isoformat(),
            "bootstrap_token_max_uses": max_uses,
        },
    )
    repository.commit(db)
    incr_counter("agent_identity_reissue_total", outcome="success")
    return AgentBootstrapTokenOut(
        agent_id=row.agent_id,
        bootstrap_token=token,
        expires_at=expires_at,
        max_uses=max_uses,
    )


def disable_agent(
    db: Session,
    *,
    agent_id: str,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> None:
    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    before = {"agent_id": row.agent_id, "is_revoked": bool(row.is_revoked)}
    row.is_revoked = True
    _revoke_active_credentials(db, row.agent_id, "agent_disabled")
    _revoke_active_bootstrap_tokens(db, row.agent_id, "agent_disabled")
    repository.save_agent(db, row)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="agents.disable",
        resource_type="agent",
        resource_id=row.agent_id,
        outcome="success",
        before=before,
        after={"agent_id": row.agent_id, "is_revoked": True},
    )
    repository.commit(db)
    incr_counter("agent_disable_total", outcome="success")


def enable_agent(
    db: Session,
    *,
    agent_id: str,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> None:
    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    before = {"agent_id": row.agent_id, "is_revoked": bool(row.is_revoked)}
    row.is_revoked = False
    repository.save_agent(db, row)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="agents.enable",
        resource_type="agent",
        resource_id=row.agent_id,
        outcome="success",
        before=before,
        after={"agent_id": row.agent_id, "is_revoked": False},
    )
    repository.commit(db)
    incr_counter("agent_enable_total", outcome="success")
