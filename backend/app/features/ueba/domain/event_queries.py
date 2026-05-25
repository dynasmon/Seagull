from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.features.events.models import NetEventModel
from app.features.ueba.models import UebaBaselineModel


@dataclass(frozen=True)
class SshAcceptedEvent:
    id: int
    timestamp: datetime
    agent_id: str
    username: str
    src_ip: str | None


@dataclass(frozen=True)
class SshSourceDiversityObservation:
    agent_id: str
    username: str
    distinct_sources: int
    event_count: int


def fetch_ssh_accepted_events(
    db: Session,
    *,
    after_id: int,
    since: datetime,
    limit: int,
) -> list[SshAcceptedEvent]:
    stmt = (
        select(
            NetEventModel.id,
            NetEventModel.timestamp,
            NetEventModel.agent_id,
            NetEventModel.ssh_username,
            NetEventModel.src_ip,
        )
        .where(
            NetEventModel.id > max(0, int(after_id)),
            NetEventModel.timestamp >= since,
            NetEventModel.event_type == "ssh_auth",
            NetEventModel.ssh_action == "accepted",
            NetEventModel.ssh_username.isnot(None),
            NetEventModel.ssh_username != "",
        )
        .order_by(NetEventModel.id.asc())
        .limit(max(1, int(limit)))
    )
    rows = db.execute(stmt).mappings().all()
    return [
        SshAcceptedEvent(
            id=int(row["id"]),
            timestamp=row["timestamp"],
            agent_id=str(row["agent_id"]),
            username=str(row["ssh_username"]),
            src_ip=(str(row["src_ip"]) if row.get("src_ip") else None),
        )
        for row in rows
    ]


def fetch_ssh_source_diversity(
    db: Session,
    *,
    window_started_at: datetime,
    window_ended_at: datetime,
    limit: int,
) -> tuple[list[SshSourceDiversityObservation], bool]:
    stmt = (
        select(
            NetEventModel.agent_id.label("agent_id"),
            NetEventModel.ssh_username.label("username"),
            func.count(func.distinct(NetEventModel.src_ip)).label("distinct_sources"),
            func.count(NetEventModel.id).label("event_count"),
        )
        .where(
            NetEventModel.timestamp >= window_started_at,
            NetEventModel.timestamp < window_ended_at,
            NetEventModel.event_type == "ssh_auth",
            NetEventModel.ssh_action == "accepted",
            NetEventModel.ssh_username.isnot(None),
            NetEventModel.ssh_username != "",
            NetEventModel.src_ip.isnot(None),
            NetEventModel.src_ip != "",
        )
        .group_by(NetEventModel.agent_id, NetEventModel.ssh_username)
        .order_by(func.count(func.distinct(NetEventModel.src_ip)).desc(), func.count(NetEventModel.id).desc())
        .limit(max(1, int(limit)) + 1)
    )
    rows = db.execute(stmt).mappings().all()
    truncated = len(rows) > max(1, int(limit))
    kept = rows[: max(1, int(limit))]
    return (
        [
            SshSourceDiversityObservation(
                agent_id=str(row["agent_id"]),
                username=str(row["username"]),
                distinct_sources=max(0, int(row["distinct_sources"] or 0)),
                event_count=max(0, int(row["event_count"] or 0)),
            )
            for row in kept
        ],
        truncated,
    )


@dataclass(frozen=True)
class OutboundBytesObservation:
    agent_id: str
    total_bytes: int
    event_count: int


@dataclass(frozen=True)
class LateralSpreadObservation:
    agent_id: str
    distinct_dst_ips: int
    event_count: int


def fetch_outbound_bytes_per_agent(
    db: Session,
    *,
    window_started_at: datetime,
    window_ended_at: datetime,
    limit: int,
) -> tuple[list[OutboundBytesObservation], bool]:
    stmt = (
        select(
            NetEventModel.agent_id.label("agent_id"),
            func.sum(NetEventModel.bytes).label("total_bytes"),
            func.count(NetEventModel.id).label("event_count"),
        )
        .where(
            NetEventModel.timestamp >= window_started_at,
            NetEventModel.timestamp < window_ended_at,
            NetEventModel.event_type.in_(["flow", "l7_flow", "lateral_conn"]),
            NetEventModel.bytes.isnot(None),
        )
        .group_by(NetEventModel.agent_id)
        .order_by(func.sum(NetEventModel.bytes).desc())
        .limit(max(1, int(limit)) + 1)
    )
    rows = db.execute(stmt).mappings().all()
    truncated = len(rows) > max(1, int(limit))
    kept = rows[: max(1, int(limit))]
    return (
        [
            OutboundBytesObservation(
                agent_id=str(row["agent_id"]),
                total_bytes=max(0, int(row["total_bytes"] or 0)),
                event_count=max(0, int(row["event_count"] or 0)),
            )
            for row in kept
        ],
        truncated,
    )


def fetch_lateral_spread_per_agent(
    db: Session,
    *,
    window_started_at: datetime,
    window_ended_at: datetime,
    limit: int,
) -> tuple[list[LateralSpreadObservation], bool]:
    stmt = (
        select(
            NetEventModel.agent_id.label("agent_id"),
            func.count(func.distinct(NetEventModel.dst_ip)).label("distinct_dst_ips"),
            func.count(NetEventModel.id).label("event_count"),
        )
        .where(
            NetEventModel.timestamp >= window_started_at,
            NetEventModel.timestamp < window_ended_at,
            NetEventModel.event_type == "lateral_conn",
            NetEventModel.dst_ip.isnot(None),
        )
        .group_by(NetEventModel.agent_id)
        .order_by(func.count(func.distinct(NetEventModel.dst_ip)).desc(), func.count(NetEventModel.id).desc())
        .limit(max(1, int(limit)) + 1)
    )
    rows = db.execute(stmt).mappings().all()
    truncated = len(rows) > max(1, int(limit))
    kept = rows[: max(1, int(limit))]
    return (
        [
            LateralSpreadObservation(
                agent_id=str(row["agent_id"]),
                distinct_dst_ips=max(0, int(row["distinct_dst_ips"] or 0)),
                event_count=max(0, int(row["event_count"] or 0)),
            )
            for row in kept
        ],
        truncated,
    )


@dataclass(frozen=True)
class ProcExecRateObservation:
    agent_id: str
    exec_count: int


@dataclass(frozen=True)
class ProcExecEvent:
    id: int
    timestamp: datetime
    agent_id: str
    proc_name: str
    proc_exe: str | None
    proc_parent_name: str | None
    effective_uid: int | None = None


def fetch_proc_exec_rate_per_agent(
    db: Session,
    *,
    window_started_at: datetime,
    window_ended_at: datetime,
    limit: int,
) -> tuple[list[ProcExecRateObservation], bool]:
    stmt = (
        select(
            NetEventModel.agent_id.label("agent_id"),
            func.count(NetEventModel.id).label("exec_count"),
        )
        .where(
            NetEventModel.timestamp >= window_started_at,
            NetEventModel.timestamp < window_ended_at,
            NetEventModel.event_type == "proc_exec",
        )
        .group_by(NetEventModel.agent_id)
        .order_by(func.count(NetEventModel.id).desc())
        .limit(max(1, int(limit)) + 1)
    )
    rows = db.execute(stmt).mappings().all()
    truncated = len(rows) > max(1, int(limit))
    kept = rows[: max(1, int(limit))]
    return (
        [
            ProcExecRateObservation(
                agent_id=str(row["agent_id"]),
                exec_count=max(0, int(row["exec_count"] or 0)),
            )
            for row in kept
        ],
        truncated,
    )


def fetch_proc_exec_events(
    db: Session,
    *,
    after_id: int,
    since: datetime,
    limit: int,
) -> list[ProcExecEvent]:
    stmt = (
        select(
            NetEventModel.id,
            NetEventModel.timestamp,
            NetEventModel.agent_id,
            NetEventModel.proc_name,
            NetEventModel.proc_exe,
            NetEventModel.proc_parent_name,
            NetEventModel.extra,
        )
        .where(
            NetEventModel.id > max(0, int(after_id)),
            NetEventModel.timestamp >= since,
            NetEventModel.event_type == "proc_exec",
            NetEventModel.proc_name.isnot(None),
            NetEventModel.proc_name != "",
        )
        .order_by(NetEventModel.id.asc())
        .limit(max(1, int(limit)))
    )
    rows = db.execute(stmt).mappings().all()
    return [
        ProcExecEvent(
            id=int(row["id"]),
            timestamp=row["timestamp"],
            agent_id=str(row["agent_id"]),
            proc_name=str(row["proc_name"]),
            proc_exe=(str(row["proc_exe"]) if row.get("proc_exe") else None),
            proc_parent_name=(str(row["proc_parent_name"]) if row.get("proc_parent_name") else None),
            effective_uid=_effective_uid(row.get("extra")),
        )
        for row in rows
    ]


def fetch_proc_exec_events_for_agent(
    db: Session,
    *,
    agent_id: str,
    since: datetime,
    limit: int,
) -> list[ProcExecEvent]:
    stmt = (
        select(
            NetEventModel.id,
            NetEventModel.timestamp,
            NetEventModel.agent_id,
            NetEventModel.proc_name,
            NetEventModel.proc_exe,
            NetEventModel.proc_parent_name,
            NetEventModel.extra,
        )
        .where(
            NetEventModel.agent_id == agent_id,
            NetEventModel.timestamp >= since,
            NetEventModel.event_type == "proc_exec",
            NetEventModel.proc_name.isnot(None),
            NetEventModel.proc_name != "",
        )
        .order_by(NetEventModel.timestamp.asc(), NetEventModel.id.asc())
        .limit(max(1, int(limit)))
    )
    rows = db.execute(stmt).mappings().all()
    return [
        ProcExecEvent(
            id=int(row["id"]),
            timestamp=row["timestamp"],
            agent_id=str(row["agent_id"]),
            proc_name=str(row["proc_name"]),
            proc_exe=(str(row["proc_exe"]) if row.get("proc_exe") else None),
            proc_parent_name=(str(row["proc_parent_name"]) if row.get("proc_parent_name") else None),
            effective_uid=_effective_uid(row.get("extra")),
        )
        for row in rows
    ]


def fetch_proc_exec_rate_for_agent_at(
    db: Session,
    *,
    agent_id: str,
    window_started_at: datetime,
    window_ended_at: datetime,
) -> int:
    value = db.execute(
        select(func.count(NetEventModel.id)).where(
            NetEventModel.agent_id == agent_id,
            NetEventModel.event_type == "proc_exec",
            NetEventModel.timestamp >= window_started_at,
            NetEventModel.timestamp < window_ended_at,
        )
    ).scalar()
    return max(0, int(value or 0))


def _effective_uid(extra: Any) -> int | None:
    if not isinstance(extra, dict):
        return None
    for key in ("effective_uid", "euid", "uid", "user_id"):
        raw = extra.get(key)
        if raw is None:
            continue
        try:
            return int(raw)
        except (TypeError, ValueError):
            continue
    return None


def fetch_proc_exec_count_for_agent(
    db: Session,
    *,
    agent_id: str,
    since: datetime,
) -> int:
    value = db.execute(
        select(func.count(NetEventModel.id)).where(
            NetEventModel.agent_id == agent_id,
            NetEventModel.event_type == "proc_exec",
            NetEventModel.timestamp >= since,
        )
    ).scalar()
    return max(0, int(value or 0))


def fetch_proc_name_baseline_count_for_agent(
    db: Session,
    *,
    agent_id: str,
    detector_id: str,
) -> int:
    value = db.execute(
        select(func.count(UebaBaselineModel.id)).where(
            UebaBaselineModel.detector_id == detector_id,
            UebaBaselineModel.entity_type == "proc_name",
            UebaBaselineModel.bucket_key == agent_id,
        )
    ).scalar()
    return max(0, int(value or 0))


@dataclass(frozen=True)
class FimRateObservation:
    agent_id: str
    fim_count: int


@dataclass(frozen=True)
class SudoCmdEvent:
    id: int
    timestamp: datetime
    agent_id: str
    username: str
    proc_name: str | None


def fetch_fim_rate_per_agent(
    db: Session,
    *,
    window_started_at: datetime,
    window_ended_at: datetime,
    limit: int,
) -> tuple[list[FimRateObservation], bool]:
    stmt = (
        select(
            NetEventModel.agent_id.label("agent_id"),
            func.count(NetEventModel.id).label("fim_count"),
        )
        .where(
            NetEventModel.timestamp >= window_started_at,
            NetEventModel.timestamp < window_ended_at,
            NetEventModel.event_type == "fim_change",
        )
        .group_by(NetEventModel.agent_id)
        .order_by(func.count(NetEventModel.id).desc())
        .limit(max(1, int(limit)) + 1)
    )
    rows = db.execute(stmt).mappings().all()
    truncated = len(rows) > max(1, int(limit))
    kept = rows[: max(1, int(limit))]
    return (
        [
            FimRateObservation(
                agent_id=str(row["agent_id"]),
                fim_count=max(0, int(row["fim_count"] or 0)),
            )
            for row in kept
        ],
        truncated,
    )


def fetch_fim_spike_evidence(
    db: Session,
    *,
    agent_id: str,
    window_started_at: datetime,
    window_ended_at: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    stmt = (
        select(
            NetEventModel.id,
            NetEventModel.timestamp,
            NetEventModel.fim_path,
            NetEventModel.fim_category,
        )
        .where(
            NetEventModel.timestamp >= window_started_at,
            NetEventModel.timestamp < window_ended_at,
            NetEventModel.event_type == "fim_change",
            NetEventModel.agent_id == agent_id,
            NetEventModel.fim_path.isnot(None),
        )
        .order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
        .limit(max(1, int(limit)))
    )
    return [dict(row) for row in db.execute(stmt).mappings().all()]


def fetch_sudo_cmd_events(
    db: Session,
    *,
    after_id: int,
    since: datetime,
    limit: int,
) -> list[SudoCmdEvent]:
    stmt = (
        select(
            NetEventModel.id,
            NetEventModel.timestamp,
            NetEventModel.agent_id,
            NetEventModel.ssh_username,
            NetEventModel.proc_name,
        )
        .where(
            NetEventModel.id > max(0, int(after_id)),
            NetEventModel.timestamp >= since,
            NetEventModel.event_type == "sudo_cmd",
            NetEventModel.ssh_username.isnot(None),
            NetEventModel.ssh_username != "",
        )
        .order_by(NetEventModel.id.asc())
        .limit(max(1, int(limit)))
    )
    rows = db.execute(stmt).mappings().all()
    return [
        SudoCmdEvent(
            id=int(row["id"]),
            timestamp=row["timestamp"],
            agent_id=str(row["agent_id"]),
            username=str(row["ssh_username"]),
            proc_name=(str(row["proc_name"]) if row.get("proc_name") else None),
        )
        for row in rows
    ]


def fetch_ssh_source_evidence(
    db: Session,
    *,
    agent_id: str,
    username: str,
    window_started_at: datetime,
    window_ended_at: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    stmt = (
        select(
            NetEventModel.id,
            NetEventModel.timestamp,
            NetEventModel.src_ip,
        )
        .where(
            NetEventModel.timestamp >= window_started_at,
            NetEventModel.timestamp < window_ended_at,
            NetEventModel.event_type == "ssh_auth",
            NetEventModel.ssh_action == "accepted",
            NetEventModel.agent_id == agent_id,
            NetEventModel.ssh_username == username,
            NetEventModel.src_ip.isnot(None),
            NetEventModel.src_ip != "",
        )
        .order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
        .limit(max(1, int(limit)))
    )
    return [dict(row) for row in db.execute(stmt).mappings().all()]


@dataclass(frozen=True)
class AgentBehaviorEvent:
    id: int
    timestamp: datetime
    agent_id: str
    event_type: str
    bytes: int | None
    dst_ip: str | None
    src_ip: str | None
    ssh_username: str | None
    ssh_action: str | None
    proc_name: str | None
    proc_exe: str | None
    proc_parent_name: str | None
    fim_path: str | None


def fetch_behavior_events_for_agents(
    db: Session,
    *,
    agent_ids: list[str],
    since: datetime,
    until: datetime,
    limit: int,
) -> list[AgentBehaviorEvent]:
    clean_agents = [str(a) for a in agent_ids if str(a or "").strip()]
    if not clean_agents:
        return []
    stmt = (
        select(
            NetEventModel.id,
            NetEventModel.timestamp,
            NetEventModel.agent_id,
            NetEventModel.event_type,
            NetEventModel.bytes,
            NetEventModel.dst_ip,
            NetEventModel.src_ip,
            NetEventModel.ssh_username,
            NetEventModel.ssh_action,
            NetEventModel.proc_name,
            NetEventModel.proc_exe,
            NetEventModel.proc_parent_name,
            NetEventModel.fim_path,
        )
        .where(
            NetEventModel.agent_id.in_(clean_agents),
            NetEventModel.timestamp >= since,
            NetEventModel.timestamp < until,
            NetEventModel.event_type.in_(
                ["proc_exec", "ssh_auth", "flow", "l7_flow", "lateral_conn", "fim_change", "sudo_cmd"]
            ),
        )
        .order_by(NetEventModel.timestamp.asc(), NetEventModel.id.asc())
        .limit(max(1, int(limit)))
    )
    rows = db.execute(stmt).mappings().all()
    return [
        AgentBehaviorEvent(
            id=int(row["id"]),
            timestamp=row["timestamp"],
            agent_id=str(row["agent_id"]),
            event_type=str(row["event_type"]),
            bytes=(int(row["bytes"]) if row.get("bytes") is not None else None),
            dst_ip=(str(row["dst_ip"]) if row.get("dst_ip") else None),
            src_ip=(str(row["src_ip"]) if row.get("src_ip") else None),
            ssh_username=(str(row["ssh_username"]) if row.get("ssh_username") else None),
            ssh_action=(str(row["ssh_action"]) if row.get("ssh_action") else None),
            proc_name=(str(row["proc_name"]) if row.get("proc_name") else None),
            proc_exe=(str(row["proc_exe"]) if row.get("proc_exe") else None),
            proc_parent_name=(str(row["proc_parent_name"]) if row.get("proc_parent_name") else None),
            fim_path=(str(row["fim_path"]) if row.get("fim_path") else None),
        )
        for row in rows
    ]
