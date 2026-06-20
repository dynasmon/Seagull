from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from app.features.agents import public as agents_public
from app.features.alerts import public as alerts_public
from app.features.attack_chain import public as attack_chain_public
from app.features.exposure.domain.constants import (
    EDGE_TYPE_COMMUNICATES_WITH,
    EDGE_TYPE_EXECUTED_PROCESS,
    EDGE_TYPE_HAS_CVE,
    EDGE_TYPE_HAS_PACKAGE,
    EDGE_TYPE_HAS_SERVICE,
    EDGE_TYPE_MODIFIED_FILE,
    EDGE_TYPE_PART_OF_ATTACK_CHAIN,
    EDGE_TYPE_PART_OF_INVESTIGATION,
    EDGE_TYPE_TRIGGERED_ALERT,
    EDGE_TYPE_TRIGGERED_RESPONSE_ACTION,
    EVIDENCE_SOURCE_ALERT,
    EVIDENCE_SOURCE_ATTACK_CHAIN_CASE,
    EVIDENCE_SOURCE_ATTACK_CHAIN_STEP,
    EVIDENCE_SOURCE_EVENT,
    EVIDENCE_SOURCE_INVESTIGATION,
    EVIDENCE_SOURCE_RESPONSE_ACTION,
    EVIDENCE_SOURCE_VULNERABILITY,
    NODE_TYPE_ALERT,
    NODE_TYPE_ASSET,
    NODE_TYPE_ATTACK_CHAIN_CASE,
    NODE_TYPE_ATTACK_CHAIN_STEP,
    NODE_TYPE_CVE,
    NODE_TYPE_FILE,
    NODE_TYPE_IDENTITY,
    NODE_TYPE_INVESTIGATION,
    NODE_TYPE_IP,
    NODE_TYPE_PACKAGE,
    NODE_TYPE_PROCESS,
    NODE_TYPE_PROTOCOL,
    NODE_TYPE_RESPONSE_ACTION,
    NODE_TYPE_SERVICE,
    RC_ACTIVE_ALERT,
    RC_ATTACK_CHAIN_PROGRESSION,
    RC_BRUTE_FORCE_ACTIVITY,
    RC_CRITICAL_CVE,
    RC_EXPLOITABILITY_SIGNAL,
    RC_LATERAL_MOVEMENT_SIGNAL,
    RC_PERSISTENCE_SIGNAL,
    RC_SENSITIVE_FILE_CHANGE,
    RC_SUSPICIOUS_PROCESS,
    RC_VULNERABLE_PACKAGE,
)
from app.features.exposure.domain.evidence import build_evidence_ref, merge_evidence_refs
from app.features.exposure.domain.normalization import (
    clamp_confidence,
    clamp_score,
    extract_inventory_os_context,
    make_edge_key,
    make_finding_key,
    make_node_key,
    normalize_severity,
    severity_from_score,
)
from app.features.exposure.domain.types import EdgeInput, EvidenceRef, FindingInput, NodeInput
from app.features.inventory import public as inventory_public
from app.features.investigations import public as investigations_public
from app.features.response import public as response_public
from app.features.vuln import public as vuln_public

# Security-relevant package name fragments used to filter package nodes.
# Keeping this bounded avoids creating thousands of low-value package nodes.

_SECURITY_RELEVANT_PKG_PATTERNS = re.compile(
    r"(openssl|libssl|openssh|ssh|sudo|bash|kernel|glibc|libc|curl|wget|"
    r"nginx|apache|httpd|tomcat|java|jdk|jre|python|ruby|perl|php|node|"
    r"docker|containerd|runc|nss|pam|krb5|openldap|samba|postfix|sendmail|"
    r"bind|dnsmasq|exim|procps|shadow|util-linux|polkit|dbus|systemd|"
    r"netfilter|iptables|nftables|rsync|redis|postgres|mysql|mongodb)",
    re.IGNORECASE,
)

_MAX_PACKAGE_NODES = 50
_MAX_EVIDENCE_REFS_PER_FINDING = 8


# Intermediate record types


@dataclass
class AgentRecord:
    agent_id: str
    display_name: str
    last_seen_at: Optional[datetime]
    criticality: str
    is_revoked: bool


@dataclass
class InventoryData:
    agent_id: str
    collected_at: Optional[datetime]
    hostname: Optional[str]
    os_name: Optional[str]
    packages_count: int
    packages: list[dict[str, Any]] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)


@dataclass
class VulnSignals:
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    has_exploitability_signal: bool = False
    cve_refs: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AlertSignals:
    active_count: int = 0
    brute_force_count: int = 0
    lateral_movement_count: int = 0
    suspicious_process_count: int = 0
    persistence_count: int = 0
    alert_refs: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ChainSummary:
    open_case_count: int = 0
    max_score: int = 0
    case_refs: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class EventSignals:
    ssh_fail_count: int = 0
    fim_count: int = 0
    persistence_count: int = 0
    suspicious_proc_count: int = 0
    lateral_movement_count: int = 0
    agent_id: str = ""


@dataclass
class ResponseActionContext:
    action_id: int
    action_type: str
    status: str
    requested_at: Optional[datetime]
    result_status: Optional[str] = None


# Agent loader


def load_agents_for_refresh(db: Session, *, limit: int) -> list[AgentRecord]:
    out: list[AgentRecord] = []
    for summary in agents_public.list_active_agents_for_refresh(db, limit=limit):
        criticality = str(summary.config.get("criticality") or "unknown").lower()
        if criticality not in {"critical", "high", "medium", "low", "none", "unknown"}:
            criticality = "unknown"
        out.append(
            AgentRecord(
                agent_id=str(summary.agent_id),
                display_name=str(summary.display_name or summary.agent_id),
                last_seen_at=summary.last_seen_at,
                criticality=criticality,
                is_revoked=bool(summary.is_revoked or False),
            )
        )
    return out


def load_agent_record(
    db: Session,
    *,
    agent_id: str,
    fallback_last_seen_at: datetime | None = None,
) -> AgentRecord:
    summary = agents_public.get_agent_summary(db, agent_id=agent_id)
    if summary is None:
        return AgentRecord(
            agent_id=agent_id,
            display_name=agent_id,
            last_seen_at=fallback_last_seen_at,
            criticality="unknown",
            is_revoked=False,
        )

    criticality = str(summary.config.get("criticality") or "unknown").lower()
    if criticality not in {"critical", "high", "medium", "low", "none", "unknown"}:
        criticality = "unknown"
    return AgentRecord(
        agent_id=str(summary.agent_id),
        display_name=str(summary.display_name or summary.agent_id),
        last_seen_at=summary.last_seen_at or fallback_last_seen_at,
        criticality=criticality,
        is_revoked=bool(summary.is_revoked or False),
    )


# Inventory loader


def load_inventory_data(db: Session, agent_id: str) -> Optional[InventoryData]:
    latest = inventory_public.get_latest_inventory_for_agent(db, agent_id=agent_id)
    if latest is None:
        return None

    os_context = extract_inventory_os_context(latest.os)

    packages: list[dict[str, Any]] = []
    if latest.snapshot_id is not None:
        packages = inventory_public.get_snapshot_packages(db, snapshot_id=int(latest.snapshot_id))

    return InventoryData(
        agent_id=agent_id,
        collected_at=latest.collected_at,
        hostname=os_context["hostname"],
        os_name=os_context["os_name"],
        packages_count=int(latest.packages_count or 0),
        packages=packages,
        open_ports=os_context["open_ports"],
        ip_addresses=os_context["ip_addresses"],
    )


# Vulnerability signals

_EXPLOITABLE_KEYWORDS = re.compile(
    r"(exploit|metasploit|poc|proof.of.concept|weaponized|in.the.wild|actively.exploited)",
    re.IGNORECASE,
)


def _parse_cvss_score(cvss: str | None) -> float | None:
    if not cvss:
        return None
    try:
        return float(cvss.strip())
    except ValueError:
        m = re.search(r"(\d+\.\d+)$", cvss)
        if m:
            return float(m.group(1))
        return None


def load_vuln_signals(
    db: Session,
    *,
    asset_key: str,
    agent_id: Optional[str],
    lookback_dt: datetime,
) -> VulnSignals:
    rows = vuln_public.list_active_finding_signals_for_asset(
        db, asset_key=asset_key, lookback=lookback_dt, limit=500
    )

    signals = VulnSignals()
    for r in rows:
        rank = int(r.severity_rank or 0)
        if rank >= 5:
            signals.critical_count += 1
        elif rank == 4:
            signals.high_count += 1
        elif rank == 3:
            signals.medium_count += 1
        elif rank > 0:
            signals.low_count += 1

        cve = str(r.cve or "").strip()
        evidence_json = r.evidence if isinstance(r.evidence, dict) else {}
        evidence_str = str(evidence_json) + str(r.title or "")
        if not signals.has_exploitability_signal:
            # High-severity with CVE is a conservative exploitability signal
            if rank >= 4 and cve:
                signals.has_exploitability_signal = True
            elif _EXPLOITABLE_KEYWORDS.search(evidence_str):
                signals.has_exploitability_signal = True

        last_seen = r.last_seen_at
        if cve and len(signals.cve_refs) < _MAX_EVIDENCE_REFS_PER_FINDING:
            ref = build_evidence_ref(
                source_type=EVIDENCE_SOURCE_VULNERABILITY,
                source_id=str(r.id),
                observed_at=last_seen,
                title=str(r.title or cve),
                summary=f"{normalize_severity(r.severity)} CVE {cve}",
            )
            signals.cve_refs.append(ref.to_dict())

    return signals


# Alert signals

_MITRE_BRUTE_FORCE_TACTICS = {"credential-access", "initial-access"}
_MITRE_LATERAL_TACTICS = {"lateral-movement"}
_MITRE_PERSISTENCE_TACTICS = {"persistence"}
_MITRE_EXEC_TACTICS = {"execution"}


def _classify_alert(tactic: str, technique: str, description: str) -> str:
    tactic_lower = (tactic or "").lower().replace("_", "-")
    desc_lower = (description or "").lower()
    if tactic_lower in _MITRE_LATERAL_TACTICS or "lateral" in desc_lower:
        return "lateral_movement"
    if tactic_lower in _MITRE_BRUTE_FORCE_TACTICS or "brute" in desc_lower or "brute-force" in desc_lower:
        return "brute_force"
    if tactic_lower in _MITRE_PERSISTENCE_TACTICS or "persistence" in desc_lower:
        return "persistence"
    if tactic_lower in _MITRE_EXEC_TACTICS or "execut" in desc_lower or "process" in desc_lower:
        return "suspicious_process"
    return "active_alert"


def _alert_age_multiplier(created_at: datetime | None, now: datetime) -> float:
    if created_at is None:
        return 0.4
    created_at = ensure_utc(created_at)
    now = ensure_utc(now)
    age_hours = max(0.0, (now - created_at).total_seconds() / 3600.0)
    if age_hours <= 6:
        return 1.0
    if age_hours <= 24:
        return 0.7
    if age_hours <= 72:
        return 0.4
    return 0.2


def _alert_severity_weight(severity: str) -> float:
    return {
        "critical": 2.0,
        "high": 1.5,
        "medium": 1.0,
        "low": 0.5,
        "informational": 0.25,
        "unknown": 0.4,
    }.get(normalize_severity(severity), 0.4)


def load_alert_signals(
    db: Session,
    *,
    agent_id: str,
    lookback_dt: datetime,
    asset_ips: tuple[str, ...] = (),
    hostname: str | None = None,
    now: datetime | None = None,
) -> AlertSignals:
    now = now or datetime.now(timezone.utc)

    rows = alerts_public.list_asset_alert_summaries(
        db,
        agent_id=agent_id,
        asset_ips=asset_ips,
        hostname=hostname,
        lookback=lookback_dt,
        limit=200,
    )

    signals = AlertSignals()
    for r in rows:
        tactic = str(r.mitre_tactic or "")
        technique = str(r.mitre_technique or "")
        description = str(r.description or "")
        kind = _classify_alert(tactic, technique, description)
        weight = max(
            1,
            int(
                round(
                    _alert_severity_weight(str(r.severity or ""))
                    * _alert_age_multiplier(r.created_at, now)
                )
            ),
        )

        if kind == "lateral_movement":
            signals.lateral_movement_count += weight
        elif kind == "brute_force":
            signals.brute_force_count += weight
        elif kind == "persistence":
            signals.persistence_count += weight
        elif kind == "suspicious_process":
            signals.suspicious_process_count += weight
        else:
            signals.active_count += weight

        if len(signals.alert_refs) < _MAX_EVIDENCE_REFS_PER_FINDING:
            ref = build_evidence_ref(
                source_type=EVIDENCE_SOURCE_ALERT,
                source_id=str(r.id),
                observed_at=r.created_at,
                title=str(r.description or f"Alert {r.id}"),
                summary=f"{r.severity or 'unknown'} severity alert",
            )
            signals.alert_refs.append(ref.to_dict())

    return signals


# Attack chain summary


def load_chain_summary(db: Session, *, agent_id: str) -> ChainSummary:
    rows = attack_chain_public.list_open_case_summaries_for_agent(
        db, agent_id=agent_id, limit=10, recency_tiebreak=True
    )

    summary = ChainSummary()
    for r in rows:
        summary.open_case_count += 1
        score = int(r.score or 0)
        if score > summary.max_score:
            summary.max_score = score

        if len(summary.case_refs) < _MAX_EVIDENCE_REFS_PER_FINDING:
            ref = build_evidence_ref(
                source_type=EVIDENCE_SOURCE_ATTACK_CHAIN_CASE,
                source_id=str(r.id),
                observed_at=r.last_seen_at,
                title=f"Attack chain case {r.id} [{r.max_stage or 'initial_access'}]",
                summary=f"Score {score}, {r.step_count or 0} steps",
            )
            summary.case_refs.append(ref.to_dict())

    return summary


# Event signal projection (incremental, per-event classification)

_SSH_EVENT_TYPES = {"ssh_auth"}
_FIM_EVENT_TYPES = {"fim_change"}
_PERSISTENCE_EVENT_TYPES = {"persistence_systemd", "persistence_cron", "ssh_key_change"}
_EXEC_EVENT_TYPES = {"proc_exec", "ebpf_exec"}
_SUSPICIOUS_EXEC_PATTERNS = re.compile(
    r"(curl\s|wget\s|bash\s+-i|nc\s|ncat\s|python.*-c|perl.*-e|"
    r"chmod\s+[0-7]*[7][0-7]*\s|base64|/tmp/|/dev/shm/|mkfifo)",
    re.IGNORECASE,
)
_LATERAL_EVENT_TYPES = {"beacon_suspect", "c2_suspect", "exfil_suspect", "egress_anomaly"}


def project_event_signals(event: dict[str, Any]) -> Optional[EventSignals]:
    event_type = str(event.get("event_type") or "").strip().lower()
    agent_id = str(event.get("agent_id") or "").strip()
    if not agent_id:
        return None

    extra = event.get("extra") if isinstance(event.get("extra"), dict) else {}

    signals = EventSignals(agent_id=agent_id)

    if event_type in _SSH_EVENT_TYPES:
        action = str(extra.get("action") or event.get("ssh_action") or "").lower()
        if action in {"failed", "invalid", "error", "denied"}:
            signals.ssh_fail_count = 1
        return signals if signals.ssh_fail_count > 0 else None

    if event_type in _FIM_EVENT_TYPES:
        path_cat = str(extra.get("path_category") or "").lower()
        tamper = bool(extra.get("tamper_related") or extra.get("security_file"))
        if tamper or path_cat in {"security_file", "auth_file", "config_file"}:
            signals.fim_count = 1
            return signals
        return None

    if event_type in _PERSISTENCE_EVENT_TYPES:
        signals.persistence_count = 1
        return signals

    if event_type in _EXEC_EVENT_TYPES:
        cmdline = str(extra.get("cmdline") or "").strip()
        patterns = list(extra.get("exec_patterns") or [])
        is_suspicious = bool(_SUSPICIOUS_EXEC_PATTERNS.search(cmdline))
        is_suspicious = is_suspicious or any(
            p in {
                "remote_fetch_exec",
                "exec_reverse_shell",
                "exec_priv_escalation",
                "exec_lolbin",
                "exec_service_shell",
            }
            for p in patterns
        )
        if is_suspicious:
            signals.suspicious_proc_count = 1
            return signals
        return None

    if event_type in _LATERAL_EVENT_TYPES:
        confidence = int(extra.get("confidence") or event.get("heuristic_confidence") or 0)
        if confidence >= 60:
            signals.lateral_movement_count = 1
            return signals
        return None

    return None


def load_recent_event_rows(
    db: Session,
    *,
    agent_id: str,
    lookback_dt: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    from app.features.events.models import NetEventModel  # noqa: PLC0415

    relevant_types = {
        "ssh_auth",
        "fim_change",
        "persistence_systemd",
        "persistence_cron",
        "ssh_key_change",
        "proc_exec",
        "ebpf_exec",
        "beacon_suspect",
        "c2_suspect",
        "exfil_suspect",
        "egress_anomaly",
        "flow",
        "l7_flow",
    }
    stmt = (
        select(
            NetEventModel.id,
            NetEventModel.agent_id,
            NetEventModel.event_type,
            NetEventModel.timestamp,
            NetEventModel.src_ip,
            NetEventModel.dst_ip,
            NetEventModel.src_port,
            NetEventModel.dst_port,
            NetEventModel.proto,
            NetEventModel.app_proto,
            NetEventModel.dns_qname,
            NetEventModel.http_host,
            NetEventModel.http_method,
            NetEventModel.tls_sni,
            NetEventModel.tls_alpn_first,
            NetEventModel.ja3,
            NetEventModel.ja4,
            NetEventModel.ssh_action,
            NetEventModel.ssh_username,
            NetEventModel.proc_name,
            NetEventModel.proc_exe,
            NetEventModel.proc_parent_name,
            NetEventModel.fim_path,
            NetEventModel.fim_category,
            NetEventModel.heuristic_name,
            NetEventModel.heuristic_confidence,
            NetEventModel.extra,
        )
        .where(
            NetEventModel.agent_id == agent_id,
            NetEventModel.timestamp >= lookback_dt,
            or_(
                NetEventModel.event_type.in_(list(relevant_types)),
                NetEventModel.app_proto.isnot(None),
                NetEventModel.dns_qname.isnot(None),
                NetEventModel.http_host.isnot(None),
                NetEventModel.tls_sni.isnot(None),
                NetEventModel.proc_name.isnot(None),
                NetEventModel.fim_path.isnot(None),
            ),
        )
        .order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
        .limit(int(limit))
    )
    return [dict(r) for r in db.execute(stmt).mappings().all()]


# Node builders


def build_asset_node(
    asset_key: str,
    *,
    agent_id: Optional[str],
    display_name: str,
    risk_score: int,
    severity: str,
    confidence: int,
    now: datetime,
    first_seen_at: Optional[datetime] = None,
) -> NodeInput:
    node_key = make_node_key(NODE_TYPE_ASSET, asset_key)
    return NodeInput(
        node_key=node_key,
        node_type=NODE_TYPE_ASSET,
        label=display_name,
        severity=normalize_severity(severity),
        risk_score=clamp_score(risk_score),
        confidence=clamp_confidence(confidence),
        asset_key=asset_key,
        agent_id=agent_id,
        first_seen_at=first_seen_at or now,
        last_seen_at=now,
        properties={"display_name": display_name},
    )


def build_cve_nodes_and_edges(
    db: Session,
    *,
    asset_key: str,
    agent_id: Optional[str],
    asset_node_key: str,
    now: datetime,
    max_nodes: int,
    lookback_dt: datetime,
) -> tuple[list[NodeInput], list[EdgeInput]]:
    rows = vuln_public.list_active_cve_findings_for_asset(
        db, asset_key=asset_key, lookback=lookback_dt, limit=max_nodes
    )

    nodes: list[NodeInput] = []
    edges: list[EdgeInput] = []
    seen_cves: set[str] = set()

    for r in rows:
        cve = str(r.cve or "").strip().upper()
        if not cve or cve in seen_cves:
            continue
        seen_cves.add(cve)

        sev = normalize_severity(r.severity)
        cvss_float = _parse_cvss_score(r.cvss)
        risk_score = clamp_score((cvss_float or 0) * 10) if cvss_float else _sev_to_score(sev)
        node_key = make_asset_scoped_node_key(NODE_TYPE_CVE, asset_key, cve)
        last_seen = r.last_seen_at or now

        nodes.append(
            NodeInput(
                node_key=node_key,
                node_type=NODE_TYPE_CVE,
                label=cve,
                severity=sev,
                risk_score=risk_score,
                confidence=clamp_confidence(int(r.confidence or 60)),
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=last_seen,
                last_seen_at=last_seen,
                properties={"cve": cve, "cvss": r.cvss},
            )
        )
        edge_key = make_edge_key(asset_node_key, node_key, EDGE_TYPE_HAS_CVE)
        edges.append(
            EdgeInput(
                edge_key=edge_key,
                source_node_key=asset_node_key,
                target_node_key=node_key,
                edge_type=EDGE_TYPE_HAS_CVE,
                weight=1.0,
                confidence=clamp_confidence(int(r.confidence or 60)),
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=last_seen,
                last_seen_at=last_seen,
            )
        )
        pkg_name = extract_package_name_from_location(r.location)
        if pkg_name:
            pkg_node_key = make_asset_scoped_node_key(NODE_TYPE_PACKAGE, asset_key, pkg_name)
            edges.append(
                EdgeInput(
                    edge_key=make_edge_key(pkg_node_key, node_key, EDGE_TYPE_HAS_CVE),
                    source_node_key=pkg_node_key,
                    target_node_key=node_key,
                    edge_type=EDGE_TYPE_HAS_CVE,
                    weight=0.9,
                    confidence=clamp_confidence(int(r.get("confidence") or 60)),
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=last_seen,
                    last_seen_at=last_seen,
                )
            )

    return nodes, edges


def build_package_nodes_and_edges(
    packages: list[dict[str, Any]],
    *,
    asset_key: str,
    agent_id: Optional[str],
    asset_node_key: str,
    vulnerable_pkg_names: frozenset[str],
    now: datetime,
    max_nodes: int,
) -> tuple[list[NodeInput], list[EdgeInput]]:
    nodes: list[NodeInput] = []
    edges: list[EdgeInput] = []
    seen: set[str] = set()

    prioritized: list[dict[str, Any]] = []
    remainder: list[dict[str, Any]] = []

    for pkg in packages:
        name = str(pkg.get("name") or "").strip().lower()
        if not name:
            continue
        is_vuln = name in vulnerable_pkg_names
        is_relevant = bool(_SECURITY_RELEVANT_PKG_PATTERNS.search(name))
        if is_vuln or is_relevant:
            prioritized.append(pkg)
        else:
            remainder.append(pkg)

    candidates = (prioritized + remainder)[:max_nodes]

    for pkg in candidates:
        name = str(pkg.get("name") or "").strip().lower()
        version = str(pkg.get("version") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)

        node_key = make_asset_scoped_node_key(NODE_TYPE_PACKAGE, asset_key, name)
        is_vuln = name in vulnerable_pkg_names

        nodes.append(
            NodeInput(
                node_key=node_key,
                node_type=NODE_TYPE_PACKAGE,
                label=f"{name} {version}".strip(),
                severity="high" if is_vuln else "informational",
                risk_score=50 if is_vuln else 0,
                confidence=80,
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=now,
                last_seen_at=now,
                properties={"name": name, "version": version, "manager": pkg.get("manager")},
            )
        )
        edge_key = make_edge_key(asset_node_key, node_key, EDGE_TYPE_HAS_PACKAGE)
        edges.append(
            EdgeInput(
                edge_key=edge_key,
                source_node_key=asset_node_key,
                target_node_key=node_key,
                edge_type=EDGE_TYPE_HAS_PACKAGE,
                weight=0.5,
                confidence=80,
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=now,
                last_seen_at=now,
            )
        )

    return nodes, edges


def build_inventory_service_nodes_and_edges(
    open_ports: list[int],
    *,
    asset_key: str,
    agent_id: Optional[str],
    asset_node_key: str,
    now: datetime,
    max_nodes: int,
) -> tuple[list[NodeInput], list[EdgeInput]]:
    nodes: list[NodeInput] = []
    edges: list[EdgeInput] = []
    seen_ports: set[int] = set()

    for port in sorted({int(p) for p in open_ports if p is not None})[:max_nodes]:
        if port in seen_ports:
            continue
        seen_ports.add(port)
        identifier = f"tcp/{port}"
        node_key = make_asset_scoped_node_key(NODE_TYPE_SERVICE, asset_key, identifier)
        risk_score = 28 if port in {22, 3389, 445, 5432, 6379, 9200} else 12
        nodes.append(
            NodeInput(
                node_key=node_key,
                node_type=NODE_TYPE_SERVICE,
                label=f"Service {identifier}",
                severity="medium" if risk_score >= 20 else "informational",
                risk_score=risk_score,
                confidence=68,
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=now,
                last_seen_at=now,
                properties={"port": port, "protocol": "tcp", "source": "inventory"},
            )
        )
        edges.append(
            EdgeInput(
                edge_key=make_edge_key(asset_node_key, node_key, EDGE_TYPE_HAS_SERVICE),
                source_node_key=asset_node_key,
                target_node_key=node_key,
                edge_type=EDGE_TYPE_HAS_SERVICE,
                weight=0.8,
                confidence=68,
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=now,
                last_seen_at=now,
            )
        )

    return nodes, edges


def build_alert_nodes_and_edges(
    db: Session,
    *,
    asset_key: str,
    agent_id: str,
    asset_ips: tuple[str, ...] = (),
    hostname: str | None = None,
    asset_node_key: str,
    now: datetime,
    max_nodes: int,
    lookback_dt: datetime,
) -> tuple[list[NodeInput], list[EdgeInput]]:
    rows = alerts_public.list_asset_alert_summaries(
        db,
        agent_id=agent_id,
        asset_ips=asset_ips,
        hostname=hostname,
        lookback=lookback_dt,
        limit=max_nodes,
    )

    nodes: list[NodeInput] = []
    edges: list[EdgeInput] = []

    for r in rows:
        alert_id = str(r.id)
        node_key = make_node_key(NODE_TYPE_ALERT, alert_id)
        sev = normalize_severity(r.severity)
        created_at = r.created_at or now

        nodes.append(
            NodeInput(
                node_key=node_key,
                node_type=NODE_TYPE_ALERT,
                label=str(r.description or f"Alert {alert_id}")[:256],
                severity=sev,
                risk_score=_sev_to_score(sev),
                confidence=clamp_confidence(int(r.confidence or 70)),
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=created_at,
                last_seen_at=created_at,
                properties={"mitre_tactic": r.mitre_tactic},
            )
        )
        edge_key = make_edge_key(asset_node_key, node_key, EDGE_TYPE_TRIGGERED_ALERT)
        edges.append(
            EdgeInput(
                edge_key=edge_key,
                source_node_key=asset_node_key,
                target_node_key=node_key,
                edge_type=EDGE_TYPE_TRIGGERED_ALERT,
                weight=1.0,
                confidence=clamp_confidence(int(r.confidence or 70)),
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=created_at,
                last_seen_at=created_at,
            )
        )

    return nodes, edges


def build_attack_chain_nodes_and_edges(
    db: Session,
    *,
    asset_key: str,
    agent_id: str,
    asset_node_key: str,
    now: datetime,
    max_nodes: int,
) -> tuple[list[NodeInput], list[EdgeInput]]:
    rows = attack_chain_public.list_open_case_summaries_for_agent(
        db, agent_id=agent_id, limit=max_nodes
    )

    nodes: list[NodeInput] = []
    edges: list[EdgeInput] = []
    case_ids: list[int] = []

    for r in rows:
        case_id = str(r.id)
        case_ids.append(int(case_id))
        score = int(r.score or 0)
        sev = severity_from_score(score)
        node_key = make_node_key(NODE_TYPE_ATTACK_CHAIN_CASE, case_id)
        first_seen = r.first_seen_at or now
        last_seen = r.last_seen_at or now

        nodes.append(
            NodeInput(
                node_key=node_key,
                node_type=NODE_TYPE_ATTACK_CHAIN_CASE,
                label=f"Attack chain case {case_id} [{r.max_stage or 'initial_access'}]",
                severity=sev,
                risk_score=clamp_score(score),
                confidence=72,
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=first_seen,
                last_seen_at=last_seen,
                properties={
                    "case_id": int(case_id),
                    "max_stage": r.max_stage,
                    "step_count": r.step_count,
                },
            )
        )
        edge_key = make_edge_key(asset_node_key, node_key, EDGE_TYPE_PART_OF_ATTACK_CHAIN)
        edges.append(
            EdgeInput(
                edge_key=edge_key,
                source_node_key=asset_node_key,
                target_node_key=node_key,
                edge_type=EDGE_TYPE_PART_OF_ATTACK_CHAIN,
                weight=1.5,
                confidence=72,
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=first_seen,
                last_seen_at=last_seen,
            )
        )

    if not case_ids or len(nodes) >= max_nodes:
        return nodes, edges

    remaining_nodes = max(0, max_nodes - len(nodes))
    step_rows = attack_chain_public.list_step_graph_summaries_for_cases(
        db, case_ids=case_ids, limit=max(remaining_nodes * 3, remaining_nodes)
    )
    case_node_keys = {int(r.id): make_node_key(NODE_TYPE_ATTACK_CHAIN_CASE, str(r.id)) for r in rows}
    seen_steps: set[int] = set()
    for step in step_rows:
        if len(nodes) >= max_nodes:
            break
        step_id = int(step.id)
        if step_id in seen_steps:
            continue
        seen_steps.add(step_id)
        case_id = int(step.case_id)
        ts = step.timestamp or now
        score_delta = clamp_score(int(step.score_delta or 0) * 2)
        node_key = make_node_key(NODE_TYPE_ATTACK_CHAIN_STEP, str(step_id))
        nodes.append(
            NodeInput(
                node_key=node_key,
                node_type=NODE_TYPE_ATTACK_CHAIN_STEP,
                label=str(step.label or step.stage or f"Step {step_id}")[:256],
                severity=severity_from_score(score_delta),
                risk_score=score_delta,
                confidence=76,
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=ts,
                last_seen_at=ts,
                properties={
                    "case_id": case_id,
                    "stage": step.stage,
                    "event_id": step.event_id,
                    "event_type": step.event_type,
                    "src_ip": step.src_ip,
                    "dst_ip": step.dst_ip,
                    "proto": step.proto,
                },
                source_refs=_attack_chain_step_source_refs(step),
            )
        )
        case_node_key = case_node_keys.get(case_id)
        if case_node_key:
            edges.append(
                EdgeInput(
                    edge_key=make_edge_key(case_node_key, node_key, EDGE_TYPE_PART_OF_ATTACK_CHAIN),
                    source_node_key=case_node_key,
                    target_node_key=node_key,
                    edge_type=EDGE_TYPE_PART_OF_ATTACK_CHAIN,
                    weight=1.0,
                    confidence=76,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                )
            )

    return nodes, edges


# Finding builders


def build_vuln_findings(
    db: Session,
    *,
    asset_key: str,
    agent_id: Optional[str],
    lookback_dt: datetime,
    max_findings: int,
    now: datetime,
) -> list[FindingInput]:
    rows = vuln_public.list_open_findings_for_asset(
        db, asset_key=asset_key, lookback=lookback_dt, limit=max_findings
    )

    out: list[FindingInput] = []
    for r in rows:
        cve = str(r.cve or "").strip()
        title = str(r.title or cve or f"Vulnerability {r.id}")
        sev = normalize_severity(r.severity)
        rank = int(r.severity_rank or 0)
        score_delta = {5: 30, 4: 18, 3: 8, 2: 3, 1: 1}.get(rank, 1)

        fkey = make_finding_key("vulnerability", asset_key, str(r.fingerprint or r.id))
        ref = build_evidence_ref(
            source_type=EVIDENCE_SOURCE_VULNERABILITY,
            source_id=str(r.id),
            observed_at=r.last_seen_at,
            title=title,
            summary=f"{sev} severity{' CVE: ' + cve if cve else ''}",
        )
        related_keys: list[str] = []
        if cve:
            related_keys.append(make_asset_scoped_node_key(NODE_TYPE_CVE, asset_key, cve.upper()))

        out.append(
            FindingInput(
                finding_key=fkey,
                finding_type="vulnerability",
                asset_key=asset_key,
                agent_id=agent_id,
                severity=sev,
                score_delta=score_delta,
                confidence=clamp_confidence(int(r.confidence or 60)),
                title=title,
                summary=str(r.description or "")[:512],
                status="open",
                first_seen_at=r.first_seen_at or now,
                last_seen_at=r.last_seen_at or now,
                related_node_keys=related_keys,
                evidence_refs=[ref],
                reason_codes=_vuln_reason_codes(rank),
            )
        )

    return out


def build_alert_findings(
    db: Session,
    *,
    asset_key: str,
    agent_id: str,
    asset_ips: tuple[str, ...] = (),
    hostname: str | None = None,
    lookback_dt: datetime,
    max_findings: int,
    now: datetime,
) -> list[FindingInput]:
    rows = alerts_public.list_asset_alert_summaries(
        db,
        agent_id=agent_id,
        asset_ips=asset_ips,
        hostname=hostname,
        lookback=lookback_dt,
        limit=max_findings,
    )

    out: list[FindingInput] = []
    for r in rows:
        alert_id = str(r.id)
        sev = normalize_severity(r.severity)
        tactic = str(r.mitre_tactic or "")
        technique = str(r.mitre_technique or "")
        desc = str(r.description or "")
        kind = _classify_alert(tactic, technique, desc)
        score_delta = _alert_score_delta(sev, kind)

        fkey = make_finding_key("alert", asset_key, alert_id)
        ref = build_evidence_ref(
            source_type=EVIDENCE_SOURCE_ALERT,
            source_id=alert_id,
            observed_at=r.created_at,
            title=desc[:256] or f"Alert {alert_id}",
            summary=f"{sev} {tactic}",
        )
        related_keys = [make_node_key(NODE_TYPE_ALERT, alert_id)]

        out.append(
            FindingInput(
                finding_key=fkey,
                finding_type="alert",
                asset_key=asset_key,
                agent_id=agent_id,
                severity=sev,
                score_delta=score_delta,
                confidence=clamp_confidence(int(r.confidence or 70)),
                title=desc[:256] or f"Alert {alert_id}",
                summary=f"MITRE: {tactic} {technique}".strip(),
                status="open",
                first_seen_at=r.created_at or now,
                last_seen_at=r.created_at or now,
                related_node_keys=related_keys,
                evidence_refs=[ref],
                reason_codes=_alert_reason_codes(kind),
            )
        )

    return out


def build_attack_chain_findings(
    db: Session,
    *,
    asset_key: str,
    agent_id: str,
    max_findings: int,
    now: datetime,
) -> list[FindingInput]:
    rows = attack_chain_public.list_open_case_summaries_for_agent(
        db, agent_id=agent_id, limit=max_findings
    )

    out: list[FindingInput] = []
    for r in rows:
        case_id = str(r.id)
        score = int(r.score or 0)
        sev = severity_from_score(score)
        max_stage = str(r.max_stage or "initial_access")
        fkey = make_finding_key("attack_chain_case", asset_key, case_id)
        ref = build_evidence_ref(
            source_type=EVIDENCE_SOURCE_ATTACK_CHAIN_CASE,
            source_id=case_id,
            observed_at=r.last_seen_at,
            title=f"Attack chain case {case_id}",
            summary=f"Stage: {max_stage}, score: {score}, suspect_ip: {r.suspect_ip or 'n/a'}",
        )

        out.append(
            FindingInput(
                finding_key=fkey,
                finding_type="attack_chain_case",
                asset_key=asset_key,
                agent_id=agent_id,
                severity=sev,
                score_delta=min(score, 50),
                confidence=72,
                title=f"Active attack chain: {max_stage.replace('_', ' ')}",
                summary=(
                    f"Case {case_id} | Stage: {max_stage} | Score: {score} | "
                    f"Steps: {r.step_count or 0} | Suspect IP: {r.suspect_ip or 'n/a'}"
                ),
                status="open",
                first_seen_at=r.first_seen_at or now,
                last_seen_at=r.last_seen_at or now,
                related_node_keys=[make_node_key(NODE_TYPE_ATTACK_CHAIN_CASE, case_id)],
                evidence_refs=[ref],
                reason_codes=[RC_ATTACK_CHAIN_PROGRESSION],
                extra_data={"suspect_ip": r.suspect_ip},
            )
        )

    return out


def build_event_findings_from_signals(
    signals: EventSignals,
    *,
    asset_key: str,
    now: datetime,
) -> list[FindingInput]:
    out: list[FindingInput] = []
    agent_id = signals.agent_id or None

    if signals.ssh_fail_count >= 5:
        fkey = make_finding_key("event", asset_key, f"ssh_bruteforce:{signals.agent_id}")
        out.append(
            FindingInput(
                finding_key=fkey,
                finding_type="event",
                asset_key=asset_key,
                agent_id=agent_id,
                severity="high" if signals.ssh_fail_count >= 10 else "medium",
                score_delta=min(24, 10 + signals.ssh_fail_count),
                confidence=72,
                title="Repeated SSH authentication failures",
                summary=(
                    f"Observed {signals.ssh_fail_count} failed SSH authentication attempts. "
                    "Review the source IPs and validate access controls."
                ),
                status="open",
                first_seen_at=now,
                last_seen_at=now,
                reason_codes=[RC_BRUTE_FORCE_ACTIVITY],
            )
        )

    if signals.fim_count > 0:
        fkey = make_finding_key("fim", asset_key, f"fim:{signals.agent_id}:sensitive")
        out.append(
            FindingInput(
                finding_key=fkey,
                finding_type="fim",
                asset_key=asset_key,
                agent_id=agent_id,
                severity="high",
                score_delta=14,
                confidence=74,
                title="Sensitive file modification detected",
                summary="A security-relevant file was modified. Review the change and verify it was authorized.",
                status="open",
                first_seen_at=now,
                last_seen_at=now,
                reason_codes=[RC_SENSITIVE_FILE_CHANGE],
            )
        )

    if signals.persistence_count > 0:
        fkey = make_finding_key("persistence", asset_key, f"persistence:{signals.agent_id}")
        out.append(
            FindingInput(
                finding_key=fkey,
                finding_type="fim",
                asset_key=asset_key,
                agent_id=agent_id,
                severity="high",
                score_delta=18,
                confidence=72,
                title="Persistence mechanism detected",
                summary="A systemd unit, cron job, or SSH key change was observed. Verify legitimacy.",
                status="open",
                first_seen_at=now,
                last_seen_at=now,
                reason_codes=[RC_PERSISTENCE_SIGNAL],
            )
        )

    if signals.suspicious_proc_count > 0:
        fkey = make_finding_key("proc_exec", asset_key, f"proc:{signals.agent_id}:suspicious")
        out.append(
            FindingInput(
                finding_key=fkey,
                finding_type="process_exec",
                asset_key=asset_key,
                agent_id=agent_id,
                severity="medium",
                score_delta=8,
                confidence=70,
                title="Suspicious process execution",
                summary=(
                    "A process with characteristics associated with exploitation "
                    "or post-exploitation was executed."
                ),
                status="open",
                first_seen_at=now,
                last_seen_at=now,
                reason_codes=[RC_SUSPICIOUS_PROCESS],
            )
        )

    if signals.lateral_movement_count > 0:
        fkey = make_finding_key("lateral_movement", asset_key, f"lateral:{signals.agent_id}")
        out.append(
            FindingInput(
                finding_key=fkey,
                finding_type="alert",
                asset_key=asset_key,
                agent_id=agent_id,
                severity="high",
                score_delta=20,
                confidence=65,
                title="Lateral movement signal",
                summary="Outbound signals consistent with C2 or data exfiltration were detected.",
                status="open",
                first_seen_at=now,
                last_seen_at=now,
                reason_codes=[RC_LATERAL_MOVEMENT_SIGNAL],
            )
        )

    return out


# Investigation context


def load_investigation_context(
    db: Session,
    *,
    agent_id: str,
    max_investigations: int = 5,
) -> list[dict[str, Any]]:
    rows = investigations_public.list_open_workspaces_for_agent(db, agent_id=agent_id, limit=max_investigations)
    return [
        {
            "id": r.id,
            "workspace_key": r.workspace_key,
            "title": r.title,
            "status": r.status,
            "severity": r.severity,
            "linked_attack_chain_case_id": r.linked_attack_chain_case_id,
            "updated_at": r.updated_at,
        }
        for r in rows
    ]


def load_investigation_evidence_refs(
    db: Session,
    *,
    agent_id: str,
    max_refs: int = 8,
) -> list[EvidenceRef]:
    rows = investigations_public.list_evidence_bookmarks_for_agent(db, agent_id=agent_id, limit=max_refs)
    refs: list[EvidenceRef] = []
    for row in rows:
        refs.append(
            build_evidence_ref(
                source_type=EVIDENCE_SOURCE_INVESTIGATION,
                source_id=str(row.ref_id or row.id),
                observed_at=row.observed_at,
                title=str(row.title or f"Investigation evidence {row.id}"),
                summary=str(row.summary or row.evidence_type or "Investigation bookmark"),
                metadata={"workspace_id": row.workspace_id, "evidence_type": row.evidence_type},
            )
        )
    return refs


def load_response_action_context(
    db: Session,
    *,
    agent_id: str,
    max_actions: int = 5,
) -> list[ResponseActionContext]:
    summaries = response_public.list_recent_action_contexts_for_agent(
        db,
        agent_id=agent_id,
        max_actions=max_actions,
    )
    return [
        ResponseActionContext(
            action_id=summary.action_id,
            action_type=summary.action_type,
            status=summary.status,
            requested_at=summary.requested_at,
            result_status=summary.result_status,
        )
        for summary in summaries
    ]


def build_investigation_nodes_and_edges(
    investigations: list[dict[str, Any]],
    *,
    asset_key: str,
    agent_id: str,
    asset_node_key: str,
    now: datetime,
) -> tuple[list[NodeInput], list[EdgeInput]]:
    nodes: list[NodeInput] = []
    edges: list[EdgeInput] = []

    for inv in investigations:
        inv_id = str(inv.get("id") or "")
        if not inv_id:
            continue
        node_key = make_node_key(NODE_TYPE_INVESTIGATION, inv_id)
        sev = normalize_severity(inv.get("severity"))
        updated_at = inv.get("updated_at") or now

        nodes.append(
            NodeInput(
                node_key=node_key,
                node_type=NODE_TYPE_INVESTIGATION,
                label=str(inv.get("title") or f"Investigation {inv_id}")[:256],
                severity=sev,
                risk_score=_sev_to_score(sev),
                confidence=60,
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=updated_at,
                last_seen_at=updated_at,
                properties={"workspace_key": inv.get("workspace_key"), "status": inv.get("status")},
            )
        )
        edge_key = make_edge_key(asset_node_key, node_key, EDGE_TYPE_PART_OF_INVESTIGATION)
        edges.append(
            EdgeInput(
                edge_key=edge_key,
                source_node_key=asset_node_key,
                target_node_key=node_key,
                edge_type=EDGE_TYPE_PART_OF_INVESTIGATION,
                weight=0.8,
                confidence=60,
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=updated_at,
                last_seen_at=updated_at,
            )
        )

    return nodes, edges


def build_response_action_nodes_and_edges(
    actions: list[ResponseActionContext],
    *,
    asset_key: str,
    agent_id: str,
    asset_node_key: str,
    now: datetime,
) -> tuple[list[NodeInput], list[EdgeInput], list[EvidenceRef]]:
    nodes: list[NodeInput] = []
    edges: list[EdgeInput] = []
    refs: list[EvidenceRef] = []

    for action in actions:
        requested_at = action.requested_at or now
        node_key = make_node_key(NODE_TYPE_RESPONSE_ACTION, str(action.action_id))
        status = str(action.status or "").lower()
        severity = "medium" if status in {"pending", "delivered", "running"} else "informational"
        nodes.append(
            NodeInput(
                node_key=node_key,
                node_type=NODE_TYPE_RESPONSE_ACTION,
                label=f"{action.action_type} [{status or 'unknown'}]"[:256],
                severity=severity,
                risk_score=15 if severity == "medium" else 0,
                confidence=60,
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=requested_at,
                last_seen_at=requested_at,
                properties={
                    "action_type": action.action_type,
                    "status": action.status,
                    "result_status": action.result_status,
                },
            )
        )
        edges.append(
            EdgeInput(
                edge_key=make_edge_key(asset_node_key, node_key, EDGE_TYPE_TRIGGERED_RESPONSE_ACTION),
                source_node_key=asset_node_key,
                target_node_key=node_key,
                edge_type=EDGE_TYPE_TRIGGERED_RESPONSE_ACTION,
                weight=0.4,
                confidence=60,
                asset_key=asset_key,
                agent_id=agent_id,
                first_seen_at=requested_at,
                last_seen_at=requested_at,
            )
        )
        refs.append(
            build_evidence_ref(
                source_type=EVIDENCE_SOURCE_RESPONSE_ACTION,
                source_id=str(action.action_id),
                observed_at=requested_at,
                title=f"Response action: {action.action_type}",
                summary=f"Status: {action.status}, result: {action.result_status or 'n/a'}",
                metadata={"action_type": action.action_type},
            )
        )

    return nodes, edges, refs


def build_event_nodes_and_edges(
    event_rows: list[dict[str, Any]],
    *,
    asset_key: str,
    agent_id: str,
    asset_node_key: str,
    now: datetime,
    max_nodes: int,
    max_edges: int,
) -> tuple[list[NodeInput], list[EdgeInput], EventSignals, list[EvidenceRef]]:
    nodes: dict[str, NodeInput] = {}
    edges: dict[str, EdgeInput] = {}
    refs: list[EvidenceRef] = []
    signals = EventSignals(agent_id=agent_id)

    def add_node(node: NodeInput) -> None:
        existing = nodes.get(node.node_key)
        if existing is None or (node.risk_score, node.last_seen_at) > (existing.risk_score, existing.last_seen_at):
            nodes[node.node_key] = node

    def add_edge(edge: EdgeInput) -> None:
        existing = edges.get(edge.edge_key)
        if existing is None or (edge.confidence, edge.last_seen_at) > (existing.confidence, existing.last_seen_at):
            edges[edge.edge_key] = edge

    for row in event_rows:
        ts = row.get("timestamp") or now
        sig = project_event_signals(row)
        if sig is not None:
            signals.ssh_fail_count += sig.ssh_fail_count
            signals.fim_count += sig.fim_count
            signals.persistence_count += sig.persistence_count
            signals.suspicious_proc_count += sig.suspicious_proc_count
            signals.lateral_movement_count += sig.lateral_movement_count
            if len(refs) < _MAX_EVIDENCE_REFS_PER_FINDING:
                refs.append(
                    build_evidence_ref(
                        source_type=EVIDENCE_SOURCE_EVENT,
                        source_id=str(row.get("id") or ""),
                        observed_at=ts,
                        title=str(row.get("event_type") or "event"),
                        summary=str(
                            row.get("heuristic_name") or row.get("proc_name") or row.get("fim_path") or ""
                        ).strip(),
                    )
                )

        src_ip = str(row.get("src_ip") or "").strip()
        if src_ip:
            node_key = make_asset_scoped_node_key(NODE_TYPE_IP, asset_key, src_ip)
            add_node(
                NodeInput(
                    node_key=node_key,
                    node_type=NODE_TYPE_IP,
                    label=src_ip,
                    severity="high" if sig and sig.lateral_movement_count > 0 else "informational",
                    risk_score=45 if sig and sig.lateral_movement_count > 0 else 12,
                    confidence=70,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                    properties={"direction": "inbound", "source": "event"},
                )
            )
            add_edge(
                EdgeInput(
                    edge_key=make_edge_key(node_key, asset_node_key, EDGE_TYPE_COMMUNICATES_WITH),
                    source_node_key=node_key,
                    target_node_key=asset_node_key,
                    edge_type=EDGE_TYPE_COMMUNICATES_WITH,
                    weight=1.0,
                    confidence=68,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                    properties={"direction": "inbound"},
                )
            )

        dst_ip = str(row.get("dst_ip") or "").strip()
        proto = str(row.get("proto") or row.get("app_proto") or "").strip().lower()
        dst_port = row.get("dst_port")
        if dst_ip or dst_port or proto:
            is_sensitive_service = proto in {"ssh", "rdp", "smb"} or int(dst_port or 0) in {22, 3389, 445}
            service_identifier = ":".join(
                [
                    dst_ip or "remote",
                    str(dst_port or "0"),
                    proto or "unknown",
                ]
            )
            service_key = make_asset_scoped_node_key(NODE_TYPE_SERVICE, asset_key, service_identifier)
            add_node(
                NodeInput(
                    node_key=service_key,
                    node_type=NODE_TYPE_SERVICE,
                    label=f"{dst_ip or 'remote'}:{dst_port or '?'} {proto or ''}".strip(),
                    severity="medium" if is_sensitive_service else "informational",
                    risk_score=26 if is_sensitive_service else 10,
                    confidence=64,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                    properties={"dst_ip": dst_ip, "dst_port": dst_port, "proto": proto, "source": "event"},
                )
            )
            add_edge(
                EdgeInput(
                    edge_key=make_edge_key(asset_node_key, service_key, EDGE_TYPE_COMMUNICATES_WITH),
                    source_node_key=asset_node_key,
                    target_node_key=service_key,
                    edge_type=EDGE_TYPE_COMMUNICATES_WITH,
                    weight=0.7,
                    confidence=64,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                    properties={"direction": "outbound"},
                )
            )
        else:
            service_key = None

        if proto:
            proto_key = make_asset_scoped_node_key(NODE_TYPE_PROTOCOL, asset_key, proto)
            add_node(
                NodeInput(
                    node_key=proto_key,
                    node_type=NODE_TYPE_PROTOCOL,
                    label=proto.upper(),
                    severity="informational",
                    risk_score=0,
                    confidence=60,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                    properties={"protocol": proto},
                )
            )
            add_edge(
                EdgeInput(
                    edge_key=make_edge_key(asset_node_key, proto_key, EDGE_TYPE_COMMUNICATES_WITH),
                    source_node_key=asset_node_key,
                    target_node_key=proto_key,
                    edge_type=EDGE_TYPE_COMMUNICATES_WITH,
                    weight=0.3,
                    confidence=60,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                )
            )

        for identity_type, raw_value in (
            ("dns_qname", row.get("dns_qname")),
            ("http_host", row.get("http_host")),
            ("tls_sni", row.get("tls_sni")),
            ("ja3", row.get("ja3")),
            ("ja4", row.get("ja4")),
        ):
            value = str(raw_value or "").strip()
            if not value:
                continue
            ident_key = make_asset_scoped_node_key(NODE_TYPE_IDENTITY, asset_key, f"{identity_type}:{value.lower()}")
            add_node(
                NodeInput(
                    node_key=ident_key,
                    node_type=NODE_TYPE_IDENTITY,
                    label=value[:256],
                    severity="informational",
                    risk_score=0,
                    confidence=62,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                    properties={"identity_type": identity_type},
                )
            )
            add_edge(
                EdgeInput(
                    edge_key=make_edge_key(service_key or asset_node_key, ident_key, EDGE_TYPE_COMMUNICATES_WITH),
                    source_node_key=service_key or asset_node_key,
                    target_node_key=ident_key,
                    edge_type=EDGE_TYPE_COMMUNICATES_WITH,
                    weight=0.4,
                    confidence=62,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                )
            )

        proc_name = str(row.get("proc_name") or row.get("proc_exe") or "").strip()
        if proc_name:
            proc_key = make_asset_scoped_node_key(NODE_TYPE_PROCESS, asset_key, proc_name.lower())
            suspicious = bool(sig and sig.suspicious_proc_count > 0)
            add_node(
                NodeInput(
                    node_key=proc_key,
                    node_type=NODE_TYPE_PROCESS,
                    label=proc_name[:256],
                    severity="medium" if suspicious else "informational",
                    risk_score=35 if suspicious else 6,
                    confidence=68,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                    properties={
                        "proc_exe": row.get("proc_exe"),
                        "proc_parent_name": row.get("proc_parent_name"),
                    },
                )
            )
            add_edge(
                EdgeInput(
                    edge_key=make_edge_key(asset_node_key, proc_key, EDGE_TYPE_EXECUTED_PROCESS),
                    source_node_key=asset_node_key,
                    target_node_key=proc_key,
                    edge_type=EDGE_TYPE_EXECUTED_PROCESS,
                    weight=1.0,
                    confidence=68,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                )
            )

        fim_path = str(row.get("fim_path") or "").strip()
        if fim_path:
            file_key = make_asset_scoped_node_key(NODE_TYPE_FILE, asset_key, fim_path)
            sensitive = bool(sig and (sig.fim_count > 0 or sig.persistence_count > 0))
            add_node(
                NodeInput(
                    node_key=file_key,
                    node_type=NODE_TYPE_FILE,
                    label=fim_path[:256],
                    severity="high" if sensitive else "informational",
                    risk_score=45 if sensitive else 8,
                    confidence=74 if sensitive else 60,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                    properties={"fim_category": row.get("fim_category")},
                )
            )
            add_edge(
                EdgeInput(
                    edge_key=make_edge_key(asset_node_key, file_key, EDGE_TYPE_MODIFIED_FILE),
                    source_node_key=asset_node_key,
                    target_node_key=file_key,
                    edge_type=EDGE_TYPE_MODIFIED_FILE,
                    weight=1.0,
                    confidence=74 if sensitive else 60,
                    asset_key=asset_key,
                    agent_id=agent_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                )
            )

    ordered_nodes = sorted(
        nodes.values(),
        key=lambda row: (row.risk_score, row.confidence, dt_key(row.last_seen_at)),
        reverse=True,
    )
    selected_nodes = ordered_nodes[:max_nodes]
    selected_node_keys = {row.node_key for row in selected_nodes}
    ordered_edges = [
        row for row in sorted(
            edges.values(),
            key=lambda edge: (edge.confidence, edge.weight, dt_key(edge.last_seen_at)),
            reverse=True,
        )
        if row.source_node_key in selected_node_keys and row.target_node_key in selected_node_keys | {asset_node_key}
    ]
    selected_edges = ordered_edges[:max_edges]
    return selected_nodes, selected_edges, signals, merge_evidence_refs([], refs)


def sync_asset_graph(
    db: Session,
    *,
    asset_key: str,
    keep_node_keys: set[str],
    keep_edge_keys: set[str],
) -> None:
    from app.features.exposure.models import ExposureEdgeModel, ExposureNodeModel  # noqa: PLC0415

    node_stmt = select(ExposureNodeModel).where(ExposureNodeModel.asset_key == asset_key)
    for row in db.execute(node_stmt).scalars().all():
        if row.node_key not in keep_node_keys:
            db.delete(row)

    edge_stmt = select(ExposureEdgeModel).where(ExposureEdgeModel.asset_key == asset_key)
    for row in db.execute(edge_stmt).scalars().all():
        if row.edge_key not in keep_edge_keys:
            db.delete(row)


def resolve_inactive_findings(
    db: Session,
    *,
    asset_key: str,
    active_finding_keys: set[str],
    now: datetime,
) -> None:
    from app.features.exposure.models import ExposureFindingModel  # noqa: PLC0415

    stmt = (
        update(ExposureFindingModel)
        .where(
            ExposureFindingModel.asset_key == asset_key,
            ExposureFindingModel.status == "open",
            ~ExposureFindingModel.finding_key.in_(list(active_finding_keys or ["__none__"])),
        )
        .values(status="resolved", updated_at=now)
    )
    db.execute(stmt)


# Score history throttle


_last_history_write: dict[str, datetime] = {}


def should_write_score_history(
    db: Session,
    *,
    asset_key: str,
    now: datetime,
    min_interval_seconds: int,
) -> bool:
    cached = _last_history_write.get(asset_key)
    if cached is not None:
        return (now - cached).total_seconds() >= min_interval_seconds

    # On first access, query the DB to get the last write time.
    from app.features.exposure.models import ExposureScoreHistoryModel  # noqa: PLC0415

    stmt = select(func.max(ExposureScoreHistoryModel.bucket_ts)).where(
        ExposureScoreHistoryModel.asset_key == asset_key,
        ExposureScoreHistoryModel.bucket_ts > (now - timedelta(seconds=min_interval_seconds * 2)),
    )
    last_ts = db.execute(stmt).scalar()
    if last_ts is not None:
        last_ts = ensure_utc(last_ts)
    _last_history_write[asset_key] = last_ts or datetime.min.replace(tzinfo=timezone.utc)
    if last_ts is None:
        return True
    return (now - last_ts).total_seconds() >= min_interval_seconds


def mark_history_written(asset_key: str, ts: datetime) -> None:
    _last_history_write[asset_key] = ts


def clear_history_cache() -> None:
    _last_history_write.clear()


# Vulnerable package name extraction


def extract_vulnerable_pkg_names(
    db: Session,
    *,
    asset_key: str,
    lookback_dt: datetime,
) -> frozenset[str]:
    rows = vuln_public.list_finding_locations_for_asset(
        db, asset_key=asset_key, lookback=lookback_dt, limit=500
    )
    names: set[str] = set()
    for loc in rows:
        name = extract_package_name_from_location(loc)
        if name:
            names.add(name)
    return frozenset(names)


# Helpers


def make_asset_scoped_node_key(node_type: str, asset_key: str, identifier: str) -> str:
    return make_node_key(node_type, f"{asset_key}:{identifier}")


def ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def dt_key(dt: datetime | None) -> float:
    safe = ensure_utc(dt) if dt is not None else datetime.min.replace(tzinfo=timezone.utc)
    return safe.timestamp()


def extract_package_name_from_location(location: Any) -> str | None:
    raw = str(location or "").strip()
    if not raw:
        return None
    candidates = re.split(r"[\\/]", raw)
    for candidate in reversed(candidates):
        token = candidate.split(":")[0].split("@")[0].strip().lower()
        if token and token not in {"usr", "lib", "bin", "opt", "var", "tmp"}:
            return token
    return None


def _attack_chain_step_source_refs(step: attack_chain_public.AttackChainStepGraphSummary) -> list[dict[str, Any]]:
    event_id = step.event_id
    if not event_id:
        return []
    ref = build_evidence_ref(
        source_type=EVIDENCE_SOURCE_ATTACK_CHAIN_STEP,
        source_id=str(step.id),
        observed_at=step.timestamp,
        title=str(step.label or step.stage or f"Step {step.id}"),
        summary=f"Event {event_id} ({step.event_type or 'unknown'})",
        metadata={"event_id": event_id},
    )
    return [ref.to_dict()]


def bucket_score_history_ts(now: datetime, interval_seconds: int) -> datetime:
    interval_seconds = max(1, int(interval_seconds))
    ts = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    bucket = int(ts.timestamp()) // interval_seconds * interval_seconds
    return datetime.fromtimestamp(bucket, tz=timezone.utc)


def _sev_to_score(sev: str) -> int:
    return {
        "critical": 90,
        "high": 70,
        "medium": 50,
        "low": 25,
        "informational": 10,
        "unknown": 0,
    }.get(sev, 0)


def _sev_rank(sev: str) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1,
        "unknown": 0,
    }.get(sev, 0)


def _alert_score_delta(sev: str, kind: str) -> int:
    base = {"critical": 25, "high": 15, "medium": 8, "low": 3, "informational": 1, "unknown": 2}.get(sev, 2)
    if kind == "lateral_movement":
        base = int(base * 1.4)
    elif kind == "brute_force":
        base = int(base * 1.2)
    return min(base, 40)


def _vuln_reason_codes(severity_rank: int) -> list[str]:
    codes = [RC_VULNERABLE_PACKAGE]
    if severity_rank >= 5:
        codes.append(RC_CRITICAL_CVE)
    if severity_rank >= 4:
        codes.append(RC_EXPLOITABILITY_SIGNAL)
    return codes


def _alert_reason_codes(kind: str) -> list[str]:
    mapping: dict[str, list[str]] = {
        "lateral_movement": [RC_LATERAL_MOVEMENT_SIGNAL, RC_ACTIVE_ALERT],
        "brute_force": [RC_BRUTE_FORCE_ACTIVITY, RC_ACTIVE_ALERT],
        "persistence": [RC_PERSISTENCE_SIGNAL, RC_ACTIVE_ALERT],
        "suspicious_process": [RC_SUSPICIOUS_PROCESS, RC_ACTIVE_ALERT],
    }
    return mapping.get(kind, [RC_ACTIVE_ALERT])
