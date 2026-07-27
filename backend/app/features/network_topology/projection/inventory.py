from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.features.agents import public as agents_public
from app.features.inventory import public as inventory_public
from app.features.network_topology import repository
from app.features.network_topology.classification import classify_topology_ip, infer_subnet_cidr
from app.features.network_topology.projection.helpers import (
    _edge_key,
    _ip_node_key,
    _is_stale_agent,
    _is_valid_ip,
    _matching_interface_network_cidr,
    _network_from_iface_cidrs,
    _node_key,
    _to_utc,
)
from app.features.network_topology.schemas import TopologyCoverageOut

_MAX_AGENT_ROWS = 500


def _project_agents(
    db: Session,
    *,
    now: datetime,
    coverage: TopologyCoverageOut,
) -> dict[str, str]:
    agents = agents_public.list_active_agents_for_projection(db, limit=_MAX_AGENT_ROWS)
    coverage.agents_projected = len(agents)

    agent_nodes: dict[str, str] = {}
    for agent in agents:
        is_stale = _is_stale_agent(agent.last_seen_at, now)
        node_key = _node_key("agent", agent.agent_id)
        last_seen = _to_utc(agent.last_seen_at) or now

        repository.upsert_node(
            db,
            node_key=node_key,
            node_type="agent",
            label=str(agent.display_name or agent.agent_id),
            agent_id=agent.agent_id,
            ip=None,
            cidr=None,
            port=None,
            protocol=None,
            severity="unknown",
            risk_score=0,
            confidence=95,
            first_seen_at=_to_utc(agent.created_at) or now,
            last_seen_at=last_seen,
            extra_data={"is_stale_agent": is_stale, "is_agent_asset": True},
        )
        agent_nodes[agent.agent_id] = node_key

    return agent_nodes

def _project_inventory(
    db: Session,
    *,
    now: datetime,
    cidrs: list[str] | None,
    coverage: TopologyCoverageOut,
    agent_nodes: dict[str, str],
) -> None:
    inventory_rows = inventory_public.list_latest_inventory(db, limit=_MAX_AGENT_ROWS)
    coverage.agents_with_inventory = len(inventory_rows)

    subnet_seen: set[str] = set()

    for inv in inventory_rows:
        agent_id = str(inv.agent_id)
        os_data = inv.os or {}
        hostname = str(os_data.get("hostname") or agent_id)
        last_seen = _to_utc(inv.updated_at) or now
        first_seen = _to_utc(inv.collected_at) or now
        agent_node_key = agent_nodes.get(agent_id)

        extra_data = inv.extra or {}
        netctx = extra_data.get("network_context") or {}
        interfaces: list[dict[str, Any]] = netctx.get("interfaces") or []
        neighbors: list[dict[str, Any]] = netctx.get("neighbors") or []
        routes: list[dict[str, Any]] = netctx.get("routes") or []

        if interfaces:
            _project_network_context_interfaces(
                db,
                agent_id=agent_id,
                hostname=hostname,
                interfaces=interfaces,
                agent_node_key=agent_node_key,
                cidrs=cidrs,
                first_seen=first_seen,
                last_seen=last_seen,
                subnet_seen=subnet_seen,
                coverage=coverage,
            )
            _project_network_context_neighbors_and_routes(
                db,
                agent_id=agent_id,
                interfaces=interfaces,
                neighbors=neighbors,
                routes=routes,
                cidrs=cidrs,
                first_seen=first_seen,
                last_seen=last_seen,
                subnet_seen=subnet_seen,
            )
        else:
            ip_addresses = [
                str(ip).strip()
                for ip in (os_data.get("ip_addresses") or [])
                if str(ip or "").strip()
            ]
            _project_ip_addresses_fallback(
                db,
                agent_id=agent_id,
                hostname=hostname,
                ip_addresses=ip_addresses,
                agent_node_key=agent_node_key,
                cidrs=cidrs,
                first_seen=first_seen,
                last_seen=last_seen,
                subnet_seen=subnet_seen,
                coverage=coverage,
            )

def _project_network_context_neighbors_and_routes(
    db: Session,
    *,
    agent_id: str,
    interfaces: list[dict[str, Any]],
    neighbors: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    cidrs: list[str] | None,
    first_seen: datetime,
    last_seen: datetime,
    subnet_seen: set[str],
) -> None:
    interface_keys = {
        str(iface.get("name") or "unknown"): _node_key("interface", agent_id, str(iface.get("name") or "unknown"))
        for iface in interfaces
    }

    for neighbor in neighbors[:512]:
        ip = str(neighbor.get("ip") or "").strip()
        iface_name = str(neighbor.get("interface") or "").strip()
        if not _is_valid_ip(ip):
            continue

        ip_info = classify_topology_ip(ip, internal_cidrs=cidrs)
        neighbor_key = _ip_node_key(ip, ip_info)
        repository.upsert_node(
            db,
            node_key=neighbor_key,
            node_type=ip_info.get("node_class", "unknown"),
            label=ip,
            agent_id=None,
            ip=ip,
            cidr=None,
            port=None,
            protocol=None,
            severity="unknown",
            risk_score=0,
            confidence=80,
            first_seen_at=first_seen,
            last_seen_at=last_seen,
            extra_data={
                "ip_scope": ip_info.get("scope"),
                "neighbor_state": str(neighbor.get("state") or "").strip() or None,
                "neighbor_mac": str(neighbor.get("mac") or "").strip() or None,
                "observed_by_agent_id": agent_id,
            },
        )

        iface_key = interface_keys.get(iface_name)
        if iface_key:
            repository.upsert_edge(
                db,
                edge_key=_edge_key("inferred_relationship", iface_key, neighbor_key),
                source_node_key=iface_key,
                target_node_key=neighbor_key,
                edge_type="inferred_relationship",
                agent_id=agent_id,
                weight=0.6,
                confidence=80,
                severity="unknown",
                port=None,
                protocol=None,
                first_seen_at=last_seen,
                last_seen_at=last_seen,
                extra_data={"evidence": "arp_neighbor"},
            )

        neighbor_cidr = _matching_interface_network_cidr(interfaces, ip)
        if neighbor_cidr:
            if neighbor_cidr not in subnet_seen:
                subnet_seen.add(neighbor_cidr)
                repository.upsert_node(
                    db,
                    node_key=_node_key("subnet", neighbor_cidr),
                    node_type="subnet",
                    label=neighbor_cidr,
                    agent_id=None,
                    ip=None,
                    cidr=neighbor_cidr,
                    port=None,
                    protocol=None,
                    severity="unknown",
                    risk_score=0,
                    confidence=75,
                    first_seen_at=last_seen,
                    last_seen_at=last_seen,
                    extra_data={},
                )
            repository.upsert_edge(
                db,
                edge_key=_edge_key("member_of_subnet", neighbor_key, _node_key("subnet", neighbor_cidr)),
                source_node_key=neighbor_key,
                target_node_key=_node_key("subnet", neighbor_cidr),
                edge_type="member_of_subnet",
                agent_id=agent_id,
                weight=0.7,
                confidence=75,
                severity="unknown",
                port=None,
                protocol=None,
                first_seen_at=last_seen,
                last_seen_at=last_seen,
                extra_data={"evidence": "arp_neighbor"},
            )

    for route in routes[:256]:
        gateway = str(route.get("gateway") or "").strip()
        iface_name = str(route.get("interface") or "").strip()
        destination = str(route.get("destination") or "").strip()
        if not _is_valid_ip(gateway) or gateway in {"0.0.0.0", "::"}:
            continue
        iface_key = interface_keys.get(iface_name)
        if not iface_key:
            continue

        gateway_key = _node_key("gateway", gateway)
        gateway_info = classify_topology_ip(gateway, internal_cidrs=cidrs)
        repository.upsert_node(
            db,
            node_key=gateway_key,
            node_type="gateway",
            label=gateway,
            agent_id=None,
            ip=gateway,
            cidr=None,
            port=None,
            protocol=None,
            severity="unknown",
            risk_score=0,
            confidence=80,
            first_seen_at=first_seen,
            last_seen_at=last_seen,
            extra_data={"ip_scope": gateway_info.get("scope"), "observed_by_agent_id": agent_id},
        )
        repository.upsert_edge(
            db,
            edge_key=_edge_key("route_next_hop", iface_key, gateway_key),
            source_node_key=iface_key,
            target_node_key=gateway_key,
            edge_type="route_next_hop",
            agent_id=agent_id,
            weight=0.8,
            confidence=80,
            severity="unknown",
            port=None,
            protocol=None,
            first_seen_at=last_seen,
            last_seen_at=last_seen,
            extra_data={"destination": destination, "family": str(route.get("family") or "").strip()},
        )

def _project_network_context_interfaces(
    db: Session,
    *,
    agent_id: str,
    hostname: str,
    interfaces: list[dict[str, Any]],
    agent_node_key: str | None,
    cidrs: list[str] | None,
    first_seen: datetime,
    last_seen: datetime,
    subnet_seen: set[str],
    coverage: TopologyCoverageOut,
) -> None:
    for iface in interfaces:
        iface_name = str(iface.get("name") or "unknown")
        ips: list[str] = [
            str(ip).strip()
            for ip in (iface.get("ips") or [])
            if str(ip or "").strip()
        ]
        iface_cidrs: list[str] = iface.get("cidrs") or []
        is_loopback = bool(iface.get("is_loopback"))
        is_link_local = bool(iface.get("is_link_local"))

        if not ips:
            continue

        primary_ip = ips[0]
        ip_info = classify_topology_ip(primary_ip, internal_cidrs=cidrs)
        iface_conf = 50 if (is_loopback or is_link_local) else 85

        # Interface node: topo:interface:{agent_id}:{iface_name}
        iface_node_key = _node_key("interface", agent_id, iface_name)
        repository.upsert_node(
            db,
            node_key=iface_node_key,
            node_type="interface",
            label=f"{iface_name} ({primary_ip})",
            agent_id=agent_id,
            ip=primary_ip,
            cidr=None,
            port=None,
            protocol=None,
            severity="unknown",
            risk_score=0,
            confidence=iface_conf,
            first_seen_at=first_seen,
            last_seen_at=last_seen,
            extra_data={
                "interface_name": iface_name,
                "ip_scope": ip_info.get("scope"),
                "node_class": ip_info.get("node_class"),
                "is_loopback": is_loopback,
                "is_link_local": is_link_local,
                "ips": ips[:10],
                "is_agent_asset": True,
            },
        )
        coverage.interfaces_extracted += 1

        # Host node: topo:host:{agent_id}:{primary_ip}
        host_node_key = _node_key("host", agent_id, primary_ip)
        repository.upsert_node(
            db,
            node_key=host_node_key,
            node_type="host",
            label=hostname,
            agent_id=agent_id,
            ip=primary_ip,
            cidr=None,
            port=None,
            protocol=None,
            severity="unknown",
            risk_score=0,
            confidence=90,
            first_seen_at=first_seen,
            last_seen_at=last_seen,
            extra_data={"hostname": hostname, "interface_name": iface_name, "is_agent_asset": True},
        )

        if agent_node_key:
            repository.upsert_edge(
                db,
                edge_key=_edge_key("same_agent", agent_node_key, host_node_key),
                source_node_key=agent_node_key,
                target_node_key=host_node_key,
                edge_type="same_agent",
                agent_id=agent_id,
                weight=1.0,
                confidence=90,
                severity="unknown",
                port=None,
                protocol=None,
                first_seen_at=last_seen,
                last_seen_at=last_seen,
                extra_data={},
            )

        repository.upsert_edge(
            db,
            edge_key=_edge_key("owns_interface", host_node_key, iface_node_key),
            source_node_key=host_node_key,
            target_node_key=iface_node_key,
            edge_type="owns_interface",
            agent_id=agent_id,
            weight=1.0,
            confidence=85,
            severity="unknown",
            port=None,
            protocol=None,
            first_seen_at=last_seen,
            last_seen_at=last_seen,
            extra_data={},
        )

        if is_loopback or is_link_local:
            continue

        # Derive network CIDR from interface CIDR (e.g. "10.0.0.1/24" → "10.0.0.0/24")
        cidr_key = _network_from_iface_cidrs(iface_cidrs, primary_ip)
        if not cidr_key:
            continue

        if cidr_key not in subnet_seen:
            subnet_seen.add(cidr_key)
            coverage.subnets_inferred += 1
            repository.upsert_node(
                db,
                node_key=_node_key("subnet", cidr_key),
                node_type="subnet",
                label=cidr_key,
                agent_id=None,
                ip=None,
                cidr=cidr_key,
                port=None,
                protocol=None,
                severity="unknown",
                risk_score=0,
                confidence=75,
                first_seen_at=last_seen,
                last_seen_at=last_seen,
                extra_data={},
            )

        repository.upsert_edge(
            db,
            edge_key=_edge_key("member_of_subnet", iface_node_key, _node_key("subnet", cidr_key)),
            source_node_key=iface_node_key,
            target_node_key=_node_key("subnet", cidr_key),
            edge_type="member_of_subnet",
            agent_id=agent_id,
            weight=0.8,
            confidence=75,
            severity="unknown",
            port=None,
            protocol=None,
            first_seen_at=last_seen,
            last_seen_at=last_seen,
            extra_data={},
        )

def _project_ip_addresses_fallback(
    db: Session,
    *,
    agent_id: str,
    hostname: str,
    ip_addresses: list[str],
    agent_node_key: str | None,
    cidrs: list[str] | None,
    first_seen: datetime,
    last_seen: datetime,
    subnet_seen: set[str],
    coverage: TopologyCoverageOut,
) -> None:
    host_node_key = _node_key("host", agent_id, hostname)
    repository.upsert_node(
        db,
        node_key=host_node_key,
        node_type="host",
        label=hostname,
        agent_id=agent_id,
        ip=ip_addresses[0] if ip_addresses else None,
        cidr=None,
        port=None,
        protocol=None,
        severity="unknown",
        risk_score=0,
        confidence=85,
        first_seen_at=first_seen,
        last_seen_at=last_seen,
        extra_data={"hostname": hostname, "ip_addresses": ip_addresses[:20], "is_agent_asset": True},
    )

    if agent_node_key:
        repository.upsert_edge(
            db,
            edge_key=_edge_key("same_agent", agent_node_key, host_node_key),
            source_node_key=agent_node_key,
            target_node_key=host_node_key,
            edge_type="same_agent",
            agent_id=agent_id,
            weight=1.0,
            confidence=90,
            severity="unknown",
            port=None,
            protocol=None,
            first_seen_at=last_seen,
            last_seen_at=last_seen,
            extra_data={},
        )

    for ip in ip_addresses[:20]:
        coverage.interfaces_extracted += 1
        ip_info = classify_topology_ip(ip, internal_cidrs=cidrs)
        iface_node_key = _node_key("interface", agent_id, ip)

        repository.upsert_node(
            db,
            node_key=iface_node_key,
            node_type="interface",
            label=ip,
            agent_id=agent_id,
            ip=ip,
            cidr=None,
            port=None,
            protocol=None,
            severity="unknown",
            risk_score=0,
            confidence=75,
            first_seen_at=last_seen,
            last_seen_at=last_seen,
            extra_data={"ip_scope": ip_info.get("scope"), "node_class": ip_info.get("node_class"), "is_agent_asset": True},
        )

        repository.upsert_edge(
            db,
            edge_key=_edge_key("owns_interface", host_node_key, iface_node_key),
            source_node_key=host_node_key,
            target_node_key=iface_node_key,
            edge_type="owns_interface",
            agent_id=agent_id,
            weight=1.0,
            confidence=80,
            severity="unknown",
            port=None,
            protocol=None,
            first_seen_at=last_seen,
            last_seen_at=last_seen,
            extra_data={},
        )

        cidr = infer_subnet_cidr(ip)
        if cidr and cidr not in subnet_seen:
            subnet_seen.add(cidr)
            coverage.subnets_inferred += 1
            repository.upsert_node(
                db,
                node_key=_node_key("subnet", cidr),
                node_type="subnet",
                label=cidr,
                agent_id=None,
                ip=None,
                cidr=cidr,
                port=None,
                protocol=None,
                severity="unknown",
                risk_score=0,
                confidence=70,
                first_seen_at=last_seen,
                last_seen_at=last_seen,
                extra_data={},
            )

        if cidr:
            repository.upsert_edge(
                db,
                edge_key=_edge_key("member_of_subnet", iface_node_key, _node_key("subnet", cidr)),
                source_node_key=iface_node_key,
                target_node_key=_node_key("subnet", cidr),
                edge_type="member_of_subnet",
                agent_id=agent_id,
                weight=0.8,
                confidence=70,
                severity="unknown",
                port=None,
                protocol=None,
                first_seen_at=last_seen,
                last_seen_at=last_seen,
                extra_data={},
            )
