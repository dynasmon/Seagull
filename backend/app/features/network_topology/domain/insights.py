from __future__ import annotations

from typing import Any

from app.features.network_topology.domain.serializers import _to_utc
from app.features.network_topology.schemas import TopologyInsightOut, TopologyVisibilityOut


def _compute_insights(
    insight_metrics: dict[str, Any],
    *,
    window_minutes: int,
) -> list[TopologyInsightOut]:
    window_label = f"{window_minutes // 60}h" if window_minutes >= 60 else f"{window_minutes}m"
    insights: list[TopologyInsightOut] = []

    nodes_with_alerts = int(insight_metrics.get("nodes_with_alerts", 0))
    if nodes_with_alerts > 0:
        insights.append(TopologyInsightOut(
            id="nodes_with_alerts",
            group="needs_attention",
            severity="high" if nodes_with_alerts >= 5 else "medium",
            title=f"{nodes_with_alerts} host{'s' if nodes_with_alerts != 1 else ''} with active alerts",
            detail="These hosts appear in security alerts. Open the alert queue to review and triage them.",
            count=nodes_with_alerts,
        ))

    nodes_with_exposure = int(insight_metrics.get("nodes_with_exposure_findings", 0))
    if nodes_with_exposure > 0:
        insights.append(TopologyInsightOut(
            id="nodes_with_exposure_findings",
            group="needs_attention",
            severity="high" if nodes_with_exposure >= 3 else "medium",
            title=f"{nodes_with_exposure} host{'s' if nodes_with_exposure != 1 else ''} with exposure findings",
            detail="These hosts are linked to open exposure findings. Review the Exposure panel for remediation steps.",
            count=nodes_with_exposure,
        ))

    exposed_services = int(insight_metrics.get("exposed_services", 0))
    if exposed_services > 0:
        insights.append(TopologyInsightOut(
            id="exposed_services",
            group="needs_attention",
            severity="high",
            title=f"{exposed_services} service{'s' if exposed_services != 1 else ''} with alert activity",
            detail="Services observed with alert evidence. Verify that these ports and protocols are expected.",
            count=exposed_services,
        ))

    high_risk_edges = int(insight_metrics.get("high_risk_edges", 0))
    if high_risk_edges > 0:
        insights.append(TopologyInsightOut(
            id="high_risk_flows",
            group="needs_attention",
            severity="high" if high_risk_edges >= 10 else "medium",
            title=f"{high_risk_edges} high-risk network relationship{'s' if high_risk_edges != 1 else ''}",
            detail="Connections classified as high or critical severity from alert or exposure evidence.",
            count=high_risk_edges,
        ))

    public_to_internal = int(insight_metrics.get("public_to_internal", 0))
    if public_to_internal > 0:
        insights.append(TopologyInsightOut(
            id="public_to_internal",
            group="needs_attention",
            severity="medium",
            title=f"{public_to_internal} inbound flow{'s' if public_to_internal != 1 else ''} from the public internet",
            detail="Traffic originated from external IPs to internal hosts. Confirm these are expected entry points.",
            count=public_to_internal,
        ))

    stale_agents = int(insight_metrics.get("stale_agents", 0))
    if stale_agents > 0:
        insights.append(TopologyInsightOut(
            id="stale_agents",
            group="needs_attention",
            severity="medium",
            title=f"{stale_agents} agent{'s' if stale_agents != 1 else ''} marked stale",
            detail="Agents not recently seen. Their topology segment may be outdated or the agent may be offline.",
            count=stale_agents,
        ))

    new_external_ips = int(insight_metrics.get("new_external_ips", 0))
    if new_external_ips > 0:
        insights.append(TopologyInsightOut(
            id="new_external_ips",
            group="needs_attention",
            severity="medium" if new_external_ips >= 10 else "low",
            title=f"{new_external_ips} new external IP{'s' if new_external_ips != 1 else ''} in the last {window_label}",
            detail="Public endpoints first observed in this window. Review for unexpected external contact.",
            count=new_external_ips,
        ))

    internal_to_internal = int(insight_metrics.get("internal_to_internal", 0))
    if internal_to_internal > 0:
        insights.append(TopologyInsightOut(
            id="internal_flows",
            group="normal_activity",
            severity="ok",
            title=f"{internal_to_internal} internal-to-internal flow{'s' if internal_to_internal != 1 else ''}",
            detail="Observed connections between internal hosts. Normal for most enterprise and server traffic.",
            count=internal_to_internal,
        ))

    internal_to_public = int(insight_metrics.get("internal_to_public", 0))
    if internal_to_public > 0:
        insights.append(TopologyInsightOut(
            id="outbound_flows",
            group="normal_activity",
            severity="ok",
            title=f"{internal_to_public} outbound connection{'s' if internal_to_public != 1 else ''} to public internet",
            detail="Internal hosts contacting external IPs. Review if unfamiliar destinations appear in the topology.",
            count=internal_to_public,
        ))

    new_internal_hosts = int(insight_metrics.get("new_internal_hosts", 0))
    if new_internal_hosts > 0:
        insights.append(TopologyInsightOut(
            id="new_internal_hosts",
            group="normal_activity",
            severity="info",
            title=f"{new_internal_hosts} new internal host{'s' if new_internal_hosts != 1 else ''} in the last {window_label}",
            detail="Hosts first seen in this window, from agent inventory or observed traffic.",
            count=new_internal_hosts,
        ))

    noisy_nodes = int(insight_metrics.get("noisy_nodes", 0))
    if noisy_nodes > 0:
        insights.append(TopologyInsightOut(
            id="noisy_nodes",
            group="normal_activity",
            severity="info",
            title=f"{noisy_nodes} high-traffic node{'s' if noisy_nodes != 1 else ''}",
            detail="Nodes with 500+ observed events. Likely gateways, DNS resolvers, or heavily-used servers.",
            count=noisy_nodes,
        ))

    if not any(i.group in ("normal_activity", "needs_attention") for i in insights):
        insights.append(TopologyInsightOut(
            id="no_activity",
            group="normal_activity",
            severity="ok",
            title="No recent network activity detected",
            detail="No flows, alerts, or topology changes found in the current window. This may indicate no agent coverage or a quiet period.",
            count=0,
        ))

    stale_other = int(insight_metrics.get("stale_other", 0))
    if stale_other > 0:
        insights.append(TopologyInsightOut(
            id="stale_topology_segments",
            group="visibility_gaps",
            severity="low",
            title=f"{stale_other} stale topology node{'s' if stale_other != 1 else ''}",
            detail="Non-agent nodes (hosts, interfaces, services) that have not been refreshed. Their data may be outdated.",
            count=stale_other,
        ))

    isolated_nodes = int(insight_metrics.get("isolated_nodes", 0))
    if isolated_nodes > 0:
        insights.append(TopologyInsightOut(
            id="isolated_nodes",
            group="visibility_gaps",
            severity="info",
            title=f"{isolated_nodes} isolated node{'s' if isolated_nodes != 1 else ''} with no connections",
            detail="Nodes discovered from inventory or alerts but with no observed flows or topology edges. They may represent agents or hosts with incomplete coverage.",
            count=isolated_nodes,
        ))

    docker_count = int(insight_metrics.get("docker_node_count", 0))
    if docker_count > 0:
        insights.append(TopologyInsightOut(
            id="docker_context",
            group="visibility_gaps",
            severity="info",
            title=f"{docker_count} container network address{'es' if docker_count != 1 else ''} detected",
            detail="An agent appears to be running inside Docker and may only observe container-local traffic, not the host network.",
            count=docker_count,
        ))

    flow_edge_count = int(insight_metrics.get("flow_edge_count", 0))
    if flow_edge_count == 0:
        insights.append(TopologyInsightOut(
            id="no_flow_data",
            group="visibility_gaps",
            severity="medium",
            title="No network flow data available",
            detail="Flow-based topology and connection insights are unavailable. Ensure agents are collecting network events.",
            count=0,
        ))

    insights.append(TopologyInsightOut(
        id="no_physical_topology",
        group="visibility_gaps",
        severity="info",
        title="Physical switch topology not available",
        detail="Seagull derives connectivity from traffic observations. SNMP, LLDP, CDP, and MAC table data are not collected.",
    ))

    insights.append(TopologyInsightOut(
        id="no_vlan_info",
        group="visibility_gaps",
        severity="info",
        title="VLAN segmentation is unknown",
        detail="VLAN boundaries cannot be determined from agent telemetry alone. Network segmentation may differ from what is shown.",
    ))

    return insights

def _compute_visibility(
    *,
    insight_metrics: dict[str, Any],
    coverage: dict[str, Any],
    alert_edge_count: int,
    exposure_edge_count: int,
) -> TopologyVisibilityOut:
    agents_projected = int(coverage.get("agents_projected") or 0)
    agents_with_inventory = int(coverage.get("agents_with_inventory") or 0)
    inventory_coverage = round(agents_with_inventory / agents_projected, 2) if agents_projected > 0 else 0.0

    flow_coverage = int(insight_metrics.get("flow_edge_count", 0)) > 0
    services_projected = int(coverage.get("services_projected") or 0)
    protocol_coverage = flow_coverage and services_projected > 0

    limitations: list[str] = [
        "Physical switch topology is unavailable: connectivity is derived from traffic and inventory, not hardware discovery.",
        "VLAN segmentation is unknown unless explicitly configured in agent settings.",
        "MAC address tables are not accessible: Layer 2 topology cannot be mapped.",
        "SNMP, LLDP, and CDP data are not collected: network device topology cannot be confirmed.",
    ]

    docker_count = int(insight_metrics.get("docker_node_count", 0))
    if docker_count > 0:
        limitations.append(
            f"{docker_count} Docker/container network address{'es' if docker_count != 1 else ''} detected: "
            "the agent may be running inside a container and may only observe container-local traffic."
        )

    if agents_projected > 0 and inventory_coverage < 0.5:
        limitations.append(
            f"Inventory data is partial: only {int(inventory_coverage * 100)}% of agents reported host inventory. "
            "Host discovery may be incomplete."
        )

    if not flow_coverage:
        limitations.append(
            "No network flow data is available. Flow-based topology, connection insights, and service detection are inactive."
        )

    last_flow_at = insight_metrics.get("last_flow_at")
    last_alert_at = insight_metrics.get("last_alert_at")
    last_inventory_at = insight_metrics.get("last_inventory_at")

    return TopologyVisibilityOut(
        inventory_coverage=inventory_coverage,
        flow_coverage=flow_coverage,
        alert_coverage=alert_edge_count > 0,
        protocol_coverage=protocol_coverage,
        exposure_coverage=exposure_edge_count > 0,
        last_inventory_at=_to_utc(last_inventory_at) if last_inventory_at else None,
        last_event_at=_to_utc(last_flow_at) if last_flow_at else None,
        last_alert_at=_to_utc(last_alert_at) if last_alert_at else None,
        known_limitations=limitations,
    )
