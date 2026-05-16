import type {
  TopologyEdgeType,
  TopologyGraph,
  TopologyGroup,
  TopologyGroupEdge,
  TopologyNode,
  TopologySeverity,
} from "../types";

function severityWeight(sev: string): number {
  const MAP: Record<string, number> = {
    critical: 5, high: 4, medium: 3, low: 2, informational: 1, unknown: 0,
  };
  return MAP[String(sev ?? "").toLowerCase()] ?? 0;
}

function highestSeverity(nodes: TopologyNode[]): TopologySeverity {
  const sorted = [...nodes].sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity));
  return (sorted[0]?.severity as TopologySeverity) ?? "unknown";
}

const SCOPE_LABELS: Record<string, string> = {
  public_internet:  "Public Internet",
  internal_network: "Internal Network",
  private_address:  "Private Network",
  loopback:         "Loopback",
  link_local:       "Link-local",
  unique_local:     "Unique Local",
  cgnat:            "CGNAT",
  reserved:         "Reserved",
  unknown:          "Unknown Scope",
};

function groupKeyForNode(node: TopologyNode, subnetByNodeKey: Map<string, string>): string {
  if (node.agent_id) return `agent:${node.agent_id}`;
  const subnet = subnetByNodeKey.get(node.node_key);
  if (subnet) return `subnet:${subnet}`;
  if (node.cidr) return `subnet:${node.cidr}`;
  const scope = String(node.metadata?.ip_scope ?? "").toLowerCase();
  if (scope) return `scope:${scope}`;
  return "ungrouped";
}

function groupTypeFor(key: string): TopologyGroup["group_type"] {
  if (key.startsWith("agent:")) return "agent";
  if (key.startsWith("subnet:")) return "subnet";
  if (key.startsWith("scope:")) return "scope";
  return "ungrouped";
}

function groupLabelFor(key: string, agentLabelById: Map<string, string>): string {
  if (key.startsWith("agent:")) {
    const id = key.slice("agent:".length);
    return agentLabelById.get(id) ?? id;
  }
  if (key.startsWith("subnet:")) return key.slice("subnet:".length);
  if (key.startsWith("scope:")) {
    const scope = key.slice("scope:".length);
    return SCOPE_LABELS[scope] ?? scope;
  }
  return "Ungrouped";
}

export function groupTopologyGraph(
  graph: TopologyGraph,
  agentLabelById: Map<string, string> = new Map(),
): { groups: TopologyGroup[]; edges: TopologyGroupEdge[] } {
  if (!graph || graph.nodes.length === 0) return { groups: [], edges: [] };

  const subnetByNodeKey = new Map<string, string>();
  for (const edge of graph.edges) {
    if (edge.edge_type === "member_of_subnet") {
      subnetByNodeKey.set(edge.source_node_key, edge.target_node_key);
    }
  }

  const nodeGroupKey = new Map<string, string>();
  for (const node of graph.nodes) {
    nodeGroupKey.set(node.node_key, groupKeyForNode(node, subnetByNodeKey));
  }

  const buckets = new Map<string, TopologyNode[]>();
  for (const node of graph.nodes) {
    const gk = nodeGroupKey.get(node.node_key) ?? "ungrouped";
    const bucket = buckets.get(gk) ?? [];
    bucket.push(node);
    buckets.set(gk, bucket);
  }

  const groups: TopologyGroup[] = [];
  for (const [gk, nodes] of buckets) {
    const alertCount = nodes.reduce((s, n) => s + n.alert_count, 0);
    const highestSev = highestSeverity(nodes);
    const riskScore = Math.max(0, ...nodes.map((n) => n.risk_score));
    const stale = nodes.every((n) => n.is_stale);
    const agentId = nodes.find((n) => n.agent_id)?.agent_id ?? null;
    const cidr = nodes.find((n) => n.cidr)?.cidr ?? null;
    groups.push({
      group_key: gk,
      group_type: groupTypeFor(gk),
      label: groupLabelFor(gk, agentLabelById),
      node_keys: nodes.map((n) => n.node_key),
      node_count: nodes.length,
      alert_count: alertCount,
      highest_severity: highestSev,
      risk_score: riskScore,
      is_stale: stale,
      agent_id: agentId,
      cidr,
    });
  }

  const groupEdgeMap = new Map<string, TopologyGroupEdge>();
  for (const edge of graph.edges) {
    const sg = nodeGroupKey.get(edge.source_node_key);
    const tg = nodeGroupKey.get(edge.target_node_key);
    if (!sg || !tg || sg === tg) continue;
    const [a, b] = [sg, tg].sort();
    const ek = `${a}|||${b}`;
    const existing = groupEdgeMap.get(ek);
    if (existing) {
      existing.weight += Number(edge.weight || 0);
      existing.event_count += edge.event_count;
      existing.alert_count += edge.alert_count;
      existing.edge_types = [...new Set([...existing.edge_types, edge.edge_type as TopologyEdgeType])];
      if (severityWeight(edge.severity) > severityWeight(existing.severity)) {
        existing.severity = edge.severity as TopologySeverity;
      }
    } else {
      groupEdgeMap.set(ek, {
        edge_key: ek,
        source_group_key: sg,
        target_group_key: tg,
        edge_types: [edge.edge_type as TopologyEdgeType],
        weight: Number(edge.weight || 0),
        event_count: edge.event_count,
        alert_count: edge.alert_count,
        severity: edge.severity as TopologySeverity,
      });
    }
  }

  return { groups, edges: [...groupEdgeMap.values()] };
}
