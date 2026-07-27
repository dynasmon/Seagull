import type {
  TopologyEdgeType,
  TopologyGraph,
  TopologyGroup,
  TopologyGroupBackend,
  TopologyGroupEdge,
  TopologyGroupEdgeBackend,
  TopologyNode,
  TopologySeverity,
} from "../../types";

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

function isPublicEndpoint(node: TopologyNode): boolean {
  return (
    node.node_type === "external_ip" ||
    String(node.metadata?.ip_scope ?? "").toLowerCase() === "public_internet"
  );
}

function subnetRef(targetNodeKey: string, cidrByNodeKey: Map<string, string>): string {
  const cidr = cidrByNodeKey.get(targetNodeKey);
  if (cidr) return cidr;
  const prefix = "topo:subnet:";
  return targetNodeKey.startsWith(prefix) ? targetNodeKey.slice(prefix.length) : targetNodeKey;
}

function groupKeyForNode(node: TopologyNode, subnetByNodeKey: Map<string, string>): string {
  const scope = String(node.metadata?.ip_scope ?? "").toLowerCase();
  if (isPublicEndpoint(node)) return `scope:${scope || "public_internet"}`;
  if (node.agent_id) return `agent:${node.agent_id}`;
  const subnet = subnetByNodeKey.get(node.node_key);
  if (subnet) return `subnet:${subnet}`;
  if (node.cidr) return `subnet:${node.cidr}`;
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

  const subnetCidrByNodeKey = new Map(
    graph.nodes
      .filter((node) => node.node_type === "subnet" && node.cidr)
      .map((node) => [node.node_key, node.cidr as string]),
  );
  const subnetByNodeKey = new Map<string, string>();
  for (const edge of graph.edges) {
    if (edge.edge_type === "member_of_subnet") {
      subnetByNodeKey.set(edge.source_node_key, subnetRef(edge.target_node_key, subnetCidrByNodeKey));
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
    const groupSubnetRef = gk.startsWith("subnet:") ? gk.slice("subnet:".length) : null;
    const cidr = nodes.find((n) => n.cidr)?.cidr ?? groupSubnetRef;
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

function backendGroupToGroup(group: TopologyGroupBackend): TopologyGroup {
  return {
    group_key: group.group_key,
    group_type: group.group_type as TopologyGroup["group_type"],
    label: group.label,
    node_keys: group.child_node_keys,
    node_count: group.node_count,
    alert_count: group.alert_count,
    highest_severity: group.highest_severity,
    risk_score: group.risk_score,
    is_stale: group.is_stale,
    agent_id: (group.metadata?.agent_id as string | null) ?? null,
    cidr: (group.metadata?.cidr as string | null) ?? null,
    gateway_candidate_count: typeof group.metadata?.gateway_candidate_count === "number"
      ? group.metadata.gateway_candidate_count
      : null,
  };
}

function backendGroupEdgeTypes(edge: TopologyGroupEdgeBackend): TopologyEdgeType[] {
  const breakdown = edge.metadata?.edge_types;
  if (!breakdown || typeof breakdown !== "object") return [edge.edge_type as TopologyEdgeType];
  const types = Object.keys(breakdown as Record<string, unknown>);
  if (types.length === 0) return [edge.edge_type as TopologyEdgeType];
  return [
    edge.edge_type as TopologyEdgeType,
    ...types.filter((type) => type !== edge.edge_type),
  ] as TopologyEdgeType[];
}

function backendGroupEdgeTypeCounts(edge: TopologyGroupEdgeBackend): Record<string, number> {
  const breakdown = edge.metadata?.edge_types;
  if (!breakdown || typeof breakdown !== "object") return { [edge.edge_type]: edge.edge_count };
  const counts: Record<string, number> = {};
  for (const [type, value] of Object.entries(breakdown as Record<string, unknown>)) {
    const count = Number(value);
    if (Number.isFinite(count) && count > 0) counts[type] = count;
  }
  return Object.keys(counts).length > 0 ? counts : { [edge.edge_type]: edge.edge_count };
}

function backendGroupEdgeToGroupEdge(edge: TopologyGroupEdgeBackend): TopologyGroupEdge {
  return {
    edge_key: edge.edge_key,
    source_group_key: edge.source_group_key,
    target_group_key: edge.target_group_key,
    edge_types: backendGroupEdgeTypes(edge),
    edge_type_counts: backendGroupEdgeTypeCounts(edge),
    weight: edge.weight,
    event_count: edge.edge_count,
    alert_count: edge.alert_count,
    severity: edge.highest_severity,
  };
}

/**
 * The API caps `child_node_keys` per group, so large groups arrive truncated. Resolve every
 * node in the graph to a group, falling back to the same identity the grouper used.
 */
export function resolveNodeGroupKeys(
  graph: TopologyGraph | null,
  groups: TopologyGroup[],
): Map<string, string> {
  const assigned = new Map<string, string>();
  if (!graph) return assigned;

  const present = new Set(graph.nodes.map((node) => node.node_key));
  for (const group of groups) {
    for (const key of group.node_keys) {
      if (present.has(key) && !assigned.has(key)) assigned.set(key, group.group_key);
    }
  }

  const byAgent = new Map<string, string>();
  const byCidr = new Map<string, string>();
  const byScope = new Map<string, string>();
  for (const group of groups) {
    if (group.agent_id && !byAgent.has(group.agent_id)) byAgent.set(group.agent_id, group.group_key);
    if (group.cidr && !byCidr.has(group.cidr)) byCidr.set(group.cidr, group.group_key);
    if (group.group_key.startsWith("scope:")) {
      byScope.set(group.group_key.slice("scope:".length), group.group_key);
    }
  }

  for (const node of graph.nodes) {
    if (assigned.has(node.node_key)) continue;
    const scope = String(node.metadata?.ip_scope ?? "").toLowerCase();
    const fallback = isPublicEndpoint(node)
      ? byScope.get(scope || "public_internet")
      : (node.agent_id ? byAgent.get(node.agent_id) : undefined) ??
        (node.cidr ? byCidr.get(node.cidr) : undefined) ??
        (scope ? byScope.get(scope) : undefined);
    if (fallback) assigned.set(node.node_key, fallback);
  }

  return assigned;
}

export function resolveTopologyGroups(
  graph: TopologyGraph | null,
  agentLabelById: Map<string, string> = new Map(),
): { groups: TopologyGroup[]; edges: TopologyGroupEdge[] } {
  if (!graph) return { groups: [], edges: [] };
  if (graph.groups) {
    return {
      groups: graph.groups.map(backendGroupToGroup),
      edges: (graph.group_edges ?? []).map(backendGroupEdgeToGroupEdge),
    };
  }
  return groupTopologyGraph(graph, agentLabelById);
}
