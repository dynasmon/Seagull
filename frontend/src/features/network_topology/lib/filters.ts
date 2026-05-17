import type {
  TopologyEdge,
  TopologyFilters,
  TopologyGraph,
  TopologyGraphParams,
  TopologyIpScope,
  TopologyNode,
  TopologyObservationParams,
  TopologySeverity,
  TopologySubnetParams,
  TopologyTimeWindowMinutes,
  TopologyViewMode,
} from "../types";
import { groupTopologyGraph } from "./grouping";

export const DEFAULT_TOPOLOGY_FILTERS: TopologyFilters = {
  agent_id: "",
  group_key: "",
  window_minutes: 1440,
  node_types: [],
  edge_types: [],
  ip_scopes: [],
  min_confidence: 30,
  severities: [],
  q: "",
  view_mode: "location",
  include_stale: false,
  has_alerts: false,
  has_exposure: false,
};

export const TOPOLOGY_TIME_WINDOWS: Array<{ value: TopologyTimeWindowMinutes; label: string }> = [
  { value: 15, label: "15 min" },
  { value: 60, label: "1 hour" },
  { value: 360, label: "6 hours" },
  { value: 1440, label: "24 hours" },
  { value: 10080, label: "7 days" },
];

export const TOPOLOGY_NODE_TYPE_OPTIONS = [
  { value: "agent", label: "Agent" },
  { value: "host", label: "Host" },
  { value: "interface", label: "Interface" },
  { value: "subnet", label: "Subnet" },
  { value: "service", label: "Service" },
  { value: "external_ip", label: "External IP" },
  { value: "gateway", label: "Gateway" },
  { value: "docker_network", label: "Docker Network" },
  { value: "unknown", label: "Unknown" },
];

export const TOPOLOGY_EDGE_TYPE_OPTIONS = [
  { value: "observed_flow", label: "Observed Flow" },
  { value: "listens_on", label: "Listening Service" },
  { value: "owns_interface", label: "Owns Interface" },
  { value: "member_of_subnet", label: "Subnet Member" },
  { value: "alert_related", label: "Alert Context" },
  { value: "exposure_related", label: "Exposure Context" },
  { value: "same_agent", label: "Same Agent" },
  { value: "route_next_hop", label: "Next Hop" },
  { value: "inferred_relationship", label: "Inferred" },
];

export const TOPOLOGY_IP_SCOPE_OPTIONS = [
  { value: "internal_network", label: "Internal" },
  { value: "private_address", label: "Private" },
  { value: "public_internet", label: "Public" },
  { value: "link_local", label: "Link-local" },
  { value: "loopback", label: "Loopback" },
  { value: "unique_local", label: "Unique Local" },
  { value: "cgnat", label: "CGNAT" },
  { value: "reserved", label: "Reserved" },
  { value: "unknown", label: "Unknown" },
];

export const TOPOLOGY_SEVERITY_OPTIONS = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "informational", label: "Informational" },
  { value: "unknown", label: "Unknown" },
];

function clean(value: unknown): string {
  return String(value ?? "").trim();
}

function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  const next = Number.parseInt(clean(value), 10);
  if (!Number.isFinite(next)) return fallback;
  return Math.min(max, Math.max(min, next));
}

function parseWindow(value: unknown): TopologyTimeWindowMinutes {
  const raw = clampInt(value, 15, 10080, DEFAULT_TOPOLOGY_FILTERS.window_minutes);
  return TOPOLOGY_TIME_WINDOWS.some((option) => option.value === raw)
    ? (raw as TopologyTimeWindowMinutes)
    : DEFAULT_TOPOLOGY_FILTERS.window_minutes;
}

function parseList(csv: string): string[] {
  return csv
    .split(",")
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
}

function parseViewMode(value: string | null): TopologyViewMode {
  return value === "connection" ? "connection" : "location";
}

export function parseTopologyFilters(sp: URLSearchParams): TopologyFilters {
  const nodeTypes = [
    ...sp.getAll("node_types"),
    ...parseList(sp.get("node_type") ?? ""),
  ].map((v) => v.toLowerCase()).filter(Boolean);

  const edgeTypes = [
    ...sp.getAll("edge_types"),
    ...parseList(sp.get("edge_type") ?? ""),
  ].map((v) => v.toLowerCase()).filter(Boolean);

  const ipScopes = [
    ...sp.getAll("ip_scopes"),
    ...parseList(sp.get("ip_scope") ?? ""),
  ].map((v) => v.toLowerCase()).filter(Boolean) as TopologyIpScope[];

  const severities = [
    ...sp.getAll("severities"),
    ...parseList(sp.get("severity") ?? ""),
  ].map((v) => v.toLowerCase()).filter(Boolean) as TopologySeverity[];

  return {
    agent_id: clean(sp.get("agent")),
    group_key: clean(sp.get("group")),
    window_minutes: parseWindow(sp.get("window")),
    node_types: [...new Set(nodeTypes)],
    edge_types: [...new Set(edgeTypes)],
    ip_scopes: [...new Set(ipScopes)],
    min_confidence: clampInt(sp.get("min_confidence"), 1, 99, DEFAULT_TOPOLOGY_FILTERS.min_confidence),
    severities: [...new Set(severities)],
    q: clean(sp.get("q")),
    view_mode: parseViewMode(sp.get("mode")),
    include_stale: sp.get("include_stale") === "1",
    has_alerts: sp.get("has_alerts") === "1",
    has_exposure: sp.get("has_exposure") === "1",
  };
}

export function serializeTopologyFilters(filters: TopologyFilters): URLSearchParams {
  const sp = new URLSearchParams();
  if (filters.agent_id) sp.set("agent", filters.agent_id);
  if (filters.group_key) sp.set("group", filters.group_key);
  if (filters.window_minutes !== DEFAULT_TOPOLOGY_FILTERS.window_minutes) {
    sp.set("window", String(filters.window_minutes));
  }
  for (const nt of filters.node_types) sp.append("node_types", nt);
  for (const et of filters.edge_types) sp.append("edge_types", et);
  for (const is of filters.ip_scopes) sp.append("ip_scopes", is);
  if (filters.min_confidence !== DEFAULT_TOPOLOGY_FILTERS.min_confidence) {
    sp.set("min_confidence", String(filters.min_confidence));
  }
  for (const sv of filters.severities) sp.append("severities", sv);
  if (filters.q) sp.set("q", filters.q);
  if (filters.view_mode !== DEFAULT_TOPOLOGY_FILTERS.view_mode) sp.set("mode", filters.view_mode);
  if (filters.include_stale) sp.set("include_stale", "1");
  if (filters.has_alerts) sp.set("has_alerts", "1");
  if (filters.has_exposure) sp.set("has_exposure", "1");
  return sp;
}

export function topologyFilterKey(filters: TopologyFilters): string {
  return serializeTopologyFilters(filters).toString();
}

export function hasActiveTopologyFilters(filters: TopologyFilters): boolean {
  const f = { ...filters, view_mode: "location" as TopologyViewMode };
  return topologyFilterKey(f) !== "";
}

export function activeFilterCount(filters: TopologyFilters): number {
  let count = 0;
  if (filters.agent_id) count++;
  if (filters.group_key) count++;
  if (filters.window_minutes !== DEFAULT_TOPOLOGY_FILTERS.window_minutes) count++;
  count += filters.node_types.length;
  count += filters.edge_types.length;
  count += filters.ip_scopes.length;
  count += filters.severities.length;
  if (filters.min_confidence !== DEFAULT_TOPOLOGY_FILTERS.min_confidence) count++;
  if (filters.q) count++;
  if (filters.include_stale) count++;
  if (filters.has_alerts) count++;
  if (filters.has_exposure) count++;
  return count;
}

function windowBounds(filters: TopologyFilters, now: Date): { since: string; until: string } {
  const until = new Date(now);
  const since = new Date(until.getTime() - filters.window_minutes * 60_000);
  return { since: since.toISOString(), until: until.toISOString() };
}

export function resolveTopologyGraphParams(
  filters: TopologyFilters,
  now = new Date(),
  opts: { focused_group_key?: string } = {},
): TopologyGraphParams {
  const bounds = windowBounds(filters, now);
  const focusedGroupKey = opts.focused_group_key || undefined;
  return {
    max_nodes: 350,
    max_edges: 650,
    min_confidence: filters.min_confidence,
    agent_id: filters.agent_id || undefined,
    node_types: filters.node_types.length > 0 ? filters.node_types : undefined,
    edge_types: filters.edge_types.length > 0 ? filters.edge_types : undefined,
    ip_scope: filters.ip_scopes[0] || undefined,
    include_stale: filters.include_stale || false,
    view_mode: filters.view_mode,
    group_by: filters.view_mode === "location" ? "auto" : undefined,
    focused_group_key: focusedGroupKey,
    exclusive_focus: focusedGroupKey ? filters.view_mode === "connection" : undefined,
    ...bounds,
  };
}

export function resolveTopologySubnetParams(filters: TopologyFilters, now = new Date()): TopologySubnetParams {
  return {
    page_size: 50,
    agent_id: filters.agent_id || undefined,
    ...windowBounds(filters, now),
  };
}

export function resolveTopologyObservationParams(filters: TopologyFilters, now = new Date()): TopologyObservationParams {
  return {
    page_size: 50,
    agent_id: filters.agent_id || undefined,
    ...windowBounds(filters, now),
  };
}

function matchesText(value: unknown, needle: string): boolean {
  if (!needle) return true;
  return String(value ?? "").toLowerCase().includes(needle);
}

function nodeMatchesSearch(node: TopologyNode, needle: string): boolean {
  if (!needle) return true;
  return (
    matchesText(node.label, needle) ||
    matchesText(node.ip, needle) ||
    matchesText(node.cidr, needle) ||
    matchesText(node.protocol, needle) ||
    matchesText(node.port, needle) ||
    matchesText(node.agent_id, needle) ||
    matchesText(node.metadata?.hostname, needle) ||
    matchesText(node.metadata?.service_name, needle)
  );
}

function edgeMatchesSearch(edge: TopologyEdge, nodeByKey: Map<string, TopologyNode>, needle: string): boolean {
  if (!needle) return true;
  const source = nodeByKey.get(edge.source_node_key);
  const target = nodeByKey.get(edge.target_node_key);
  return (
    matchesText(edge.edge_type, needle) ||
    matchesText(edge.protocol, needle) ||
    matchesText(edge.port, needle) ||
    matchesText(edge.agent_id, needle) ||
    (source ? nodeMatchesSearch(source, needle) : false) ||
    (target ? nodeMatchesSearch(target, needle) : false)
  );
}

export function filterTopologyGraph(graph: TopologyGraph | null, filters: TopologyFilters): TopologyGraph | null {
  if (!graph) return null;

  const severities = filters.severities.map((s) => String(s || "").toLowerCase()).filter(Boolean);
  const needle = filters.q.trim().toLowerCase();
  const hasAlerts = filters.has_alerts;
  const hasExposure = filters.has_exposure;
  const groupKey = filters.group_key.trim();

  if (!severities.length && !needle && !hasAlerts && !hasExposure && !groupKey) return graph;

  const nodeByKey = new Map(graph.nodes.map((node) => [node.node_key, node]));
  const resolvedGroups = graph.groups
    ? graph.groups.map((group) => ({
        group_key: group.group_key,
        node_keys: group.child_node_keys,
        agent_id: (group.metadata?.agent_id as string | null) ?? null,
        cidr: (group.metadata?.cidr as string | null) ?? null,
      }))
    : groupTopologyGraph(graph).groups.map((group) => ({
        group_key: group.group_key,
        node_keys: group.node_keys,
        agent_id: group.agent_id,
        cidr: group.cidr,
      }));
  const selectedGroup = groupKey ? resolvedGroups.find((group) => group.group_key === groupKey) ?? null : null;
  const selectedGroupNodeKeys = new Set(selectedGroup?.node_keys ?? []);
  const visibleNodeKeys = new Set<string>();

  for (const node of graph.nodes) {
    const severityOk = !severities.length || severities.includes(String(node.severity || "").toLowerCase());
    const alertsOk = !hasAlerts || node.alert_count > 0;
    const exposureOk = !hasExposure || Boolean(node.metadata?.has_exposure_findings || node.metadata?.exposure_asset_key);
    const groupOk = !selectedGroup || selectedGroupNodeKeys.has(node.node_key) ||
      Boolean(selectedGroup.agent_id && node.agent_id === selectedGroup.agent_id) ||
      Boolean(selectedGroup.cidr && node.cidr === selectedGroup.cidr);
    if (severityOk && alertsOk && exposureOk && groupOk && nodeMatchesSearch(node, needle)) {
      visibleNodeKeys.add(node.node_key);
    }
  }

  const edges = graph.edges.filter((edge) => {
    const severityOk = !severities.length || severities.includes(String(edge.severity || "").toLowerCase());
    const searchOk = edgeMatchesSearch(edge, nodeByKey, needle);
    const endpointOk = selectedGroup
      ? visibleNodeKeys.has(edge.source_node_key) && visibleNodeKeys.has(edge.target_node_key)
      : visibleNodeKeys.has(edge.source_node_key) || visibleNodeKeys.has(edge.target_node_key);
    if (severityOk && searchOk && endpointOk) {
      visibleNodeKeys.add(edge.source_node_key);
      visibleNodeKeys.add(edge.target_node_key);
      return true;
    }
    return false;
  });
  const filteredNodes = graph.nodes.filter((node) => visibleNodeKeys.has(node.node_key));
  const visibleGroupKeys = new Set<string>();
  if (graph.groups) {
    for (const group of graph.groups) {
      const groupAgentId = (group.metadata?.agent_id as string | null) ?? null;
      const groupCidr = (group.metadata?.cidr as string | null) ?? null;
      const visible = filteredNodes.some((node) =>
        group.child_node_keys.includes(node.node_key) ||
        Boolean(groupAgentId && node.agent_id === groupAgentId) ||
        Boolean(groupCidr && node.cidr === groupCidr),
      );
      if (visible) visibleGroupKeys.add(group.group_key);
    }
  }

  return {
    ...graph,
    nodes: filteredNodes,
    edges,
    groups: graph.groups?.filter((group) => visibleGroupKeys.has(group.group_key)),
    group_edges: graph.group_edges?.filter(
      (edge) => visibleGroupKeys.has(edge.source_group_key) && visibleGroupKeys.has(edge.target_group_key),
    ),
    graph_health: {
      ...graph.graph_health,
      node_count: visibleNodeKeys.size,
      edge_count: edges.length,
    },
  };
}
