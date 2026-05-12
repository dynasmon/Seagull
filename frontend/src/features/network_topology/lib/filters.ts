import type {
  TopologyEdge,
  TopologyFilters,
  TopologyGraph,
  TopologyGraphParams,
  TopologyNode,
  TopologyObservationParams,
  TopologySubnetParams,
  TopologyTimeWindowMinutes,
} from "../types";

export const DEFAULT_TOPOLOGY_FILTERS: TopologyFilters = {
  agent_id: "",
  window_minutes: 1440,
  node_type: "",
  edge_type: "",
  ip_scope: "",
  min_confidence: 30,
  severity: "",
  q: "",
};

export const TOPOLOGY_TIME_WINDOWS: Array<{ value: TopologyTimeWindowMinutes; label: string }> = [
  { value: 15, label: "15 min" },
  { value: 60, label: "1 hour" },
  { value: 360, label: "6 hours" },
  { value: 1440, label: "24 hours" },
  { value: 10080, label: "7 days" },
];

export const TOPOLOGY_NODE_TYPE_OPTIONS = [
  { value: "", label: "All node types" },
  { value: "agent", label: "Agents" },
  { value: "host", label: "Hosts" },
  { value: "interface", label: "Interfaces" },
  { value: "subnet", label: "Subnets" },
  { value: "service", label: "Services" },
  { value: "external_ip", label: "External IPs" },
  { value: "gateway", label: "Gateways" },
  { value: "docker_network", label: "Docker networks" },
  { value: "unknown", label: "Unknown" },
];

export const TOPOLOGY_EDGE_TYPE_OPTIONS = [
  { value: "", label: "All edge types" },
  { value: "observed_flow", label: "Observed flows" },
  { value: "listens_on", label: "Listening services" },
  { value: "owns_interface", label: "Owns interface" },
  { value: "member_of_subnet", label: "Subnet membership" },
  { value: "alert_related", label: "Alert context" },
  { value: "exposure_related", label: "Exposure context" },
  { value: "same_agent", label: "Same agent" },
  { value: "route_next_hop", label: "Next hop" },
  { value: "inferred_relationship", label: "Inferred" },
];

export const TOPOLOGY_IP_SCOPE_OPTIONS = [
  { value: "", label: "All IP scopes" },
  { value: "internal_network", label: "Internal" },
  { value: "private_address", label: "Private" },
  { value: "public_internet", label: "Public" },
  { value: "link_local", label: "Link-local" },
  { value: "loopback", label: "Loopback" },
  { value: "unique_local", label: "Unique local" },
  { value: "cgnat", label: "CGNAT" },
  { value: "reserved", label: "Reserved/Test" },
  { value: "unknown", label: "Unknown" },
];

export const TOPOLOGY_SEVERITY_OPTIONS = [
  { value: "", label: "All severities" },
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

export function parseTopologyFilters(sp: URLSearchParams): TopologyFilters {
  return {
    agent_id: clean(sp.get("agent")),
    window_minutes: parseWindow(sp.get("window")),
    node_type: clean(sp.get("node_type")).toLowerCase(),
    edge_type: clean(sp.get("edge_type")).toLowerCase(),
    ip_scope: clean(sp.get("ip_scope")).toLowerCase(),
    min_confidence: clampInt(sp.get("min_confidence"), 1, 99, DEFAULT_TOPOLOGY_FILTERS.min_confidence),
    severity: clean(sp.get("severity")).toLowerCase(),
    q: clean(sp.get("q")),
  };
}

export function serializeTopologyFilters(filters: TopologyFilters): URLSearchParams {
  const sp = new URLSearchParams();
  if (filters.agent_id) sp.set("agent", filters.agent_id);
  if (filters.window_minutes !== DEFAULT_TOPOLOGY_FILTERS.window_minutes) sp.set("window", String(filters.window_minutes));
  if (filters.node_type) sp.set("node_type", filters.node_type);
  if (filters.edge_type) sp.set("edge_type", filters.edge_type);
  if (filters.ip_scope) sp.set("ip_scope", filters.ip_scope);
  if (filters.min_confidence !== DEFAULT_TOPOLOGY_FILTERS.min_confidence) {
    sp.set("min_confidence", String(filters.min_confidence));
  }
  if (filters.severity) sp.set("severity", filters.severity);
  if (filters.q) sp.set("q", filters.q);
  return sp;
}

export function topologyFilterKey(filters: TopologyFilters): string {
  return serializeTopologyFilters(filters).toString();
}

export function hasActiveTopologyFilters(filters: TopologyFilters): boolean {
  return topologyFilterKey(filters) !== "";
}

function windowBounds(filters: TopologyFilters, now: Date): { since: string; until: string } {
  const until = new Date(now);
  const since = new Date(until.getTime() - filters.window_minutes * 60_000);
  return { since: since.toISOString(), until: until.toISOString() };
}

export function resolveTopologyGraphParams(filters: TopologyFilters, now = new Date()): TopologyGraphParams {
  const bounds = windowBounds(filters, now);
  return {
    max_nodes: 350,
    max_edges: 650,
    min_confidence: filters.min_confidence,
    agent_id: filters.agent_id || undefined,
    node_types: filters.node_type ? [filters.node_type] : undefined,
    edge_types: filters.edge_type ? [filters.edge_type] : undefined,
    ip_scope: filters.ip_scope || undefined,
    include_stale: false,
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
  const severity = String(filters.severity || "").toLowerCase();
  const needle = filters.q.trim().toLowerCase();
  if (!severity && !needle) return graph;

  const nodeByKey = new Map(graph.nodes.map((node) => [node.node_key, node]));
  const visibleNodeKeys = new Set<string>();

  for (const node of graph.nodes) {
    const severityOk = !severity || String(node.severity || "").toLowerCase() === severity;
    if (severityOk && nodeMatchesSearch(node, needle)) visibleNodeKeys.add(node.node_key);
  }

  const edges = graph.edges.filter((edge) => {
    const severityOk = !severity || String(edge.severity || "").toLowerCase() === severity;
    const searchOk = edgeMatchesSearch(edge, nodeByKey, needle);
    const endpointOk = visibleNodeKeys.has(edge.source_node_key) || visibleNodeKeys.has(edge.target_node_key);
    if ((severity || needle) && severityOk && searchOk && endpointOk) {
      visibleNodeKeys.add(edge.source_node_key);
      visibleNodeKeys.add(edge.target_node_key);
      return true;
    }
    return false;
  });

  return {
    ...graph,
    nodes: graph.nodes.filter((node) => visibleNodeKeys.has(node.node_key)),
    edges,
    graph_health: {
      ...graph.graph_health,
      node_count: visibleNodeKeys.size,
      edge_count: edges.length,
    },
  };
}
