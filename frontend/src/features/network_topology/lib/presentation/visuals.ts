import type { TopologyEdge, TopologyNode, TopologySeverity } from "../../types";

export type NodeVisual = { stroke: string; fill: string };

export type EdgeVisualStyle = {
  stroke: string;
  dashArray: string | undefined;
  width: number;
  opacity: number;
};

export const SEVERITY_COLORS: Record<string, string> = {
  critical:      "#F87171",
  high:          "#FB923C",
  medium:        "#FACC15",
  low:           "#38BDF8",
  informational: "#60A5FA",
  unknown:       "#94A3B8",
};

const NODE_VISUAL: Record<string, NodeVisual> = {
  agent:          { stroke: "#22D3EE", fill: "rgba(34,211,238,0.14)" },
  gateway:        { stroke: "#5EEAD4", fill: "rgba(94,234,212,0.13)" },
  subnet:         { stroke: "#2DD4BF", fill: "rgba(45,212,191,0.12)" },
  host:           { stroke: "#4ADE80", fill: "rgba(74,222,128,0.12)" },
  interface:      { stroke: "#A3E635", fill: "rgba(163,230,53,0.11)" },
  service:        { stroke: "#C084FC", fill: "rgba(192,132,252,0.12)" },
  docker_network: { stroke: "#818CF8", fill: "rgba(129,140,248,0.12)" },
  external_ip:    { stroke: "#94A3B8", fill: "rgba(148,163,184,0.10)" },
  unknown:        { stroke: "#64748B", fill: "rgba(100,116,139,0.10)" },
};

const STALE_VISUAL: NodeVisual = { stroke: "#F97316", fill: "rgba(249,115,22,0.12)" };

export const EXTERNAL_NODE_TYPES = new Set(["external_ip"]);

export function isExternalNode(node: Pick<TopologyNode, "node_type" | "metadata">): boolean {
  if (EXTERNAL_NODE_TYPES.has(node.node_type)) return true;
  return String(node.metadata?.ip_scope ?? "") === "public_internet";
}

export function isAgentAssetNode(node: Pick<TopologyNode, "node_type" | "metadata">): boolean {
  if (node.node_type === "agent") return true;
  return Boolean(node.metadata?.is_agent_asset);
}

/**
 * Inventory and traffic project the same machine under different keys, so an address the
 * agent owns can also appear as a plain observed host. Resolve identity by address too.
 */
export function agentAssetAddresses(nodes: Pick<TopologyNode, "node_type" | "metadata" | "ip">[]): Set<string> {
  const addresses = new Set<string>();
  for (const node of nodes) {
    if (node.ip && isAgentAssetNode(node)) addresses.add(node.ip);
  }
  return addresses;
}

export function nodeVisual(node: Pick<TopologyNode, "node_type" | "is_stale">): NodeVisual {
  if (node.node_type === "agent" && node.is_stale) return STALE_VISUAL;
  return NODE_VISUAL[node.node_type] ?? NODE_VISUAL.unknown;
}

export function nodeVisualByType(nodeType: string): NodeVisual {
  return NODE_VISUAL[nodeType] ?? NODE_VISUAL.unknown;
}

export function severityColor(severity: TopologySeverity | string | null | undefined): string {
  return SEVERITY_COLORS[String(severity ?? "").toLowerCase()] ?? SEVERITY_COLORS.unknown;
}

const RISK_SEVERITIES = new Set(["critical", "high", "medium"]);

export function hasSecuritySignal(
  node: Pick<TopologyNode, "severity" | "alert_count" | "risk_score" | "metadata">,
): boolean {
  if (Number(node.alert_count || 0) > 0) return true;
  if (RISK_SEVERITIES.has(String(node.severity ?? "").toLowerCase())) return true;
  if (Number(node.risk_score || 0) >= 70) return true;
  return Boolean(node.metadata?.has_exposure_findings || node.metadata?.exposure_asset_key);
}

export function riskAccent(
  node: Pick<TopologyNode, "severity" | "alert_count" | "risk_score" | "metadata">,
): string | null {
  return hasSecuritySignal(node) ? severityColor(node.severity) : null;
}

const EDGE_VISUAL: Record<string, EdgeVisualStyle> = {
  alert_related:         { stroke: "#F87171", dashArray: undefined, width: 2.0, opacity: 0.92 },
  exposure_related:      { stroke: "#FB7185", dashArray: "6 4",     width: 1.6, opacity: 0.82 },
  observed_flow:         { stroke: "#60A5FA", dashArray: undefined, width: 1.3, opacity: 0.52 },
  listens_on:            { stroke: "#C084FC", dashArray: undefined, width: 1.15, opacity: 0.44 },
  resolved_dns:          { stroke: "#A78BFA", dashArray: "6 4",     width: 1.1, opacity: 0.40 },
  route_next_hop:        { stroke: "#5EEAD4", dashArray: undefined, width: 1.3, opacity: 0.50 },
  member_of_subnet:      { stroke: "#2DD4BF", dashArray: "3 4",     width: 1.0, opacity: 0.30 },
  owns_interface:        { stroke: "#4ADE80", dashArray: "2 4",     width: 1.0, opacity: 0.28 },
  same_agent:            { stroke: "#475569", dashArray: "2 5",     width: 0.9, opacity: 0.24 },
  inferred_relationship: { stroke: "#64748B", dashArray: "5 5",     width: 1.0, opacity: 0.32 },
};

const EDGE_VISUAL_FALLBACK: EdgeVisualStyle = {
  stroke: "#64748B",
  dashArray: "4 4",
  width: 0.9,
  opacity: 0.26,
};

export function edgeVisual(edge: Pick<TopologyEdge, "edge_type" | "confidence">): EdgeVisualStyle {
  const base = EDGE_VISUAL[edge.edge_type] ?? EDGE_VISUAL_FALLBACK;
  if (Number(edge.confidence || 0) >= 50) return base;
  return { ...base, dashArray: base.dashArray ?? "5 4", opacity: base.opacity * 0.75 };
}

export const NODE_TYPE_LABELS: Record<string, string> = {
  agent:          "Sensor host",
  gateway:        "Gateway",
  host:           "Host",
  interface:      "Interface",
  subnet:         "Subnet",
  service:        "Service",
  external_ip:    "Internet endpoint",
  docker_network: "Container network",
  unknown:        "Unidentified",
};

export const EDGE_TYPE_LABELS: Record<string, string> = {
  alert_related:         "Alert context",
  exposure_related:      "Exposure context",
  observed_flow:         "Observed flow",
  listens_on:            "Listening service",
  resolved_dns:          "DNS resolution",
  route_next_hop:        "Route / next hop",
  member_of_subnet:      "Subnet member",
  owns_interface:        "Owns interface",
  same_agent:            "Same host",
  inferred_relationship: "Inferred link",
};

export const EDGE_TYPE_SHORT_LABELS: Record<string, string> = {
  alert_related:         "alert",
  exposure_related:      "exposure",
  observed_flow:         "flow",
  listens_on:            "listens",
  resolved_dns:          "dns",
  route_next_hop:        "route",
  member_of_subnet:      "subnet",
  owns_interface:        "nic",
  same_agent:            "host",
  inferred_relationship: "inferred",
};
