import type { TopologyEdge, TopologyNode, TopologySeverity } from "../types";

export type NodeVisual = { stroke: string; fill: string };

export type EdgeVisualStyle = {
  stroke: string;
  dashArray: string | undefined;
  width: number;
  opacity: number;
};

export const SEVERITY_COLORS: Record<string, string> = {
  critical:      "#F87171",
  high:          "#F97316",
  medium:        "#FBBF24",
  low:           "#4ADE80",
  informational: "#60A5FA",
  unknown:       "#9CA3AF",
};

const NODE_VISUAL: Record<string, NodeVisual> = {
  agent:          { stroke: "#60A5FA", fill: "rgba(96,165,250,0.13)" },
  gateway:        { stroke: "#60A5FA", fill: "rgba(96,165,250,0.13)" },
  host:           { stroke: "#4ADE80", fill: "rgba(74,222,128,0.13)" },
  interface:      { stroke: "#38BDF8", fill: "rgba(56,189,248,0.13)" },
  subnet:         { stroke: "#FBBF24", fill: "rgba(251,191,36,0.13)" },
  service:        { stroke: "#C084FC", fill: "rgba(192,132,252,0.13)" },
  external_ip:    { stroke: "#F87171", fill: "rgba(248,113,113,0.13)" },
  docker_network: { stroke: "#22D3EE", fill: "rgba(34,211,238,0.13)" },
  unknown:        { stroke: "#9CA3AF", fill: "rgba(156,163,175,0.08)" },
};

const STALE_AGENT_VISUAL: NodeVisual = { stroke: "#F97316", fill: "rgba(249,115,22,0.13)" };

export function nodeVisual(node: Pick<TopologyNode, "node_type" | "is_stale">): NodeVisual {
  if (node.node_type === "agent" && node.is_stale) return STALE_AGENT_VISUAL;
  return NODE_VISUAL[node.node_type] ?? NODE_VISUAL.unknown;
}

export function nodeVisualByType(nodeType: string): NodeVisual {
  return NODE_VISUAL[nodeType] ?? NODE_VISUAL.unknown;
}

export function severityColor(severity: TopologySeverity | string | null | undefined): string {
  return SEVERITY_COLORS[String(severity ?? "").toLowerCase()] ?? SEVERITY_COLORS.unknown;
}

export function edgeVisual(edge: Pick<TopologyEdge, "edge_type" | "confidence">): EdgeVisualStyle {
  const lowConf = Number(edge.confidence || 0) < 50;
  switch (edge.edge_type) {
    case "alert_related":
      return { stroke: "#F87171", dashArray: undefined, width: 1.8, opacity: 0.85 };
    case "exposure_related":
      return { stroke: "#F87171", dashArray: "5 3", width: 1.5, opacity: 0.75 };
    case "observed_flow":
      return { stroke: "#60A5FA", dashArray: lowConf ? "5 4" : undefined, width: 1.8, opacity: 0.7 };
    case "listens_on":
      return { stroke: "#FBBF24", dashArray: lowConf ? "5 4" : undefined, width: 1.2, opacity: 0.65 };
    case "resolved_dns":
      return { stroke: "#C084FC", dashArray: "6 4", width: 1.2, opacity: 0.6 };
    case "member_of_subnet":
      return { stroke: "#FBBF24", dashArray: "3 3", width: 1.0, opacity: 0.5 };
    default:
      return { stroke: "#4B5563", dashArray: "3 3", width: 1.0, opacity: 0.45 };
  }
}

export const NODE_TYPE_LABELS: Record<string, string> = {
  agent:          "Agent",
  gateway:        "Gateway",
  host:           "Host",
  interface:      "Interface",
  subnet:         "Subnet",
  service:        "Service",
  external_ip:    "External IP",
  docker_network: "Container Net",
  unknown:        "Unknown",
};
