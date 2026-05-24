import type { TopologyEdge, TopologyNode } from "../../types";

export type TopologyNodeImportance = "anchor" | "elevated" | "normal";

const LABEL_CHAR_PX = 6.2;
const CARD_OVERHEAD = 60;
const CARD_MIN_W = 148;
const CARD_MAX_W = 240;
const CARD_H = 52;

export function groupCardSize(label: string): { w: number; h: number } {
  const w = Math.max(CARD_MIN_W, Math.min(CARD_MAX_W, Math.ceil(label.length * LABEL_CHAR_PX) + CARD_OVERHEAD));
  return { w, h: CARD_H };
}

export function edgePriorityRank(edge: Pick<TopologyEdge, "edge_type" | "confidence" | "alert_count">): number {
  switch (edge.edge_type) {
    case "alert_related":         return 100 + Number(edge.alert_count ?? 0) * 2;
    case "exposure_related":      return 80;
    case "listens_on":            return Number(edge.confidence) >= 70 ? 50 : 35;
    case "route_next_hop":        return 25;
    case "observed_flow":         return Number(edge.confidence) >= 70 ? 30 : 15;
    case "resolved_dns":          return 20;
    case "inferred_relationship": return 12;
    case "member_of_subnet":      return 10;
    default:                      return 5;
  }
}

export function groupEdgePriorityRank(alertCount: number, edgeTypes: string[]): number {
  if (alertCount > 0) return 90;
  if (edgeTypes.includes("alert_related") || edgeTypes.includes("exposure_related")) return 75;
  return 20;
}

export function shouldShowLabel(
  node: Pick<TopologyNode, "node_type" | "alert_count" | "severity">,
  isSelected: boolean,
  isSearchMatch: boolean,
  importance: TopologyNodeImportance,
  groupNodeCount: number,
): boolean {
  if (isSelected || isSearchMatch) return true;
  if (importance === "anchor" && groupNodeCount < 30) return true;
  const sev = String(node.severity ?? "").toLowerCase();
  if (node.alert_count > 0 && (sev === "critical" || sev === "high")) return true;
  return false;
}

export function nodeBoundingRadius(importance: TopologyNodeImportance): number {
  if (importance === "anchor") return 26;
  if (importance === "elevated") return 20;
  return 16;
}

export type EdgeRoutingHint = {
  visualPriority: "high" | "normal" | "low";
  curveStrength: number;
};

export function edgeRoutingHint(
  edge: Pick<TopologyEdge, "edge_type" | "confidence" | "alert_count">,
): EdgeRoutingHint {
  const rank = edgePriorityRank(edge);
  return {
    visualPriority: rank >= 80 ? "high" : rank >= 30 ? "normal" : "low",
    curveStrength: rank >= 80 ? 0.8 : rank >= 30 ? 0.55 : 0.3,
  };
}

export function groupNodeBoundingBox(
  x: number,
  y: number,
  label: string,
): { x: number; y: number; w: number; h: number } {
  const { w, h } = groupCardSize(label);
  return { x: x - w / 2, y: y - h / 2, w, h };
}

export function deviceNodeBoundingBox(
  x: number,
  y: number,
  importance: TopologyNodeImportance,
): { x: number; y: number; w: number; h: number } {
  const r = nodeBoundingRadius(importance);
  return { x: x - r, y: y - r, w: r * 2, h: r * 2 };
}
