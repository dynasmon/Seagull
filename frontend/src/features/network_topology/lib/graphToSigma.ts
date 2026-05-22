import { MultiDirectedGraph } from "graphology";
import type { Node, Edge } from "@xyflow/react";

import { edgeVisual, nodeVisual, severityColor } from "./visuals";
import type {
  ClusterHaloNodeData,
  DeviceNodeData,
  GroupNodeData,
  TopologyEdgeData,
  TopologyGroupEdgeData,
} from "./graphTransform";

export type SigmaNodeAttributes = {
  x: number;
  y: number;
  size: number;
  color: string;
  borderColor: string;
  label: string;
  type: "border" | "circle";
  zIndex: number;
  groupKey: string | null;
  isSelected: boolean;
  isDimmed: boolean;
  importance: "anchor" | "elevated" | "normal";
  nodeType: string;
  alertCount: number;
  severity: string;
  isNew: boolean;
  hidden: boolean;
};

export type SigmaEdgeAttributes = {
  size: number;
  color: string;
  type: string;
  edgeKind: string;
  parallelIndex: number;
  parallelTotal: number;
  isSelected: boolean;
  isDimmed: boolean;
};

export type SigmaGroupNodeAttributes = {
  x: number;
  y: number;
  size: number;
  color: string;
  borderColor: string;
  label: string;
  type: "border";
  zIndex: number;
  isSelected: boolean;
  isDimmed: boolean;
  alertCount: number;
  nodeCount: number;
  groupKey: string;
};

function importanceToSize(
  importance: "anchor" | "elevated" | "normal",
): number {
  if (importance === "anchor") return 16;
  if (importance === "elevated") return 10;
  return 7;
}

function dimColor(color: string): string {
  return color + "22";
}

export function rfToSigmaGraph(
  nodes: Node[],
  edges: Edge[],
): MultiDirectedGraph<
  SigmaNodeAttributes | SigmaGroupNodeAttributes,
  SigmaEdgeAttributes
> {
  const graph = new MultiDirectedGraph<
    SigmaNodeAttributes | SigmaGroupNodeAttributes,
    SigmaEdgeAttributes
  >();

  for (const node of nodes) {
    if (node.type === "clusterHalo") continue;

    if (node.type === "device") {
      const data = node.data as unknown as DeviceNodeData;
      const visual = nodeVisual(data.node);
      const size = importanceToSize(data.importance);
      const color = data.isDimmed ? dimColor(visual.stroke) : visual.fill;
      const borderColor = data.isSelected
        ? "#ffffff"
        : data.isDimmed
          ? dimColor(visual.stroke)
          : visual.stroke;

      graph.addNode(node.id, {
        x: node.position.x + (node.width ?? 96) / 2,
        y: node.position.y + (node.height ?? 96) / 2,
        size,
        color,
        borderColor,
        label: data.showLabel || data.isSelected ? data.node.label : "",
        type: "border",
        zIndex: node.zIndex ?? 2,
        groupKey: data.groupKey,
        isSelected: data.isSelected,
        isDimmed: data.isDimmed,
        importance: data.importance,
        nodeType: data.node.node_type,
        alertCount: data.node.alert_count,
        severity: data.node.severity,
        isNew: data.isNew ?? false,
        hidden: false,
      });
    } else if (node.type === "group") {
      const data = node.data as unknown as GroupNodeData;
      const color = data.isDimmed
        ? dimColor("#60A5FA")
        : "rgba(96,165,250,0.15)";
      const alertColor =
        data.group.alert_count > 0
          ? severityColor(data.group.highest_severity)
          : "#60A5FA";
      const borderColor = data.isSelected
        ? "#ffffff"
        : data.isDimmed
          ? dimColor(alertColor)
          : alertColor;

      graph.addNode(node.id, {
        x: node.position.x + (node.width ?? 140) / 2,
        y: node.position.y + (node.height ?? 50) / 2,
        size: 22 + Math.min(12, Math.log1p(data.group.node_count) * 3),
        color,
        borderColor,
        label: data.group.label,
        type: "border",
        zIndex: node.zIndex ?? 2,
        isSelected: data.isSelected,
        isDimmed: data.isDimmed,
        alertCount: data.group.alert_count,
        nodeCount: data.group.node_count,
        groupKey: data.group.group_key,
      });
    }
  }

  for (const edge of edges) {
    if (!graph.hasNode(edge.source) || !graph.hasNode(edge.target)) continue;

    if (edge.type === "topology") {
      const data = edge.data as unknown as TopologyEdgeData;
      if (!data?.edge) continue;
      const visual = edgeVisual(data.edge);
      const color = data.isDimmed
        ? dimColor(visual.stroke)
        : data.isSelected
          ? visual.stroke
          : visual.stroke +
            Math.round(visual.opacity * 255)
              .toString(16)
              .padStart(2, "0");

      graph.addDirectedEdgeWithKey(edge.id, edge.source, edge.target, {
        size: data.isSelected ? visual.width + 1.5 : visual.width,
        color,
        type: "curve",
        edgeKind: data.edge.edge_type,
        parallelIndex: data.parallelIndex ?? 0,
        parallelTotal: data.parallelTotal ?? 1,
        isSelected: data.isSelected,
        isDimmed: data.isDimmed,
      });
    } else if (edge.type === "group") {
      const data = edge.data as unknown as TopologyGroupEdgeData;
      if (!data?.groupEdge) continue;
      const ge = data.groupEdge;
      const alertColor =
        ge.alert_count > 0
          ? severityColor(ge.severity)
          : "rgba(96,165,250,0.35)";
      const color = data.isDimmed ? dimColor(alertColor) : alertColor;

      graph.addDirectedEdgeWithKey(edge.id, edge.source, edge.target, {
        size: 1.5 + Math.min(2, Math.log1p(ge.event_count ?? 0) / 3),
        color,
        type: "curve",
        edgeKind: ge.edge_types?.[0] ?? "observed_flow",
        parallelIndex: 0,
        parallelTotal: 1,
        isSelected: data.isSelected,
        isDimmed: data.isDimmed,
      });
    }
  }

  return graph;
}

export function extractHaloData(nodes: Node[]): Array<{
  groupKey: string;
  label: string;
  nodeCount: number;
  alertCount: number;
  highestSeverity: string;
  riskScore: number;
  isSelected: boolean;
  isDimmed: boolean;
}> {
  return nodes
    .filter((n) => n.type === "clusterHalo")
    .map((n) => {
      const data = n.data as unknown as ClusterHaloNodeData;
      return {
        groupKey: data.group.group_key,
        label: data.group.label,
        nodeCount: data.group.node_count,
        alertCount: data.group.alert_count,
        highestSeverity: data.group.highest_severity,
        riskScore: data.group.risk_score,
        isSelected: data.isSelected,
        isDimmed: data.isDimmed,
      };
    });
}
