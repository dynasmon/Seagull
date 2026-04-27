import { ExposureGraphEdge, ExposureGraphNode } from "./types";

export type LayoutNode = ExposureGraphNode & { x: number; y: number; radius: number };
export type LayoutEdge = ExposureGraphEdge & { x1: number; y1: number; x2: number; y2: number };

export type GraphLayout = {
  nodes: LayoutNode[];
  edges: LayoutEdge[];
  width: number;
  height: number;
};

const NODE_RADIUS = 22;
const LEVEL_GAP = 156;
const SIBLING_GAP = 132;
const GRAPH_SIDE_PADDING = 96;

function buildAdjacency(nodes: ExposureGraphNode[], edges: ExposureGraphEdge[]) {
  const adj = new Map<string, Set<string>>();
  for (const n of nodes) adj.set(n.node_key, new Set());
  for (const e of edges) {
    adj.get(e.source_node_key)?.add(e.target_node_key);
    adj.get(e.target_node_key)?.add(e.source_node_key);
  }
  return adj;
}

function bfsLevels(
  rootKey: string,
  adj: Map<string, Set<string>>,
): Map<string, number> {
  const levels = new Map<string, number>();
  const queue: string[] = [rootKey];
  levels.set(rootKey, 0);
  while (queue.length > 0) {
    const cur = queue.shift()!;
    const curLevel = levels.get(cur)!;
    for (const neighbor of adj.get(cur) ?? []) {
      if (!levels.has(neighbor)) {
        levels.set(neighbor, curLevel + 1);
        queue.push(neighbor);
      }
    }
  }
  return levels;
}

export function computeGraphLayout(
  rootKey: string,
  nodes: ExposureGraphNode[],
  edges: ExposureGraphEdge[],
  containerWidth = 900,
): GraphLayout {
  if (nodes.length === 0) {
    return { nodes: [], edges: [], width: containerWidth, height: 300 };
  }

  const adj = buildAdjacency(nodes, edges);
  const levels = bfsLevels(rootKey, adj);

  const nodesByKey = new Map(nodes.map((node) => [node.node_key, node]));
  const levelGroups = new Map<number, string[]>();
  for (const n of nodes) {
    const lvl = levels.get(n.node_key) ?? 0;
    if (!levelGroups.has(lvl)) levelGroups.set(lvl, []);
    levelGroups.get(lvl)!.push(n.node_key);
  }

  const maxLevel = Math.max(...levelGroups.keys());
  const totalHeight = (maxLevel + 1) * LEVEL_GAP + NODE_RADIUS * 2;
  const widestLevelWidth = Math.max(
    containerWidth,
    ...Array.from(levelGroups.values()).map((keys) => keys.length * SIBLING_GAP + GRAPH_SIDE_PADDING * 2),
  );

  const posMap = new Map<string, { x: number; y: number }>();

  for (const [level, keys] of Array.from(levelGroups.entries()).sort((a, b) => a[0] - b[0])) {
    keys.sort((leftKey, rightKey) => {
      if (leftKey === rootKey) return -1;
      if (rightKey === rootKey) return 1;
      const left = nodesByKey.get(leftKey);
      const right = nodesByKey.get(rightKey);
      if (!left || !right) return leftKey.localeCompare(rightKey);
      if (right.risk_score !== left.risk_score) return right.risk_score - left.risk_score;
      if (right.confidence !== left.confidence) return right.confidence - left.confidence;
      if (left.node_type !== right.node_type) return left.node_type.localeCompare(right.node_type);
      return left.label.localeCompare(right.label);
    });
    const y = level * LEVEL_GAP + NODE_RADIUS + 20;
    const totalWidth = keys.length * SIBLING_GAP;
    const startX = (widestLevelWidth - totalWidth) / 2 + SIBLING_GAP / 2;
    keys.forEach((key, i) => {
      posMap.set(key, { x: startX + i * SIBLING_GAP, y });
    });
  }

  const layoutNodes: LayoutNode[] = nodes.map((n) => {
    const pos = posMap.get(n.node_key) ?? { x: widestLevelWidth / 2, y: totalHeight / 2 };
    return { ...n, x: pos.x, y: pos.y, radius: NODE_RADIUS };
  });

  const nodePos = new Map<string, { x: number; y: number }>();
  for (const n of layoutNodes) nodePos.set(n.node_key, { x: n.x, y: n.y });

  const layoutEdges: LayoutEdge[] = edges.map((e) => {
    const src = nodePos.get(e.source_node_key) ?? { x: 0, y: 0 };
    const tgt = nodePos.get(e.target_node_key) ?? { x: 0, y: 0 };
    return { ...e, x1: src.x, y1: src.y, x2: tgt.x, y2: tgt.y };
  });

  return { nodes: layoutNodes, edges: layoutEdges, width: widestLevelWidth, height: totalHeight };
}

export function severityColor(severity: string): string {
  switch (severity) {
    case "critical": return "#ef4444";
    case "high": return "#f97316";
    case "medium": return "#eab308";
    case "low": return "#3b82f6";
    case "informational": return "#6b7280";
    default: return "#9ca3af";
  }
}
