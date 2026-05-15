import type { TopologyEdge, TopologyGraph, TopologyNode } from "../types";

export type TopologyLayoutNode = TopologyNode & {
  x: number;
  y: number;
  radius: number;
};

export type TopologyLayoutEdge = TopologyEdge & {
  source: TopologyLayoutNode | null;
  target: TopologyLayoutNode | null;
};

export type TopologyLayout = {
  width: number;
  height: number;
  nodes: TopologyLayoutNode[];
  edges: TopologyLayoutEdge[];
};

const WIDTH = 1120;
const HEIGHT = 640;
const COLUMN_X: Record<string, number> = {
  agent: 100,
  host: 250,
  interface: 400,
  docker_network: 520,
  subnet: 660,
  gateway: 790,
  service: 900,
  external_ip: 1020,
  unknown: 560,
};

function columnFor(node: TopologyNode): number {
  return COLUMN_X[node.node_type] ?? COLUMN_X.unknown;
}

function radiusFor(node: TopologyNode): number {
  const score = Math.max(0, Math.min(100, Number(node.risk_score || 0)));
  const confidence = Math.max(0, Math.min(100, Number(node.confidence || 0)));
  return 18 + Math.round(score / 20) + Math.round(confidence / 35);
}

export function computeTopologyLayout(graph: TopologyGraph | null): TopologyLayout {
  if (!graph || graph.nodes.length === 0) {
    return { width: WIDTH, height: HEIGHT, nodes: [], edges: [] };
  }

  const columns = new Map<number, TopologyNode[]>();
  for (const node of graph.nodes) {
    const x = columnFor(node);
    const bucket = columns.get(x) ?? [];
    bucket.push(node);
    columns.set(x, bucket);
  }

  const layoutNodes: TopologyLayoutNode[] = [];
  for (const [x, nodes] of columns.entries()) {
    const sorted = [...nodes].sort((a, b) => {
      const riskDelta = Number(b.risk_score || 0) - Number(a.risk_score || 0);
      if (riskDelta !== 0) return riskDelta;
      return String(a.label).localeCompare(String(b.label));
    });
    const gap = HEIGHT / (sorted.length + 1);
    sorted.forEach((node, idx) => {
      const stagger = sorted.length > 1 && idx % 2 === 1 ? 22 : 0;
      layoutNodes.push({
        ...node,
        x,
        y: Math.max(42, Math.min(HEIGHT - 42, Math.round(gap * (idx + 1) + stagger))),
        radius: radiusFor(node),
      });
    });
  }

  const nodeByKey = new Map(layoutNodes.map((node) => [node.node_key, node]));
  return {
    width: WIDTH,
    height: HEIGHT,
    nodes: layoutNodes,
    edges: graph.edges.map((edge) => ({
      ...edge,
      source: nodeByKey.get(edge.source_node_key) ?? null,
      target: nodeByKey.get(edge.target_node_key) ?? null,
    })),
  };
}
