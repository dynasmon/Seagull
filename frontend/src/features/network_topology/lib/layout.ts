import type { TopologyEdge, TopologyGraph, TopologyNode } from "../types";
import { resolveServiceInfo } from "./services";

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

// When total service nodes exceed this, collapse them into per-agent cluster nodes.
const SERVICE_CLUSTER_THRESHOLD = 8;

function columnFor(node: TopologyNode): number {
  return COLUMN_X[node.node_type] ?? COLUMN_X.unknown;
}

function radiusFor(node: TopologyNode): number {
  const score = Math.max(0, Math.min(100, Number(node.risk_score || 0)));
  const confidence = Math.max(0, Math.min(100, Number(node.confidence || 0)));
  return 18 + Math.round(score / 20) + Math.round(confidence / 35);
}

// Collapse service nodes into per-agent cluster nodes when there are too many.
// Each cluster retains the highest-risk service's node_key so existing edges resolve naturally.
function collapseServicesIfNeeded(nodes: TopologyLayoutNode[]): TopologyLayoutNode[] {
  const serviceNodes = nodes.filter((n) => n.node_type === "service");
  if (serviceNodes.length <= SERVICE_CLUSTER_THRESHOLD) return nodes;

  const agentYById = new Map<string, number>();
  for (const n of nodes) {
    if ((n.node_type === "agent" || n.node_type === "gateway") && n.agent_id) {
      agentYById.set(n.agent_id, n.y);
    }
  }

  const byAgent = new Map<string, TopologyLayoutNode[]>();
  for (const s of serviceNodes) {
    const key = s.agent_id ?? "__none__";
    const bucket = byAgent.get(key) ?? [];
    bucket.push(s);
    byAgent.set(key, bucket);
  }

  const collapsed = new Set<string>();
  const clusters: TopologyLayoutNode[] = [];

  for (const [agentId, group] of byAgent) {
    for (const s of group) collapsed.add(s.node_key);

    const sorted = [...group].sort(
      (a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0),
    );
    const rep = sorted[0];
    const agentY = agentId !== "__none__" ? agentYById.get(agentId) : undefined;

    const ports = group
      .map((s) => s.port)
      .filter((p): p is number => p != null)
      .sort((a, b) => a - b)
      .filter((p, i, arr) => arr.indexOf(p) === i)
      .slice(0, 6);

    const protocols = [
      ...new Set(group.map((s) => s.protocol).filter((p): p is string => p != null)),
    ].slice(0, 3);

    // Resolve service names for display in canvas chips
    const serviceNames = [
      ...new Set(
        group
          .sort((a, b) => Number(b.event_count || 0) - Number(a.event_count || 0))
          .map((s) => resolveServiceInfo(s.port, s.protocol, s.metadata).name),
      ),
    ].slice(0, 5);

    clusters.push({
      ...rep,
      y: agentY ?? rep.y,
      metadata: {
        ...rep.metadata,
        _is_service_cluster: true,
        _cluster_count: group.length,
        _cluster_ports: ports,
        _cluster_protocols: protocols,
        _cluster_service_names: serviceNames,
      },
    });
  }

  return [...nodes.filter((n) => !collapsed.has(n.node_key)), ...clusters];
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

  const finalNodes = collapseServicesIfNeeded(layoutNodes);
  const nodeByKey = new Map(finalNodes.map((node) => [node.node_key, node]));
  return {
    width: WIDTH,
    height: HEIGHT,
    nodes: finalNodes,
    edges: graph.edges.map((edge) => ({
      ...edge,
      source: nodeByKey.get(edge.source_node_key) ?? null,
      target: nodeByKey.get(edge.target_node_key) ?? null,
    })),
  };
}
