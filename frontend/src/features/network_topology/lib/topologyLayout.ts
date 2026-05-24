import ElkConstructor from "elkjs/lib/elk-api.js";
import type { ELK, ElkExtendedEdge, ElkNode } from "elkjs/lib/elk-api.js";
import elkWorkerUrl from "elkjs/lib/elk-worker.min.js?url";

import type {
  TopologyEdge,
  TopologyGraph,
  TopologyGroup,
  TopologyGroupEdge,
  TopologyNode,
  TopologyViewMode,
} from "../types";
import { groupCardSize } from "./presentation";
import type { TopologyNodeImportance } from "./presentation";

export type { TopologyNodeImportance };

export type TopologyLayoutNode = TopologyNode & {
  x: number;
  y: number;
  radius: number;
  group_key: string | null;
  importance: TopologyNodeImportance;
};

export type TopologyLayoutEdge = TopologyEdge & {
  source: TopologyLayoutNode | null;
  target: TopologyLayoutNode | null;
};

export type TopologyLayoutArea = {
  group: TopologyGroup;
  x: number;
  y: number;
  radius: number;
  ring: number;
  degree: number;
  isCentral: boolean;
};

export type TopologyLayout = {
  width: number;
  height: number;
  nodes: TopologyLayoutNode[];
  edges: TopologyLayoutEdge[];
  areas: TopologyLayoutArea[];
};

export type TopologyGroupLayoutPoint = {
  x: number;
  y: number;
  ring: number;
  degree: number;
  isCentral: boolean;
};

const DEVICE_NODE_SIZE = 96;
const HALO_PADDING = 42;
const HALO_MIN_RADIUS = 110;
const HALO_MAX_RADIUS = 360;

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
  unknown: 0,
};

function severityWeight(value: unknown): number {
  return SEVERITY_WEIGHT[String(value ?? "").toLowerCase()] ?? 0;
}

export function nodeImportance(node: TopologyNode): TopologyNodeImportance {
  if (node.node_type === "agent" || node.node_type === "gateway" || node.node_type === "subnet") return "anchor";
  if (node.alert_count > 0 || severityWeight(node.severity) >= 4 || Number(node.risk_score || 0) >= 70) return "elevated";
  return "normal";
}

function nodeRadius(node: TopologyNode): number {
  const importance = nodeImportance(node);
  if (importance === "anchor") return 13;
  if (importance === "elevated") return 10;
  return 7;
}

export function findLocalAnchor(nodes: TopologyNode[]): TopologyNode | null {
  let best: TopologyNode | null = null;
  for (const node of nodes) {
    if (node.node_type !== "agent" || node.is_stale) continue;
    if (!best || Number(node.event_count || 0) > Number(best.event_count || 0)) best = node;
  }
  return best;
}

function buildExplicitNodeGroupMap(groups: TopologyGroup[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const group of groups) {
    for (const nodeKey of group.node_keys) map.set(nodeKey, group.group_key);
  }
  return map;
}

const STRESS_LAYOUT_OPTIONS: Record<string, string> = {
  "elk.algorithm": "stress",
  "elk.direction": "UNDEFINED",
  "elk.stress.desiredEdgeLength": "180",
  "elk.spacing.nodeNode": "80",
  "elk.padding": "[top=60,left=60,bottom=60,right=60]",
  "elk.edgeRouting": "SPLINES",
  "elk.overlapRemoval": "true",
};

const MRTREE_LAYOUT_OPTIONS: Record<string, string> = {
  "elk.algorithm": "org.eclipse.elk.mrtree",
  "elk.direction": "DOWN",
  "elk.spacing.nodeNode": "80",
  "elk.padding": "[top=60,left=60,bottom=60,right=60]",
  "elk.edgeRouting": "SPLINES",
  "elk.overlapRemoval": "true",
};

function buildConnectionInput(
  graph: TopologyGraph,
  anchorKey: string | null,
): ElkNode {
  const nodeIds = new Set(graph.nodes.map((n) => n.node_key));
  const elkNodes: ElkNode[] = graph.nodes.map((node) => {
    const isAnchor = anchorKey !== null && node.node_key === anchorKey;
    const opts: Record<string, string> = {};
    if (isAnchor) opts["elk.stress.origin"] = "true";
    const base: ElkNode = {
      id: node.node_key,
      width: DEVICE_NODE_SIZE,
      height: DEVICE_NODE_SIZE,
      layoutOptions: Object.keys(opts).length > 0 ? opts : undefined,
    };
    if (isAnchor) {
      base.x = 0;
      base.y = 0;
    }
    return base;
  });

  if (anchorKey && nodeIds.has(anchorKey)) {
    const idx = elkNodes.findIndex((n) => n.id === anchorKey);
    if (idx > 0) {
      const [anchor] = elkNodes.splice(idx, 1);
      elkNodes.unshift(anchor);
    }
  }

  const elkEdges: ElkExtendedEdge[] = [];
  for (const edge of graph.edges) {
    if (!nodeIds.has(edge.source_node_key) || !nodeIds.has(edge.target_node_key)) continue;
    elkEdges.push({
      id: edge.edge_key,
      sources: [edge.source_node_key],
      targets: [edge.target_node_key],
    });
  }

  return {
    id: "root",
    layoutOptions: STRESS_LAYOUT_OPTIONS,
    children: elkNodes,
    edges: elkEdges,
  };
}

function buildLocationInput(
  groups: TopologyGroup[],
  groupEdges: TopologyGroupEdge[],
  anchorGroupKey: string | null,
): ElkNode {
  const groupIds = new Set(groups.map((g) => g.group_key));
  const ordered = [...groups];
  if (anchorGroupKey) {
    const idx = ordered.findIndex((g) => g.group_key === anchorGroupKey);
    if (idx > 0) {
      const [anchor] = ordered.splice(idx, 1);
      ordered.unshift(anchor);
    }
  }

  const elkNodes: ElkNode[] = ordered.map((group) => {
    const { w, h } = groupCardSize(group.label);
    return { id: group.group_key, width: w, height: h };
  });

  const elkEdges: ElkExtendedEdge[] = [];
  for (const edge of groupEdges) {
    if (!groupIds.has(edge.source_group_key) || !groupIds.has(edge.target_group_key)) continue;
    elkEdges.push({
      id: edge.edge_key,
      sources: [edge.source_group_key],
      targets: [edge.target_group_key],
    });
  }

  return {
    id: "root",
    layoutOptions: MRTREE_LAYOUT_OPTIONS,
    children: elkNodes,
    edges: elkEdges,
  };
}

function resolveNodeGroupKey(
  node: TopologyNode,
  groups: TopologyGroup[],
  explicitGroupByNode: Map<string, string>,
): string | null {
  const explicit = explicitGroupByNode.get(node.node_key);
  if (explicit) return explicit;
  if (node.agent_id) {
    const byAgent = groups.find((group) => group.agent_id && group.agent_id === node.agent_id);
    if (byAgent) return byAgent.group_key;
  }
  if (node.cidr) {
    const byCidr = groups.find((group) => group.cidr && group.cidr === node.cidr);
    if (byCidr) return byCidr.group_key;
  }
  const scope = String(node.metadata?.ip_scope ?? "").toLowerCase();
  if (scope) {
    const byScope = groups.find((group) => group.group_key === `scope:${scope}` || group.group_key === `ip_scope:${scope}`);
    if (byScope) return byScope.group_key;
  }
  return null;
}

function buildAreas(
  groups: TopologyGroup[],
  nodeByKey: Map<string, TopologyLayoutNode>,
  anchorGroupKey: string | null,
): TopologyLayoutArea[] {
  const areas: TopologyLayoutArea[] = [];
  for (const group of groups) {
    const members = group.node_keys
      .map((key) => nodeByKey.get(key))
      .filter((n): n is TopologyLayoutNode => Boolean(n));
    if (members.length === 0) continue;
    const cx = members.reduce((s, n) => s + n.x, 0) / members.length;
    const cy = members.reduce((s, n) => s + n.y, 0) / members.length;
    const maxDist = members.reduce(
      (max, n) => Math.max(max, Math.hypot(n.x - cx, n.y - cy) + n.radius),
      0,
    );
    const smallGroup = members.length < 5;
    const padding = smallGroup ? 24 : HALO_PADDING;
    const haloMin = smallGroup ? 72 : HALO_MIN_RADIUS;
    areas.push({
      group,
      x: cx,
      y: cy,
      radius: Math.max(haloMin, Math.min(HALO_MAX_RADIUS, maxDist + padding)),
      ring: 0,
      degree: 0,
      isCentral: group.group_key === anchorGroupKey,
    });
  }
  return areas;
}

function emptyLayout(): TopologyLayout {
  return { width: 1680, height: 1040, nodes: [], edges: [], areas: [] };
}

export type ElkLayoutHandle = {
  computeLayout: (
    graph: TopologyGraph | null,
    groups: TopologyGroup[],
    groupEdges: TopologyGroupEdge[],
    viewMode: TopologyViewMode,
  ) => Promise<{
    connectionLayout: TopologyLayout;
    locationPositions: Map<string, TopologyGroupLayoutPoint>;
  }>;
  terminate: () => void;
};

export function createElkLayoutHandle(): ElkLayoutHandle {
  const elk: ELK = new ElkConstructor({
    workerFactory: () => new Worker(elkWorkerUrl),
  });

  async function computeConnectionLayout(
    graph: TopologyGraph,
    groups: TopologyGroup[],
    anchorKey: string | null,
  ): Promise<TopologyLayout> {
    if (graph.nodes.length === 0) return emptyLayout();
    const input = buildConnectionInput(graph, anchorKey);
    const result = await elk.layout(input);
    const positions = new Map<string, { x: number; y: number }>();
    for (const child of result.children ?? []) {
      const cx = (child.x ?? 0) + (child.width ?? DEVICE_NODE_SIZE) / 2;
      const cy = (child.y ?? 0) + (child.height ?? DEVICE_NODE_SIZE) / 2;
      positions.set(child.id, { x: Math.round(cx), y: Math.round(cy) });
    }
    const explicitGroupByNode = buildExplicitNodeGroupMap(groups);
    const layoutNodes: TopologyLayoutNode[] = graph.nodes.map((node) => {
      const pos = positions.get(node.node_key) ?? { x: 0, y: 0 };
      return {
        ...node,
        x: pos.x,
        y: pos.y,
        radius: nodeRadius(node),
        group_key: resolveNodeGroupKey(node, groups, explicitGroupByNode),
        importance: nodeImportance(node),
      };
    });
    const nodeByKey = new Map(layoutNodes.map((n) => [n.node_key, n]));
    const anchorNode = anchorKey ? nodeByKey.get(anchorKey) : null;
    const anchorGroupKey = anchorNode?.group_key ?? null;
    const areas = buildAreas(groups, nodeByKey, anchorGroupKey);
    const layoutEdges: TopologyLayoutEdge[] = graph.edges.map((edge) => ({
      ...edge,
      source: nodeByKey.get(edge.source_node_key) ?? null,
      target: nodeByKey.get(edge.target_node_key) ?? null,
    }));
    const width = Math.round(result.width ?? 1680);
    const height = Math.round(result.height ?? 1040);
    return { width, height, nodes: layoutNodes, edges: layoutEdges, areas };
  }

  async function computeLocationPositions(
    groups: TopologyGroup[],
    groupEdges: TopologyGroupEdge[],
    anchorGroupKey: string | null,
  ): Promise<Map<string, TopologyGroupLayoutPoint>> {
    if (groups.length === 0) return new Map();
    const input = buildLocationInput(groups, groupEdges, anchorGroupKey);
    const result = await elk.layout(input);
    const positions = new Map<string, TopologyGroupLayoutPoint>();
    for (const child of result.children ?? []) {
      const cx = (child.x ?? 0) + (child.width ?? 200) / 2;
      const cy = (child.y ?? 0) + (child.height ?? 60) / 2;
      positions.set(child.id, {
        x: Math.round(cx),
        y: Math.round(cy),
        ring: 0,
        degree: 0,
        isCentral: child.id === anchorGroupKey,
      });
    }
    return positions;
  }

  async function computeLayout(
    graph: TopologyGraph | null,
    groups: TopologyGroup[],
    groupEdges: TopologyGroupEdge[],
    viewMode: TopologyViewMode,
  ) {
    if (!graph || graph.nodes.length === 0) {
      return { connectionLayout: emptyLayout(), locationPositions: new Map() };
    }
    const anchor = findLocalAnchor(graph.nodes);
    const anchorKey = anchor?.node_key ?? null;
    const explicitMap = buildExplicitNodeGroupMap(groups);
    const anchorGroupKey = anchor
      ? resolveNodeGroupKey(anchor, groups, explicitMap)
      : null;

    if (viewMode === "location") {
      const locationPositions = await computeLocationPositions(groups, groupEdges, anchorGroupKey);
      return { connectionLayout: emptyLayout(), locationPositions };
    }
    const connectionLayout = await computeConnectionLayout(graph, groups, anchorKey);
    return { connectionLayout, locationPositions: new Map() };
  }

  return {
    computeLayout,
    terminate: () => elk.terminateWorker(),
  };
}

export function topologyNodeSetKey(graph: TopologyGraph | null): string {
  if (!graph) return "";
  return graph.nodes
    .map((n) => n.node_key)
    .sort()
    .join("|");
}
