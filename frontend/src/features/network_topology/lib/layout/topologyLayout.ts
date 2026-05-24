import type {
  TopologyEdge,
  TopologyGraph,
  TopologyGroup,
  TopologyNode,
} from "../../types";
import {
  arrangeGroupCluster,
  classifyGroupMembers,
  placeRegionsOrbital,
  type ClusterMember,
  type ClusterSatellite,
  type RegionInput,
} from "./layoutContainment";
import { groupCardSize } from "./presentation";
import type { TopologyNodeImportance } from "./presentation";

export type { TopologyNodeImportance };

export const AGGREGATE_NODE_PREFIX = "__agg__:";
const UNASSIGNED_GROUP_KEY = "__unassigned__";

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
  w: number;
  h: number;
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

function resolveAnchorGroupKey(graph: TopologyGraph, groups: TopologyGroup[]): string | null {
  const anchor = findLocalAnchor(graph.nodes);
  if (!anchor) return null;
  for (const group of groups) {
    if (group.node_keys.includes(anchor.node_key)) return group.group_key;
  }
  if (anchor.agent_id) {
    const byAgent = groups.find((group) => group.agent_id && group.agent_id === anchor.agent_id);
    if (byAgent) return byAgent.group_key;
  }
  return null;
}

function groupPriority(group: Pick<TopologyGroup, "alert_count" | "risk_score" | "node_count">): number {
  return (group.alert_count || 0) * 1000 + Math.round(Number(group.risk_score || 0)) * 4 + group.node_count;
}

const ANCHOR_TYPE_RANK: Record<string, number> = { agent: 0, gateway: 1, subnet: 2 };

function pickHub(members: TopologyNode[]): TopologyNode {
  const anchors = members.filter((node) => nodeImportance(node) === "anchor");
  const pool = anchors.length > 0 ? anchors : members;
  return pool.reduce((best, node) => {
    const bestRank = ANCHOR_TYPE_RANK[best.node_type] ?? 9;
    const nodeRank = ANCHOR_TYPE_RANK[node.node_type] ?? 9;
    if (nodeRank !== bestRank) return nodeRank < bestRank ? node : best;
    const byEvents = Number(node.event_count || 0) - Number(best.event_count || 0);
    if (byEvents !== 0) return byEvents > 0 ? node : best;
    const byRisk = Number(node.risk_score || 0) - Number(best.risk_score || 0);
    if (byRisk !== 0) return byRisk > 0 ? node : best;
    return node.node_key < best.node_key ? node : best;
  });
}

function relationshipImportantKeys(edges: TopologyEdge[]): Set<string> {
  const keys = new Set<string>();
  for (const edge of edges) {
    if (edge.edge_type === "alert_related" || edge.edge_type === "exposure_related") {
      keys.add(edge.source_node_key);
      keys.add(edge.target_node_key);
    }
  }
  return keys;
}

function synthesizeUnassignedGroup(orphans: TopologyNode[]): TopologyGroup {
  return {
    group_key: UNASSIGNED_GROUP_KEY,
    group_type: "ungrouped",
    label: "Unassigned",
    node_keys: orphans.map((node) => node.node_key),
    node_count: orphans.length,
    alert_count: orphans.reduce((sum, node) => sum + node.alert_count, 0),
    highest_severity: "unknown",
    risk_score: Math.max(0, ...orphans.map((node) => Number(node.risk_score || 0))),
    is_stale: orphans.length > 0 && orphans.every((node) => node.is_stale),
    agent_id: null,
    cidr: null,
  };
}

function dominantNodeType(nodes: TopologyNode[]): string {
  const counts = new Map<string, number>();
  for (const node of nodes) counts.set(node.node_type, (counts.get(node.node_type) ?? 0) + 1);
  let best = "host";
  let bestCount = -1;
  for (const [type, count] of counts) {
    if (count > bestCount) {
      best = type;
      bestCount = count;
    }
  }
  return best;
}

function makeAggregateNode(groupKey: string, hidden: TopologyNode[]): TopologyNode {
  const count = hidden.length;
  const alertSum = hidden.reduce((sum, node) => sum + node.alert_count, 0);
  return {
    node_key: `${AGGREGATE_NODE_PREFIX}${groupKey}`,
    node_type: dominantNodeType(hidden),
    agent_id: hidden.find((node) => node.agent_id)?.agent_id ?? null,
    label: `+${count}`,
    ip: null,
    cidr: null,
    port: null,
    protocol: null,
    severity: "informational",
    risk_score: 0,
    confidence: 100,
    is_stale: hidden.every((node) => node.is_stale),
    event_count: 0,
    alert_count: alertSum,
    observation_count: 0,
    first_seen_at: "",
    last_seen_at: "",
    updated_at: "",
    metadata: {
      _aggregate: true,
      _aggregate_count: count,
      _aggregate_group: groupKey,
    },
  };
}

export function buildConnectionLayout(
  graph: TopologyGraph,
  groups: TopologyGroup[],
  focusedGroupKey: string | null = null,
): TopologyLayout {
  if (graph.nodes.length === 0) return emptyLayout();

  const presentByKey = new Map(graph.nodes.map((node) => [node.node_key, node]));
  const groupOfNode = new Map<string, string>();
  for (const group of groups) {
    for (const key of group.node_keys) {
      if (presentByKey.has(key) && !groupOfNode.has(key)) groupOfNode.set(key, group.group_key);
    }
  }

  const membersByGroup = new Map<string, TopologyNode[]>();
  const orphans: TopologyNode[] = [];
  for (const node of graph.nodes) {
    const groupKey = groupOfNode.get(node.node_key);
    if (!groupKey) {
      orphans.push(node);
      continue;
    }
    const list = membersByGroup.get(groupKey);
    if (list) list.push(node);
    else membersByGroup.set(groupKey, [node]);
  }

  const groupByKey = new Map(groups.map((group) => [group.group_key, group]));
  if (orphans.length > 0) {
    membersByGroup.set(UNASSIGNED_GROUP_KEY, orphans);
    groupByKey.set(UNASSIGNED_GROUP_KEY, synthesizeUnassignedGroup(orphans));
  }

  const anchorGroupKey = resolveAnchorGroupKey(graph, groups);
  const relationshipKeys = relationshipImportantKeys(graph.edges);

  const regionInputs: RegionInput[] = [];
  const layoutNodesByGroup = new Map<string, TopologyLayoutNode[]>();
  const shownKeys = new Set<string>();

  for (const [groupKey, members] of membersByGroup) {
    const group = groupByKey.get(groupKey);
    if (!group || members.length === 0) continue;

    const hub = pickHub(members);
    const clusterMembers: ClusterMember[] = members.map((node) => ({
      key: node.node_key,
      importance: nodeImportance(node),
      risk_score: Number(node.risk_score || 0),
      alert_count: Number(node.alert_count || 0),
      alwaysShow:
        node.node_key === hub.node_key ||
        nodeImportance(node) !== "normal" ||
        node.alert_count > 0 ||
        relationshipKeys.has(node.node_key),
    }));

    const expanded = focusedGroupKey === groupKey;
    const classified = classifyGroupMembers(clusterMembers, expanded);

    const shownMembers = members.filter((node) => classified.shownKeys.has(node.node_key));
    const hiddenMembers = members.filter((node) => !classified.shownKeys.has(node.node_key));
    const aggregateNode = hiddenMembers.length > 0 ? makeAggregateNode(groupKey, hiddenMembers) : null;

    const satellites: ClusterSatellite[] = shownMembers
      .filter((node) => node.node_key !== hub.node_key)
      .map((node) => ({
        key: node.node_key,
        importance: nodeImportance(node),
        risk_score: Number(node.risk_score || 0),
        alert_count: Number(node.alert_count || 0),
        isAggregate: false,
      }));
    if (aggregateNode) {
      satellites.push({
        key: aggregateNode.node_key,
        importance: "normal",
        risk_score: 0,
        alert_count: aggregateNode.alert_count,
        isAggregate: true,
      });
    }

    const arrangement = arrangeGroupCluster(hub.node_key, satellites, group.label);
    regionInputs.push({
      key: groupKey,
      width: arrangement.width,
      height: arrangement.height,
      isCentral: groupKey === anchorGroupKey,
      priority: groupPriority(group),
    });

    const renderNodes = aggregateNode ? [...shownMembers, aggregateNode] : shownMembers;
    const layoutNodes: TopologyLayoutNode[] = renderNodes.map((node) => {
      const local = arrangement.centers.get(node.node_key) ?? { x: arrangement.width / 2, y: arrangement.height / 2 };
      shownKeys.add(node.node_key);
      return {
        ...node,
        x: Math.round(local.x),
        y: Math.round(local.y),
        radius: nodeRadius(node),
        group_key: groupKey,
        importance: nodeImportance(node),
      };
    });
    layoutNodesByGroup.set(groupKey, layoutNodes);
  }

  if (regionInputs.length === 0) return emptyLayout();

  const placement = placeRegionsOrbital(regionInputs);

  const layoutNodes: TopologyLayoutNode[] = [];
  const nodeByKey = new Map<string, TopologyLayoutNode>();
  for (const [groupKey, groupNodes] of layoutNodesByGroup) {
    const origin = placement.origins.get(groupKey);
    if (!origin) continue;
    for (const node of groupNodes) {
      const placed: TopologyLayoutNode = { ...node, x: Math.round(origin.x + node.x), y: Math.round(origin.y + node.y) };
      layoutNodes.push(placed);
      nodeByKey.set(placed.node_key, placed);
    }
  }

  const areas: TopologyLayoutArea[] = [];
  for (const input of regionInputs) {
    const origin = placement.origins.get(input.key);
    const group = groupByKey.get(input.key);
    if (!origin || !group) continue;
    areas.push({ group, x: origin.x, y: origin.y, w: input.width, h: input.height, isCentral: input.isCentral });
  }

  const layoutEdges: TopologyLayoutEdge[] = [];
  for (const edge of graph.edges) {
    if (!shownKeys.has(edge.source_node_key) || !shownKeys.has(edge.target_node_key)) continue;
    layoutEdges.push({
      ...edge,
      source: nodeByKey.get(edge.source_node_key) ?? null,
      target: nodeByKey.get(edge.target_node_key) ?? null,
    });
  }

  return {
    width: Math.max(960, Math.round(placement.width)),
    height: Math.max(640, Math.round(placement.height)),
    nodes: layoutNodes,
    edges: layoutEdges,
    areas,
  };
}

export function buildLocationLayout(
  graph: TopologyGraph | null,
  groups: TopologyGroup[],
): Map<string, TopologyGroupLayoutPoint> {
  const positions = new Map<string, TopologyGroupLayoutPoint>();
  if (groups.length === 0) return positions;
  const anchorGroupKey = graph ? resolveAnchorGroupKey(graph, groups) : null;

  const regionInputs: RegionInput[] = groups.map((group) => {
    const { w, h } = groupCardSize(group.label);
    return {
      key: group.group_key,
      width: w,
      height: h,
      isCentral: group.group_key === anchorGroupKey,
      priority: groupPriority(group),
    };
  });

  const placement = placeRegionsOrbital(regionInputs);
  for (const group of groups) {
    const origin = placement.origins.get(group.group_key);
    if (!origin) continue;
    const { w, h } = groupCardSize(group.label);
    positions.set(group.group_key, {
      x: Math.round(origin.x + w / 2),
      y: Math.round(origin.y + h / 2),
      ring: 0,
      degree: 0,
      isCentral: group.group_key === anchorGroupKey,
    });
  }
  return positions;
}

function emptyLayout(): TopologyLayout {
  return { width: 1680, height: 1040, nodes: [], edges: [], areas: [] };
}

export function topologyNodeSetKey(graph: TopologyGraph | null): string {
  if (!graph) return "";
  return graph.nodes
    .map((n) => n.node_key)
    .sort()
    .join("|");
}
