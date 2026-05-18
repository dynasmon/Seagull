import type { TopologyEdge, TopologyGraph, TopologyGroup, TopologyGroupEdge, TopologyNode } from "../types";
import { resolveServiceInfo } from "./services";

export type TopologyNodeImportance = "anchor" | "elevated" | "normal";

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

const WIDTH = 1680;
const HEIGHT = 1040;
const CENTER = { x: WIDTH / 2, y: HEIGHT / 2 };
const SERVICE_CLUSTER_THRESHOLD = 18;

const MIN_SPACING_NORMAL = 96;
const MIN_SPACING_IMPORTANT = 120;
const RING_BASE_RADIUS = 88;
const RING_EXPANSION = 96;
const HALO_MIN_RADIUS = 110;
const HALO_MAX_RADIUS = 360;
const HALO_PADDING = 42;

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
  unknown: 0,
};

export function stableTopologyHash(value: string): number {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function severityWeight(value: unknown): number {
  return SEVERITY_WEIGHT[String(value ?? "").toLowerCase()] ?? 0;
}

function sortedGroupKeys(groups: TopologyGroup[]): string[] {
  return [...groups].map((group) => group.group_key).sort((a, b) => a.localeCompare(b));
}

function groupDegreeMap(groups: TopologyGroup[], groupEdges: TopologyGroupEdge[]): Map<string, number> {
  const degrees = new Map(groups.map((group) => [group.group_key, 0]));
  for (const edge of groupEdges) {
    if (!degrees.has(edge.source_group_key) || !degrees.has(edge.target_group_key)) continue;
    const weight = Math.max(1, Number(edge.weight || 0), Number(edge.event_count || 0));
    degrees.set(edge.source_group_key, (degrees.get(edge.source_group_key) ?? 0) + weight);
    degrees.set(edge.target_group_key, (degrees.get(edge.target_group_key) ?? 0) + weight);
  }
  return degrees;
}

function centralGroup(
  groups: TopologyGroup[],
  groupEdges: TopologyGroupEdge[],
): TopologyGroup | null {
  if (groups.length === 0) return null;
  const degrees = groupDegreeMap(groups, groupEdges);
  return [...groups].sort((a, b) => {
    const degreeDelta = (degrees.get(b.group_key) ?? 0) - (degrees.get(a.group_key) ?? 0);
    if (degreeDelta !== 0) return degreeDelta;
    const nodeDelta = b.node_count - a.node_count;
    if (nodeDelta !== 0) return nodeDelta;
    const alertDelta = b.alert_count - a.alert_count;
    if (alertDelta !== 0) return alertDelta;
    const riskDelta = b.risk_score - a.risk_score;
    if (riskDelta !== 0) return riskDelta;
    return a.group_key.localeCompare(b.group_key);
  })[0];
}

function buildAdjacency(groups: TopologyGroup[], groupEdges: TopologyGroupEdge[]): Map<string, Set<string>> {
  const adjacency = new Map(groups.map((group) => [group.group_key, new Set<string>()]));
  for (const edge of groupEdges) {
    if (!adjacency.has(edge.source_group_key) || !adjacency.has(edge.target_group_key)) continue;
    adjacency.get(edge.source_group_key)?.add(edge.target_group_key);
    adjacency.get(edge.target_group_key)?.add(edge.source_group_key);
  }
  return adjacency;
}

function groupDistances(
  groups: TopologyGroup[],
  groupEdges: TopologyGroupEdge[],
  centerKey: string,
): Map<string, number> {
  const adjacency = buildAdjacency(groups, groupEdges);
  const distances = new Map<string, number>([[centerKey, 0]]);
  const queue = [centerKey];
  while (queue.length > 0) {
    const key = queue.shift() as string;
    const distance = distances.get(key) ?? 0;
    for (const neighbor of adjacency.get(key) ?? []) {
      if (distances.has(neighbor)) continue;
      distances.set(neighbor, distance + 1);
      queue.push(neighbor);
    }
  }
  return distances;
}

export function computeLocationGroupLayout(
  groups: TopologyGroup[],
  groupEdges: TopologyGroupEdge[],
): Map<string, TopologyGroupLayoutPoint> {
  const positions = new Map<string, TopologyGroupLayoutPoint>();
  const centerGroup = centralGroup(groups, groupEdges);
  if (!centerGroup) return positions;

  const degrees = groupDegreeMap(groups, groupEdges);
  const distances = groupDistances(groups, groupEdges, centerGroup.group_key);
  const maxConnectedRing = Math.max(0, ...distances.values());
  const fallbackRing = Math.max(2, maxConnectedRing + 1);
  const byRing = new Map<number, TopologyGroup[]>();

  for (const group of groups) {
    const ring = distances.get(group.group_key) ?? fallbackRing;
    const bucket = byRing.get(ring) ?? [];
    bucket.push(group);
    byRing.set(ring, bucket);
  }

  positions.set(centerGroup.group_key, {
    x: CENTER.x,
    y: CENTER.y,
    ring: 0,
    degree: degrees.get(centerGroup.group_key) ?? 0,
    isCentral: true,
  });

  for (const [ring, ringGroups] of [...byRing.entries()].sort((a, b) => a[0] - b[0])) {
    if (ring === 0) continue;
    const baseRadius = 440 + Math.max(0, ring - 1) * 260;
    const minByCount = Math.ceil((ringGroups.length * 228) / (2 * Math.PI));
    const radius = Math.max(baseRadius, minByCount);
    const ordered = [...ringGroups].sort((a, b) => {
      const degreeDelta = (degrees.get(b.group_key) ?? 0) - (degrees.get(a.group_key) ?? 0);
      if (degreeDelta !== 0) return degreeDelta;
      const nodeDelta = b.node_count - a.node_count;
      if (nodeDelta !== 0) return nodeDelta;
      const alertDelta = b.alert_count - a.alert_count;
      if (alertDelta !== 0) return alertDelta;
      return a.group_key.localeCompare(b.group_key);
    });
    const startAngle = -Math.PI / 2 + ((stableTopologyHash(`${centerGroup.group_key}:${ring}`) % 19) / 19) * 0.45;
    ordered.forEach((group, index) => {
      const angle = startAngle + (index / ordered.length) * Math.PI * 2;
      positions.set(group.group_key, {
        x: Math.round(CENTER.x + Math.cos(angle) * radius),
        y: Math.round(CENTER.y + Math.sin(angle) * radius * 0.78),
        ring,
        degree: degrees.get(group.group_key) ?? 0,
        isCentral: false,
      });
    });
  }

  for (const key of sortedGroupKeys(groups)) {
    if (positions.has(key)) continue;
    positions.set(key, {
      x: CENTER.x,
      y: CENTER.y,
      ring: fallbackRing,
      degree: degrees.get(key) ?? 0,
      isCentral: false,
    });
  }

  return positions;
}

function nodeIsPublic(node: TopologyNode): boolean {
  return node.node_type === "external_ip" || String(node.metadata?.ip_scope ?? "").toLowerCase() === "public_internet";
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

function minSpacingForImportance(importance: TopologyNodeImportance): number {
  return importance === "normal" ? MIN_SPACING_NORMAL : MIN_SPACING_IMPORTANT;
}

function nodeMinSpacing(node: TopologyNode): number {
  return minSpacingForImportance(nodeImportance(node));
}

function sliceMinSpacing(nodes: TopologyNode[]): number {
  return nodes.reduce((max, n) => Math.max(max, nodeMinSpacing(n)), MIN_SPACING_NORMAL);
}

function ringCapacity(radius: number, minSpacing: number): number {
  return Math.max(1, Math.floor((2 * Math.PI * radius) / minSpacing));
}

function nodePriority(node: TopologyNode): number {
  const importance = nodeImportance(node);
  const base = importance === "anchor" ? 3000 : importance === "elevated" ? 2000 : 1000;
  const publicPenalty = nodeIsPublic(node) ? -2000 : 0;
  return base + Number(node.alert_count || 0) * 12 + Number(node.risk_score || 0) + publicPenalty;
}

function buildExplicitNodeGroupMap(groups: TopologyGroup[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const group of groups) {
    for (const nodeKey of group.node_keys) map.set(nodeKey, group.group_key);
  }
  return map;
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

function serviceOwnerMap(nodes: TopologyNode[], edges: TopologyEdge[]): Map<string, string> {
  const nodeByKey = new Map(nodes.map((node) => [node.node_key, node]));
  const owners = new Map<string, string>();
  for (const edge of edges) {
    const source = nodeByKey.get(edge.source_node_key);
    const target = nodeByKey.get(edge.target_node_key);
    if (!source || !target) continue;
    if (source.node_type === "service" && target.node_type !== "service") owners.set(source.node_key, target.node_key);
    if (target.node_type === "service" && source.node_type !== "service") owners.set(target.node_key, source.node_key);
  }
  return owners;
}

function collapseServicesIfNeeded(nodes: TopologyNode[], edges: TopologyEdge[]): TopologyNode[] {
  const services = nodes.filter((node) => node.node_type === "service");
  if (services.length <= SERVICE_CLUSTER_THRESHOLD) return nodes;

  const owners = serviceOwnerMap(nodes, edges);
  const byOwner = new Map<string, TopologyNode[]>();
  for (const service of services) {
    const owner = owners.get(service.node_key) ?? (service.agent_id ? `agent:${service.agent_id}` : "__none__");
    const bucket = byOwner.get(owner) ?? [];
    bucket.push(service);
    byOwner.set(owner, bucket);
  }

  const collapsed = new Set<string>();
  const clusters: TopologyNode[] = [];
  for (const [ownerKey, bucket] of byOwner) {
    for (const service of bucket) collapsed.add(service.node_key);
    const ordered = [...bucket].sort((a, b) => {
      const riskDelta = Number(b.risk_score || 0) - Number(a.risk_score || 0);
      if (riskDelta !== 0) return riskDelta;
      return a.node_key.localeCompare(b.node_key);
    });
    const representative = ordered[0];
    const ports = [...new Set(bucket.map((service) => service.port).filter((port): port is number => port != null))]
      .sort((a, b) => a - b)
      .slice(0, 6);
    const protocols = [...new Set(bucket.map((service) => service.protocol).filter((protocol): protocol is string => protocol != null))]
      .sort()
      .slice(0, 3);
    const serviceNames = [...new Set(
      bucket
        .sort((a, b) => Number(b.event_count || 0) - Number(a.event_count || 0))
        .map((service) => resolveServiceInfo(service.port, service.protocol, service.metadata).name),
    )].slice(0, 5);
    clusters.push({
      ...representative,
      metadata: {
        ...representative.metadata,
        _is_service_cluster: true,
        _cluster_count: bucket.length,
        _cluster_ports: ports,
        _cluster_protocols: protocols,
        _cluster_service_names: serviceNames,
        _cluster_owner_node_key: ownerKey.startsWith("agent:") || ownerKey === "__none__" ? null : ownerKey,
      },
    });
  }

  return [...nodes.filter((node) => !collapsed.has(node.node_key)), ...clusters];
}

function relaxGroupCollisions(
  placements: TopologyLayoutNode[],
  center: { x: number; y: number },
): TopologyLayoutNode[] {
  if (placements.length < 2) return placements;
  const MAX_ITER = 8;
  const MAX_PUSH = 12;
  const maxBound = HALO_MAX_RADIUS - HALO_PADDING;
  const result = placements.map((n) => ({ ...n }));

  for (let iter = 0; iter < MAX_ITER; iter++) {
    let moved = false;
    for (let i = 0; i < result.length; i++) {
      for (let j = i + 1; j < result.length; j++) {
        const a = result[i];
        const b = result[j];
        const minDist = Math.max(minSpacingForImportance(a.importance), minSpacingForImportance(b.importance));
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist >= minDist || dist < 0.01) continue;
        const push = Math.min(MAX_PUSH, (minDist - dist) / 2);
        const nx = dist > 0.01 ? dx / dist : 1;
        const ny = dist > 0.01 ? dy / dist : 0;
        if (a.importance !== "anchor") {
          const ax2 = Math.round(a.x - nx * push);
          const ay2 = Math.round(a.y - ny * push);
          if (Math.hypot(ax2 - center.x, ay2 - center.y) <= maxBound) {
            result[i] = { ...a, x: ax2, y: ay2 };
            moved = true;
          }
        }
        if (b.importance !== "anchor") {
          const bx2 = Math.round(b.x + nx * push);
          const by2 = Math.round(b.y + ny * push);
          if (Math.hypot(bx2 - center.x, by2 - center.y) <= maxBound) {
            result[j] = { ...b, x: bx2, y: by2 };
            moved = true;
          }
        }
      }
    }
    if (!moved) break;
  }

  return result;
}

function placeAroundCenter(
  groupKey: string,
  members: TopologyNode[],
  center: { x: number; y: number },
  groupType: TopologyGroup["group_type"],
): TopologyLayoutNode[] {
  const anchor = members.find((node) => groupType === "subnet" && node.node_type === "subnet")
    ?? members.find((node) => node.node_type === "agent")
    ?? members.find((node) => node.node_type === "gateway")
    ?? null;

  const placements: TopologyLayoutNode[] = [];
  if (anchor) {
    placements.push({
      ...anchor,
      x: center.x,
      y: center.y,
      radius: nodeRadius(anchor),
      group_key: groupKey,
      importance: nodeImportance(anchor),
    });
  }

  const remaining = members
    .filter((node) => node.node_key !== anchor?.node_key)
    .sort((a, b) => {
      const priorityDelta = nodePriority(b) - nodePriority(a);
      if (priorityDelta !== 0) return priorityDelta;
      const hashDelta = stableTopologyHash(a.node_key) - stableTopologyHash(b.node_key);
      if (hashDelta !== 0) return hashDelta;
      return a.node_key.localeCompare(b.node_key);
    });

  const publicNodes = remaining.filter(nodeIsPublic);
  const regularNodes = remaining.filter((node) => !nodeIsPublic(node));

  function placeRingNodes(nodes: TopologyNode[], initialRing: number): number {
    let cursor = 0;
    let ring = initialRing;
    while (cursor < nodes.length) {
      const radius = RING_BASE_RADIUS + Math.max(0, ring - 1) * RING_EXPANSION;
      const estimatedCapacity = ringCapacity(radius, MIN_SPACING_NORMAL);
      const candidates = nodes.slice(cursor, cursor + estimatedCapacity);
      const minSpacing = sliceMinSpacing(candidates);
      const capacity = ringCapacity(radius, minSpacing);
      const slice = nodes.slice(cursor, cursor + capacity);
      const startAngle = ((stableTopologyHash(`${groupKey}:${ring}`) % 360) / 360) * Math.PI * 2;
      slice.forEach((node, index) => {
        const angle = startAngle + (index / Math.max(1, slice.length)) * Math.PI * 2;
        placements.push({
          ...node,
          x: Math.round(center.x + Math.cos(angle) * radius),
          y: Math.round(center.y + Math.sin(angle) * radius),
          radius: nodeRadius(node),
          group_key: groupKey,
          importance: nodeImportance(node),
        });
      });
      cursor += slice.length;
      ring += 1;
    }
    return ring;
  }

  const nextRing = placeRingNodes(regularNodes, anchor ? 1 : 0);
  placeRingNodes(publicNodes, Math.max(nextRing, 2));

  return placements;
}

function placeServicesNearOwners(
  placements: TopologyLayoutNode[],
  members: TopologyNode[],
  edges: TopologyEdge[],
  groupKey: string,
): TopologyLayoutNode[] {
  const memberByKey = new Map(members.map((node) => [node.node_key, node]));
  const owners = serviceOwnerMap(members, edges);
  const placementByKey = new Map(placements.map((node) => [node.node_key, node]));
  const servicesByOwner = new Map<string, TopologyNode[]>();

  for (const member of members) {
    if (member.node_type !== "service") continue;
    const ownerKey = String(member.metadata?._cluster_owner_node_key ?? owners.get(member.node_key) ?? "");
    if (!ownerKey || !memberByKey.has(ownerKey) || !placementByKey.has(ownerKey)) continue;
    const bucket = servicesByOwner.get(ownerKey) ?? [];
    bucket.push(member);
    servicesByOwner.set(ownerKey, bucket);
  }

  if (servicesByOwner.size === 0) return placements;

  const next = placements.filter((node) => node.node_type !== "service" || !servicesByOwner.has(String(node.metadata?._cluster_owner_node_key ?? owners.get(node.node_key) ?? "")));
  for (const [ownerKey, services] of servicesByOwner) {
    const owner = placementByKey.get(ownerKey);
    if (!owner) continue;
    const ordered = [...services].sort((a, b) => a.node_key.localeCompare(b.node_key));
    let svcCursor = 0;
    let svcRing = 0;
    while (svcCursor < ordered.length) {
      const svcRadius = owner.radius + 30 + svcRing * MIN_SPACING_NORMAL;
      const capacity = ringCapacity(svcRadius, MIN_SPACING_NORMAL);
      const slice = ordered.slice(svcCursor, svcCursor + capacity);
      const startAngle = ((stableTopologyHash(`${groupKey}:${ownerKey}:svc:${svcRing}`) % 360) / 360) * Math.PI * 2;
      slice.forEach((service, index) => {
        const angle = startAngle + (index / Math.max(1, slice.length)) * Math.PI * 2;
        next.push({
          ...service,
          x: Math.round(owner.x + Math.cos(angle) * svcRadius),
          y: Math.round(owner.y + Math.sin(angle) * svcRadius),
          radius: nodeRadius(service),
          group_key: groupKey,
          importance: nodeImportance(service),
        });
      });
      svcCursor += slice.length;
      svcRing += 1;
    }
  }
  return next;
}

function layoutUngroupedNodes(nodes: TopologyNode[]): TopologyLayoutNode[] {
  const ordered = [...nodes].sort((a, b) => a.node_key.localeCompare(b.node_key));
  return ordered.map((node, index) => {
    const angle = ((stableTopologyHash(node.node_key) % 360) / 360) * Math.PI * 2;
    const radius = 420 + Math.floor(index / 24) * 42;
    return {
      ...node,
      x: Math.round(CENTER.x + Math.cos(angle) * radius),
      y: Math.round(CENTER.y + Math.sin(angle) * radius * 0.82),
      radius: nodeRadius(node),
      group_key: null,
      importance: nodeImportance(node),
    };
  });
}

export function computeTopologyLayout(
  graph: TopologyGraph | null,
  groups: TopologyGroup[] = [],
  groupEdges: TopologyGroupEdge[] = [],
): TopologyLayout {
  if (!graph || graph.nodes.length === 0) {
    return { width: WIDTH, height: HEIGHT, nodes: [], edges: [], areas: [] };
  }

  const collapsedNodes = collapseServicesIfNeeded(graph.nodes, graph.edges);
  const explicitGroupByNode = buildExplicitNodeGroupMap(groups);
  const membersByGroup = new Map<string, TopologyNode[]>();
  const ungrouped: TopologyNode[] = [];

  for (const node of collapsedNodes) {
    const groupKey = resolveNodeGroupKey(node, groups, explicitGroupByNode);
    if (!groupKey) {
      ungrouped.push(node);
      continue;
    }
    const bucket = membersByGroup.get(groupKey) ?? [];
    bucket.push(node);
    membersByGroup.set(groupKey, bucket);
  }

  const groupPositions = computeLocationGroupLayout(groups, groupEdges);
  const layoutNodes: TopologyLayoutNode[] = [];
  const areas: TopologyLayoutArea[] = [];

  for (const group of groups) {
    const members = membersByGroup.get(group.group_key) ?? [];
    const point = groupPositions.get(group.group_key);
    if (!point) continue;
    const placed = relaxGroupCollisions(
      placeServicesNearOwners(
        placeAroundCenter(group.group_key, members, point, group.group_type),
        members,
        graph.edges,
        group.group_key,
      ),
      point,
    );
    layoutNodes.push(...placed);
    const maxDistance = placed.reduce((max, node) => {
      const dx = node.x - point.x;
      const dy = node.y - point.y;
      return Math.max(max, Math.sqrt(dx * dx + dy * dy) + node.radius);
    }, 0);
    const smallGroup = members.length < 5;
    const padding = smallGroup ? 24 : HALO_PADDING;
    const haloMin = smallGroup ? 72 : HALO_MIN_RADIUS;
    areas.push({
      group,
      x: point.x,
      y: point.y,
      radius: Math.max(haloMin, Math.min(HALO_MAX_RADIUS, maxDistance + padding)),
      ring: point.ring,
      degree: point.degree,
      isCentral: point.isCentral,
    });
  }

  layoutNodes.push(...layoutUngroupedNodes(ungrouped));

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
    areas,
  };
}
