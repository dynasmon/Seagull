import type { Edge, Node } from "@xyflow/react";

import type {
  TopologyEdge,
  TopologyGraph,
  TopologyGroup,
  TopologyGroupEdge,
  TopologyNode,
  TopologySeverity,
} from "../../types";
import type { TopologyGroupLayoutPoint, TopologyLayout } from "../layout/topologyLayout";
import { shouldShowLabel, groupCardSize, edgePriorityRank, groupEdgePriorityRank, nodeBoundingRadius } from "../layout/presentation";
import {
  bowAroundObstacles,
  circleAnchor,
  rectAnchor,
  type EdgeAnchorShape,
  type Obstacle,
} from "../layout/edgeAnchors";
import { resolveNodeGroupKeys } from "./grouping";
import { agentAssetAddresses, isAgentAssetNode } from "../presentation/visuals";

const DEVICE_NODE_W = 92;
const DEVICE_NODE_H = 84;

export type DeviceNodeData = Record<string, unknown> & {
  node: TopologyNode;
  isAgentAsset: boolean;
  isSelected: boolean;
  isHighlighted: boolean;
  isDimmed: boolean;
  isSearchMatch: boolean;
  showLabel: boolean;
  importance: "anchor" | "elevated" | "normal";
  groupKey: string | null;
  isNew: boolean;
  isIsolatedGhost?: boolean;
};

export const ISOLATED_GHOST_NODE_ID = "__topology_isolated_ghost__";

export type GroupNodeData = Record<string, unknown> & {
  group: TopologyGroup;
  isSelected: boolean;
  isHighlighted: boolean;
  isDimmed: boolean;
  isCentral: boolean;
  serviceCount: number;
  externalCount: number;
  linkCount: number;
};

export type TopologyGroupStats = {
  serviceCount: number;
  externalCount: number;
};

export function computeGroupStats(
  graph: TopologyGraph | null,
  groups: TopologyGroup[],
): Map<string, TopologyGroupStats> {
  const stats = new Map<string, TopologyGroupStats>(
    groups.map((group) => [group.group_key, { serviceCount: 0, externalCount: 0 }]),
  );
  const assigned = resolveNodeGroupKeys(graph, groups);
  for (const node of graph?.nodes ?? []) {
    const entry = stats.get(assigned.get(node.node_key) ?? "");
    if (!entry) continue;
    if (node.node_type === "service") entry.serviceCount += 1;
    if (node.node_type === "external_ip" || node.metadata?.ip_scope === "public_internet") {
      entry.externalCount += 1;
    }
  }
  return stats;
}

export type TopologyEdgeData = Record<string, unknown> & {
  edge: TopologyEdge;
  isSelected: boolean;
  isDimmed: boolean;
  sourceShape: EdgeAnchorShape;
  targetShape: EdgeAnchorShape;
  parallelIndex: number;
  parallelTotal: number;
  isBidirectional: boolean;
};

export type TopologyGroupEdgeData = Record<string, unknown> & {
  groupEdge: TopologyGroupEdge;
  isSelected: boolean;
  isDimmed: boolean;
  sourceShape: EdgeAnchorShape;
  targetShape: EdgeAnchorShape;
  bow: number;
};

export type TopologyBundle = {
  sourceGroupKey: string;
  targetGroupKey: string;
  sourceLabel: string;
  targetLabel: string;
  typeCounts: Record<string, number>;
  dominantType: string;
  linkCount: number;
  eventCount: number;
  alertCount: number;
  severity: TopologySeverity;
};

export type TopologyBundleEdgeData = Record<string, unknown> & {
  bundle: TopologyBundle;
  isSelected: boolean;
  isDimmed: boolean;
  sourceShape: EdgeAnchorShape;
  targetShape: EdgeAnchorShape;
  bow: number;
};

export const BUNDLE_EDGE_PREFIX = "bundle:";

const BUNDLE_EXEMPT_EDGE_TYPES = new Set(["alert_related", "exposure_related"]);

function severityRank(value: unknown): number {
  return { critical: 5, high: 4, medium: 3, low: 2, informational: 1 }[
    String(value ?? "").toLowerCase()
  ] ?? 0;
}

export type ClusterHaloNodeData = Record<string, unknown> & {
  group: TopologyGroup;
  width: number;
  height: number;
  isCentral: boolean;
  isSelected: boolean;
  isDimmed: boolean;
  drawnCount: number;
};

type SelectionState = {
  selectedKey: string | null;
  selectedKind: "node" | "edge" | "group" | null;
  highlightedKeys: Set<string>;
};

export type TopologySearchState = {
  matchedNodeKeys: Set<string>;
  matchedGroupKeys: Set<string>;
  activeMatchKey: string | null;
};

export type TopologyFocusState = {
  focusedNodeKeys: Set<string>;
};

export function computeHighlightedKeys(
  graph: TopologyGraph | null,
  groups: TopologyGroup[],
  selectedKey: string | null,
  selectedKind: "node" | "edge" | "group" | null,
  groupEdges: TopologyGroupEdge[] = [],
): Set<string> {
  if (!selectedKey || !selectedKind) return new Set();
  const keys = new Set<string>([selectedKey]);
  if (selectedKind === "node" && graph) {
    for (const edge of graph.edges) {
      if (edge.source_node_key === selectedKey) {
        keys.add(edge.target_node_key);
        keys.add(edge.edge_key);
      }
      if (edge.target_node_key === selectedKey) {
        keys.add(edge.source_node_key);
        keys.add(edge.edge_key);
      }
    }
  }
  if (selectedKind === "group") {
    const group = groups.find((g) => g.group_key === selectedKey);
    if (group) {
      for (const nk of group.node_keys) keys.add(nk);
    }
    for (const edge of groupEdges) {
      if (edge.source_group_key === selectedKey) {
        keys.add(edge.edge_key);
        keys.add(edge.target_group_key);
      }
      if (edge.target_group_key === selectedKey) {
        keys.add(edge.edge_key);
        keys.add(edge.source_group_key);
      }
    }
  }
  return keys;
}


export function pruneIsolatedNodes(
  graph: TopologyGraph,
  searchState?: TopologySearchState,
  overrideShowIsolated?: boolean,
): { activeGraph: TopologyGraph; isolatedCount: number } {
  if (overrideShowIsolated) {
    return { activeGraph: graph, isolatedCount: 0 };
  }
  const connectedNodeKeys = new Set<string>();
  for (const edge of graph.edges) {
    connectedNodeKeys.add(edge.source_node_key);
    connectedNodeKeys.add(edge.target_node_key);
  }
  const matched = searchState?.matchedNodeKeys ?? new Set<string>();
  const activeNodes: TopologyNode[] = [];
  let isolatedCount = 0;
  for (const node of graph.nodes) {
    const isActive =
      connectedNodeKeys.has(node.node_key) ||
      node.node_type === "agent" ||
      node.alert_count > 0 ||
      matched.has(node.node_key);
    if (isActive) activeNodes.push(node);
    else isolatedCount += 1;
  }
  return {
    activeGraph: { ...graph, nodes: activeNodes },
    isolatedCount,
  };
}

function makeIsolatedGhostNode(
  isolatedCount: number,
  layout: TopologyLayout,
  isDimmed: boolean,
): Node<DeviceNodeData> {
  const ghostX = Math.max(0, layout.width / 2 - DEVICE_NODE_W / 2);
  const ghostY = layout.height + 56;
  const syntheticNode: TopologyNode = {
    node_key: ISOLATED_GHOST_NODE_ID,
    node_type: "unknown",
    agent_id: null,
    label: `${isolatedCount} nodes with no observed links`,
    ip: null,
    cidr: null,
    port: null,
    protocol: null,
    severity: "informational",
    risk_score: 0,
    confidence: 100,
    is_stale: false,
    event_count: 0,
    alert_count: 0,
    observation_count: 0,
    first_seen_at: "",
    last_seen_at: "",
    updated_at: "",
    metadata: { _isolated_pool: true, _isolated_count: isolatedCount },
  };
  return {
    id: ISOLATED_GHOST_NODE_ID,
    type: "device",
    position: { x: ghostX, y: ghostY },
    data: {
      node: syntheticNode,
      isAgentAsset: false,
      isSelected: false,
      isHighlighted: false,
      isDimmed,
      isSearchMatch: false,
      showLabel: true,
      importance: "normal",
      groupKey: null,
      isNew: false,
      isIsolatedGhost: true,
    },
    selectable: true,
    width: DEVICE_NODE_W,
    height: DEVICE_NODE_H,
    style: { transition: "opacity 180ms ease" },
    zIndex: 1,
  };
}

export function graphToConnectionView(
  graph: TopologyGraph | null,
  layout: TopologyLayout | null,
  selState: SelectionState,
  searchState?: TopologySearchState,
  focusState?: TopologyFocusState,
  newNodeIds?: Set<string>,
  isolatedCount: number = 0,
  expandedBundleKeys: Set<string> = new Set(),
): {
  nodes: Node<DeviceNodeData | ClusterHaloNodeData>[];
  edges: Edge<TopologyEdgeData | TopologyBundleEdgeData>[];
  isolatedCount: number;
} {
  if (!graph || !layout) return { nodes: [], edges: [], isolatedCount };

  const groupNodeCounts = new Map<string, number>();
  for (const ln of layout.nodes) {
    if (ln.group_key) {
      groupNodeCounts.set(ln.group_key, (groupNodeCounts.get(ln.group_key) ?? 0) + 1);
    }
  }
  const hasSelection = selState.selectedKey !== null;
  const hasSearch = Boolean(searchState && searchState.matchedNodeKeys.size > 0);
  const hasFocus = Boolean(focusState && focusState.focusedNodeKeys.size > 0);
  const selfAddresses = agentAssetAddresses(graph.nodes);

  const deviceNodes: Node<DeviceNodeData>[] = layout.nodes.map((ln) => {
    const isSelected = selState.selectedKind === "node" && selState.selectedKey === ln.node_key;
    const isSearchMatch = Boolean(searchState?.matchedNodeKeys.has(ln.node_key));
    const isHighlighted = hasSearch
      ? isSearchMatch
      : selState.highlightedKeys.has(ln.node_key);
    const isDimmed = hasSearch
      ? !isSearchMatch && !isSelected
      : hasFocus
        ? !focusState!.focusedNodeKeys.has(ln.node_key) && !isSelected
        : hasSelection && !isSelected && !isHighlighted;
    return {
      id: ln.node_key,
      type: "device",
      position: { x: ln.x - DEVICE_NODE_W / 2, y: ln.y - DEVICE_NODE_H / 2 },
      data: {
        node: ln,
        isAgentAsset: isAgentAssetNode(ln) || Boolean(ln.ip && selfAddresses.has(ln.ip)),
        isSelected,
        isHighlighted,
        isDimmed,
        isSearchMatch,
        showLabel: shouldShowLabel(ln, isSelected, isSearchMatch, ln.importance, groupNodeCounts.get(ln.group_key ?? "") ?? 0),
        importance: ln.importance,
        groupKey: ln.group_key,
        isNew: newNodeIds?.has(ln.node_key) ?? false,
      },
      selectable: true,
      width: DEVICE_NODE_W,
      height: DEVICE_NODE_H,
      style: { transition: "opacity 180ms ease" },
      zIndex: ln.importance === "anchor" ? 4 : ln.importance === "elevated" ? 3 : 2,
    };
  });

  const haloNodes = layout.areas.map<Node<ClusterHaloNodeData>>((area) => {
    const isSelected = selState.selectedKind === "group" && selState.selectedKey === area.group.group_key;
    const isHighlighted = selState.highlightedKeys.has(area.group.group_key);
    const hasGroupSearchMatch = area.group.node_keys.some((key) => searchState?.matchedNodeKeys.has(key));
    const isDimmed = hasSearch
      ? !hasGroupSearchMatch
      : hasFocus
        ? !area.group.node_keys.some((key) => focusState!.focusedNodeKeys.has(key))
        : hasSelection && !isSelected && !isHighlighted;
    return {
      id: `halo:${area.group.group_key}`,
      type: "clusterHalo",
      position: { x: area.x, y: area.y },
      data: {
        group: area.group,
        width: area.w,
        height: area.h,
        isCentral: area.isCentral,
        isSelected,
        isDimmed,
        drawnCount: groupNodeCounts.get(area.group.group_key) ?? 0,
      },
      width: area.w,
      height: area.h,
      draggable: false,
      selectable: false,
      focusable: false,
      zIndex: 0,
      style: { transition: "opacity 180ms ease" },
    };
  });

  const presentNodeKeys = new Set(layout.nodes.map((n) => n.node_key));

  type LayoutEdge = (typeof layout.edges)[0];
  const directedSet = new Set<string>();
  for (const edge of layout.edges) {
    if (!presentNodeKeys.has(edge.source_node_key) || !presentNodeKeys.has(edge.target_node_key)) continue;
    directedSet.add(`${edge.source_node_key}|${edge.target_node_key}|${edge.edge_type}`);
  }

  const pairTypeMap = new Map<string, Map<string, LayoutEdge[]>>();
  for (const edge of layout.edges) {
    if (!presentNodeKeys.has(edge.source_node_key) || !presentNodeKeys.has(edge.target_node_key)) continue;
    const pairKey =
      edge.source_node_key < edge.target_node_key
        ? `${edge.source_node_key}|${edge.target_node_key}`
        : `${edge.target_node_key}|${edge.source_node_key}`;
    const typeMap = pairTypeMap.get(pairKey) ?? new Map<string, LayoutEdge[]>();
    const typeEdges = typeMap.get(edge.edge_type) ?? [];
    typeEdges.push(edge);
    typeMap.set(edge.edge_type, typeEdges);
    pairTypeMap.set(pairKey, typeMap);
  }

  const pairCountMap = new Map<string, number>();
  for (const [pairKey, typeMap] of pairTypeMap) {
    pairCountMap.set(pairKey, typeMap.size);
  }

  const pairIndexMap = new Map<string, number>();
  const edges: Edge<TopologyEdgeData | TopologyBundleEdgeData>[] = [];
  const processedPairTypes = new Set<string>();

  const groupOfLayoutNode = new Map(
    layout.nodes.filter((node) => node.group_key).map((node) => [node.node_key, node.group_key!]),
  );
  const areaByGroup = new Map(layout.areas.map((area) => [area.group.group_key, area]));
  const groupLabels = new Map(layout.areas.map((area) => [area.group.group_key, area.group.label]));
  const bundles = new Map<string, TopologyBundle>();

  for (const edge of layout.edges) {
    if (!presentNodeKeys.has(edge.source_node_key) || !presentNodeKeys.has(edge.target_node_key)) continue;
    const pairKey =
      edge.source_node_key < edge.target_node_key
        ? `${edge.source_node_key}|${edge.target_node_key}`
        : `${edge.target_node_key}|${edge.source_node_key}`;
    const pairTypeKey = `${pairKey}|${edge.edge_type}`;
    if (processedPairTypes.has(pairTypeKey)) continue;
    processedPairTypes.add(pairTypeKey);

    const typeEdges = pairTypeMap.get(pairKey)?.get(edge.edge_type) ?? [edge];
    const selectedInType = typeEdges.find((candidate) =>
      selState.selectedKind === "edge" && selState.selectedKey === candidate.edge_key,
    );
    const rep = selectedInType ?? typeEdges.reduce((best, candidate) =>
      edgePriorityRank(candidate) > edgePriorityRank(best) ? candidate : best,
    );

    const parallelTotal = pairCountMap.get(pairKey) ?? 1;
    const parallelIndex = pairIndexMap.get(pairKey) ?? 0;
    pairIndexMap.set(pairKey, parallelIndex + 1);

    const isSelected = Boolean(selectedInType);
    const isConnected =
      selState.highlightedKeys.has(rep.source_node_key) ||
      selState.highlightedKeys.has(rep.target_node_key);
    const edgeEndpointMatched = hasSearch
      ? searchState!.matchedNodeKeys.has(rep.source_node_key) ||
        searchState!.matchedNodeKeys.has(rep.target_node_key)
      : false;
    const isDimmed = hasSearch
      ? !edgeEndpointMatched && !isSelected
      : hasFocus
        ? !focusState!.focusedNodeKeys.has(rep.source_node_key) &&
          !focusState!.focusedNodeKeys.has(rep.target_node_key) &&
          !isSelected
        : hasSelection && !isSelected && !isConnected;

    const priority = edgePriorityRank(rep);
    const isBidirectional = directedSet.has(
      `${rep.target_node_key}|${rep.source_node_key}|${rep.edge_type}`,
    );

    const sourceGroup = groupOfLayoutNode.get(rep.source_node_key) ?? null;
    const targetGroup = groupOfLayoutNode.get(rep.target_node_key) ?? null;
    const crossesGroups = Boolean(sourceGroup && targetGroup && sourceGroup !== targetGroup);
    const bundleKey =
      crossesGroups && sourceGroup && targetGroup
        ? sourceGroup < targetGroup
          ? `${sourceGroup}|||${targetGroup}`
          : `${targetGroup}|||${sourceGroup}`
        : null;
    const mustStayVisible =
      isSelected ||
      BUNDLE_EXEMPT_EDGE_TYPES.has(rep.edge_type) ||
      Number(rep.alert_count || 0) > 0 ||
      Boolean(focusState) ||
      (bundleKey ? expandedBundleKeys.has(bundleKey) : false);

    if (bundleKey && !mustStayVisible) {
      const existing = bundles.get(bundleKey);
      const [a, b] = bundleKey.split("|||");
      const entry = existing ?? {
        sourceGroupKey: a,
        targetGroupKey: b,
        sourceLabel: groupLabels.get(a) ?? a,
        targetLabel: groupLabels.get(b) ?? b,
        typeCounts: {} as Record<string, number>,
        dominantType: rep.edge_type,
        linkCount: 0,
        eventCount: 0,
        alertCount: 0,
        severity: "unknown" as TopologySeverity,
      };
      entry.typeCounts[rep.edge_type] = (entry.typeCounts[rep.edge_type] ?? 0) + typeEdges.length;
      entry.linkCount += typeEdges.length;
      entry.eventCount += typeEdges.reduce((sum, item) => sum + Number(item.event_count || 0), 0);
      entry.alertCount += typeEdges.reduce((sum, item) => sum + Number(item.alert_count || 0), 0);
      if (edgePriorityRank(rep) > edgePriorityRank({ edge_type: entry.dominantType, confidence: 100, alert_count: 0 })) {
        entry.dominantType = rep.edge_type;
      }
      if (severityRank(rep.severity) > severityRank(entry.severity)) entry.severity = rep.severity;
      bundles.set(bundleKey, entry);
      continue;
    }

    edges.push({
      id: rep.edge_key,
      source: rep.source_node_key,
      target: rep.target_node_key,
      type: "topology",
      data: {
        edge: rep,
        isSelected,
        isDimmed,
        sourceShape: circleAnchor(nodeBoundingRadius(rep.source?.importance ?? "normal")),
        targetShape: circleAnchor(nodeBoundingRadius(rep.target?.importance ?? "normal")),
        parallelIndex,
        parallelTotal,
        isBidirectional,
      },
      zIndex: isSelected ? 5 : priority >= 80 ? 3 : 0,
    });
  }

  for (const [bundleKey, bundle] of bundles) {
    const sourceArea = areaByGroup.get(bundle.sourceGroupKey);
    const targetArea = areaByGroup.get(bundle.targetGroupKey);
    if (!sourceArea || !targetArea) continue;
    const isDimmed = hasSearch || hasSelection;
    const obstacles: Obstacle[] = layout.areas
      .filter(
        (area) =>
          area.group.group_key !== bundle.sourceGroupKey &&
          area.group.group_key !== bundle.targetGroupKey,
      )
      .map((area) => ({ x: area.x, y: area.y, w: area.w, h: area.h }));
    const bow = bowAroundObstacles(
      { x: sourceArea.x + sourceArea.w / 2, y: sourceArea.y + sourceArea.h / 2 },
      { x: targetArea.x + targetArea.w / 2, y: targetArea.y + targetArea.h / 2 },
      obstacles,
    );
    edges.push({
      id: `${BUNDLE_EDGE_PREFIX}${bundleKey}`,
      source: `halo:${bundle.sourceGroupKey}`,
      target: `halo:${bundle.targetGroupKey}`,
      type: "bundle",
      data: {
        bundle,
        isSelected: false,
        isDimmed,
        sourceShape: rectAnchor(sourceArea.w, sourceArea.h),
        targetShape: rectAnchor(targetArea.w, targetArea.h),
        bow,
      },
      zIndex: 0,
    });
  }

  const allNodes: Node<DeviceNodeData | ClusterHaloNodeData>[] = [...haloNodes, ...deviceNodes];
  if (isolatedCount > 0) {
    allNodes.push(makeIsolatedGhostNode(isolatedCount, layout, hasSelection || hasSearch || hasFocus));
  }
  return { nodes: allNodes, edges, isolatedCount };
}

export function graphToLocationView(
  groups: TopologyGroup[],
  groupEdges: TopologyGroupEdge[],
  positions: Map<string, TopologyGroupLayoutPoint> | null,
  selState: SelectionState,
  searchState?: TopologySearchState,
  groupStats?: Map<string, TopologyGroupStats>,
): { nodes: Node<GroupNodeData>[]; edges: Edge<TopologyGroupEdgeData>[] } {
  if (!positions) return { nodes: [], edges: [] };
  const hasSelection = selState.selectedKey !== null;
  const hasSearch = Boolean(searchState && searchState.matchedGroupKeys.size > 0);

  const linkCounts = new Map<string, number>();
  for (const edge of groupEdges) {
    linkCounts.set(edge.source_group_key, (linkCounts.get(edge.source_group_key) ?? 0) + 1);
    linkCounts.set(edge.target_group_key, (linkCounts.get(edge.target_group_key) ?? 0) + 1);
  }

  const nodes: Node<GroupNodeData>[] = groups.map((group) => {
    const point = positions.get(group.group_key) ?? {
      x: 0,
      y: 0,
      ring: 0,
      degree: 0,
      isCentral: false,
    };
    const isSelected = selState.selectedKind === "group" && selState.selectedKey === group.group_key;
    const isHighlighted = hasSearch
      ? searchState!.matchedGroupKeys.has(group.group_key)
      : selState.highlightedKeys.has(group.group_key);
    const isDimmed = hasSearch
      ? !searchState!.matchedGroupKeys.has(group.group_key) && !isSelected
      : hasSelection && !isSelected && !isHighlighted;
    const { w, h } = groupCardSize(group.label);
    const stats = groupStats?.get(group.group_key);
    return {
      id: group.group_key,
      type: "group",
      position: { x: point.x - w / 2, y: point.y - h / 2 },
      data: {
        group,
        isSelected,
        isHighlighted,
        isDimmed,
        isCentral: point.isCentral,
        serviceCount: stats?.serviceCount ?? 0,
        externalCount: stats?.externalCount ?? 0,
        linkCount: linkCounts.get(group.group_key) ?? 0,
      },
      selectable: true,
      width: w,
      height: h,
      style: { transition: "opacity 180ms ease" },
      zIndex: isSelected ? 4 : point.isCentral ? 3 : 2,
    };
  });

  const groupKeySet = new Set(groups.map((g) => g.group_key));
  const groupLabelByKey = new Map(groups.map((g) => [g.group_key, g.label]));
  const cardObstacles = groups.flatMap((group) => {
    const point = positions.get(group.group_key);
    if (!point) return [];
    const { w, h } = groupCardSize(group.label);
    return [{ key: group.group_key, x: point.x - w / 2, y: point.y - h / 2, w, h }];
  });
  const edges: Edge<TopologyGroupEdgeData>[] = groupEdges
    .filter((ge) => groupKeySet.has(ge.source_group_key) && groupKeySet.has(ge.target_group_key))
    .map((ge) => {
      const isSelected = selState.selectedKind === "edge" && selState.selectedKey === ge.edge_key;
      const isConnected =
        selState.highlightedKeys.has(ge.source_group_key) ||
        selState.highlightedKeys.has(ge.target_group_key);
      const edgeEndpointMatched = hasSearch
        ? searchState!.matchedGroupKeys.has(ge.source_group_key) ||
          searchState!.matchedGroupKeys.has(ge.target_group_key)
        : false;
      const isDimmed = hasSearch
        ? !edgeEndpointMatched && !isSelected
        : hasSelection && !isSelected && !isConnected;
      const priority = groupEdgePriorityRank(ge.alert_count, ge.edge_types as string[]);
      const sourceCard = groupCardSize(groupLabelByKey.get(ge.source_group_key) ?? "");
      const targetCard = groupCardSize(groupLabelByKey.get(ge.target_group_key) ?? "");
      const sourcePoint = positions.get(ge.source_group_key);
      const targetPoint = positions.get(ge.target_group_key);
      const bow =
        sourcePoint && targetPoint
          ? bowAroundObstacles(sourcePoint, targetPoint, cardObstacles.filter(
              (obstacle) =>
                obstacle.key !== ge.source_group_key && obstacle.key !== ge.target_group_key,
            ))
          : 0;
      return {
        id: ge.edge_key,
        source: ge.source_group_key,
        target: ge.target_group_key,
        type: "group",
        data: {
          groupEdge: ge,
          isSelected,
          isDimmed,
          sourceShape: rectAnchor(sourceCard.w, sourceCard.h),
          targetShape: rectAnchor(targetCard.w, targetCard.h),
          bow,
        },
        zIndex: isSelected ? 3 : priority >= 70 ? 2 : 0,
      };
    });

  return { nodes, edges };
}
