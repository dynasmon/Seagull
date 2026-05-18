import type { Edge, Node } from "@xyflow/react";

import type { TopologyEdge, TopologyGraph, TopologyGroup, TopologyGroupEdge, TopologyNode } from "../types";
import { groupTopologyGraph } from "./grouping";
import { computeTopologyLayout, computeLocationGroupLayout } from "./topologyLayoutEngine";
import { shouldShowLabel, groupCardSize, edgePriorityRank, groupEdgePriorityRank, nodeBoundingRadius } from "./presentation";

const DEVICE_NODE_W = 80;
const DEVICE_NODE_H = 80;

export type DeviceNodeData = Record<string, unknown> & {
  node: TopologyNode;
  isSelected: boolean;
  isHighlighted: boolean;
  isDimmed: boolean;
  isSearchMatch: boolean;
  showLabel: boolean;
  importance: "anchor" | "elevated" | "normal";
  groupKey: string | null;
};

export type GroupNodeData = Record<string, unknown> & {
  group: TopologyGroup;
  isSelected: boolean;
  isHighlighted: boolean;
  isDimmed: boolean;
};

export type TopologyEdgeData = Record<string, unknown> & {
  edge: TopologyEdge;
  isSelected: boolean;
  isDimmed: boolean;
  sourceRadius: number;
  targetRadius: number;
};

export type TopologyGroupEdgeData = Record<string, unknown> & {
  groupEdge: TopologyGroupEdge;
  isSelected: boolean;
  isDimmed: boolean;
};

export type ClusterHaloNodeData = Record<string, unknown> & {
  group: TopologyGroup;
  radius: number;
  isSelected: boolean;
  isDimmed: boolean;
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


export function graphToConnectionView(
  graph: TopologyGraph | null,
  selState: SelectionState,
  searchState?: TopologySearchState,
  focusState?: TopologyFocusState,
  inputGroups: TopologyGroup[] = [],
  inputGroupEdges: TopologyGroupEdge[] = [],
): { nodes: Node<DeviceNodeData | ClusterHaloNodeData>[]; edges: Edge<TopologyEdgeData>[] } {
  if (!graph) return { nodes: [], edges: [] };

  const fallbackGrouping = inputGroups.length === 0 ? groupTopologyGraph(graph) : null;
  const groups = inputGroups.length > 0 ? inputGroups : fallbackGrouping?.groups ?? [];
  const groupEdges = inputGroupEdges.length > 0 ? inputGroupEdges : fallbackGrouping?.edges ?? [];
  const layout = computeTopologyLayout(graph, groups, groupEdges);
  const groupNodeCounts = new Map<string, number>();
  for (const ln of layout.nodes) {
    if (ln.group_key) {
      groupNodeCounts.set(ln.group_key, (groupNodeCounts.get(ln.group_key) ?? 0) + 1);
    }
  }
  const hasSelection = selState.selectedKey !== null;
  const hasSearch = Boolean(searchState && searchState.matchedNodeKeys.size > 0);
  const hasFocus = Boolean(focusState && focusState.focusedNodeKeys.size > 0);

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
        isSelected,
        isHighlighted,
        isDimmed,
        isSearchMatch,
        showLabel: shouldShowLabel(ln, isSelected, isSearchMatch, ln.importance, groupNodeCounts.get(ln.group_key ?? "") ?? 0),
        importance: ln.importance,
        groupKey: ln.group_key,
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
      position: { x: area.x - area.radius, y: area.y - area.radius },
      data: { group: area.group, radius: area.radius, isSelected, isDimmed },
      width: area.radius * 2,
      height: area.radius * 2,
      draggable: false,
      selectable: false,
      focusable: false,
      zIndex: 0,
      style: { transition: "opacity 180ms ease" },
    };
  });

  const presentNodeKeys = new Set(layout.nodes.map((n) => n.node_key));
  const edges: Edge<TopologyEdgeData>[] = [];
  for (const edge of layout.edges) {
    if (!presentNodeKeys.has(edge.source_node_key) || !presentNodeKeys.has(edge.target_node_key)) continue;
    const isSelected = selState.selectedKind === "edge" && selState.selectedKey === edge.edge_key;
    const isConnected =
      selState.highlightedKeys.has(edge.source_node_key) ||
      selState.highlightedKeys.has(edge.target_node_key);
    const edgeEndpointMatched = hasSearch
      ? searchState!.matchedNodeKeys.has(edge.source_node_key) ||
        searchState!.matchedNodeKeys.has(edge.target_node_key)
      : false;
    const isDimmed = hasSearch
      ? !edgeEndpointMatched && !isSelected
      : hasFocus
        ? !focusState!.focusedNodeKeys.has(edge.source_node_key) &&
          !focusState!.focusedNodeKeys.has(edge.target_node_key) &&
          !isSelected
        : hasSelection && !isSelected && !isConnected;
    const priority = edgePriorityRank(edge);
    edges.push({
      id: edge.edge_key,
      source: edge.source_node_key,
      target: edge.target_node_key,
      type: "topology",
      data: {
        edge,
        isSelected,
        isDimmed,
        sourceRadius: nodeBoundingRadius(edge.source?.importance ?? "normal"),
        targetRadius: nodeBoundingRadius(edge.target?.importance ?? "normal"),
      },
      zIndex: isSelected ? 5 : priority >= 80 ? 3 : priority >= 30 ? 2 : 1,
    });
  }

  return { nodes: [...haloNodes, ...deviceNodes], edges };
}

export function graphToLocationView(
  groups: TopologyGroup[],
  groupEdges: TopologyGroupEdge[],
  selState: SelectionState,
  searchState?: TopologySearchState,
): { nodes: Node<GroupNodeData>[]; edges: Edge<TopologyGroupEdgeData>[] } {
  const positions = computeLocationGroupLayout(groups, groupEdges);
  const hasSelection = selState.selectedKey !== null;
  const hasSearch = Boolean(searchState && searchState.matchedGroupKeys.size > 0);

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
    return {
      id: group.group_key,
      type: "group",
      position: { x: point.x - w / 2, y: point.y - h / 2 },
      data: { group, isSelected, isHighlighted, isDimmed },
      selectable: true,
      width: w,
      height: h,
      style: { transition: "opacity 180ms ease" },
      zIndex: isSelected ? 4 : point.isCentral ? 3 : 2,
    };
  });

  const groupKeySet = new Set(groups.map((g) => g.group_key));
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
      return {
        id: ge.edge_key,
        source: ge.source_group_key,
        target: ge.target_group_key,
        type: "group",
        data: { groupEdge: ge, isSelected, isDimmed },
        zIndex: isSelected ? 3 : priority >= 70 ? 2 : 1,
      };
    });

  return { nodes, edges };
}
