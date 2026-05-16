import type { Edge, Node } from "@xyflow/react";

import type { TopologyEdge, TopologyGraph, TopologyGroup, TopologyGroupEdge, TopologyNode } from "../types";
import { computeTopologyLayout } from "./layout";

const DEVICE_NODE_W = 80;
const DEVICE_NODE_H = 60;
const GROUP_NODE_W = 168;
const GROUP_NODE_H = 88;

export type DeviceNodeData = Record<string, unknown> & {
  node: TopologyNode;
  isSelected: boolean;
  isHighlighted: boolean;
  isDimmed: boolean;
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
};

export type TopologyGroupEdgeData = Record<string, unknown> & {
  groupEdge: TopologyGroupEdge;
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
  }
  return keys;
}

export function graphToConnectionView(
  graph: TopologyGraph | null,
  selState: SelectionState,
  searchState?: TopologySearchState,
  focusState?: TopologyFocusState,
): { nodes: Node<DeviceNodeData>[]; edges: Edge<TopologyEdgeData>[] } {
  if (!graph) return { nodes: [], edges: [] };

  const layout = computeTopologyLayout(graph);
  const hasSelection = selState.selectedKey !== null;
  const hasSearch = Boolean(searchState && searchState.matchedNodeKeys.size > 0);
  const hasFocus = Boolean(focusState && focusState.focusedNodeKeys.size > 0);

  const nodes: Node<DeviceNodeData>[] = layout.nodes.map((ln) => {
    const isSelected = selState.selectedKind === "node" && selState.selectedKey === ln.node_key;
    const isHighlighted = hasSearch
      ? searchState!.matchedNodeKeys.has(ln.node_key)
      : selState.highlightedKeys.has(ln.node_key);
    const isDimmed = hasSearch
      ? !searchState!.matchedNodeKeys.has(ln.node_key) && !isSelected
      : hasFocus
        ? !focusState!.focusedNodeKeys.has(ln.node_key) && !isSelected
        : hasSelection && !isSelected && !isHighlighted;
    return {
      id: ln.node_key,
      type: "device",
      position: { x: ln.x - DEVICE_NODE_W / 2, y: ln.y - DEVICE_NODE_H / 2 },
      data: { node: ln, isSelected, isHighlighted, isDimmed },
      selectable: true,
      draggable: false,
      width: DEVICE_NODE_W,
      height: DEVICE_NODE_H,
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
    edges.push({
      id: edge.edge_key,
      source: edge.source_node_key,
      target: edge.target_node_key,
      type: "topology",
      data: { edge, isSelected, isDimmed },
    });
  }

  return { nodes, edges };
}

function computeGroupLayout(groups: TopologyGroup[]): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();
  if (groups.length === 0) return positions;

  const sorted = [...groups].sort((a, b) => {
    const alertDelta = b.alert_count - a.alert_count;
    if (alertDelta !== 0) return alertDelta;
    return b.node_count - a.node_count;
  });

  if (sorted.length === 1) {
    positions.set(sorted[0].group_key, { x: 600 - GROUP_NODE_W / 2, y: 380 - GROUP_NODE_H / 2 });
    return positions;
  }

  const CX = 600;
  const CY = 370;
  const R = Math.min(280, 100 + sorted.length * 30);

  sorted.forEach((g, idx) => {
    if (idx === 0) {
      positions.set(g.group_key, { x: CX - GROUP_NODE_W / 2, y: CY - R * 0.2 - GROUP_NODE_H / 2 });
    } else {
      const angle = ((idx - 1) / (sorted.length - 1)) * 2 * Math.PI - Math.PI / 2;
      positions.set(g.group_key, {
        x: Math.round(CX + R * Math.cos(angle)) - GROUP_NODE_W / 2,
        y: Math.round(CY + R * Math.sin(angle) * 0.75) - GROUP_NODE_H / 2,
      });
    }
  });

  return positions;
}

export function graphToLocationView(
  groups: TopologyGroup[],
  groupEdges: TopologyGroupEdge[],
  selState: SelectionState,
  searchState?: TopologySearchState,
): { nodes: Node<GroupNodeData>[]; edges: Edge<TopologyGroupEdgeData>[] } {
  const positions = computeGroupLayout(groups);
  const hasSelection = selState.selectedKey !== null;
  const hasSearch = Boolean(searchState && searchState.matchedGroupKeys.size > 0);

  const nodes: Node<GroupNodeData>[] = groups.map((group) => {
    const pos = positions.get(group.group_key) ?? { x: 0, y: 0 };
    const isSelected = selState.selectedKind === "group" && selState.selectedKey === group.group_key;
    const isHighlighted = hasSearch
      ? searchState!.matchedGroupKeys.has(group.group_key)
      : selState.highlightedKeys.has(group.group_key);
    const isDimmed = hasSearch
      ? !searchState!.matchedGroupKeys.has(group.group_key) && !isSelected
      : hasSelection && !isSelected && !isHighlighted;
    return {
      id: group.group_key,
      type: "group",
      position: pos,
      data: { group, isSelected, isHighlighted, isDimmed },
      selectable: true,
      draggable: false,
      width: GROUP_NODE_W,
      height: GROUP_NODE_H,
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
      const isDimmed = hasSelection && !isSelected && !isConnected;
      return {
        id: ge.edge_key,
        source: ge.source_group_key,
        target: ge.target_group_key,
        type: "group",
        data: { groupEdge: ge, isSelected, isDimmed },
      };
    });

  return { nodes, edges };
}
