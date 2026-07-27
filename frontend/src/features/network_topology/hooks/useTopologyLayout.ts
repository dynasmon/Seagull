import { useMemo } from "react";

import {
  buildConnectionLayout,
  buildLocationLayout,
  topologyNodeSetKey,
  type TopologyGroupLayoutPoint,
  type TopologyLayout,
} from "../lib/layout/topologyLayout";
import type { TopologyGraph, TopologyGroup, TopologyGroupEdge, TopologyViewMode } from "../types";

type LayoutState = {
  connectionLayout: TopologyLayout | null;
  locationPositions: Map<string, TopologyGroupLayoutPoint> | null;
  topologyKey: string;
};

export function useTopologyLayout(
  graph: TopologyGraph | null,
  groups: TopologyGroup[],
  viewMode: TopologyViewMode,
  focusedGroupKey: string | null,
  pinnedNodeKeys: Set<string> = EMPTY_KEYS,
  groupEdges: TopologyGroupEdge[] = EMPTY_GROUP_EDGES,
): LayoutState {
  const topologyKey = useMemo(() => topologyNodeSetKey(graph), [graph]);

  return useMemo(() => {
    if (!graph) return { connectionLayout: null, locationPositions: null, topologyKey };
    if (viewMode === "location") {
      return {
        connectionLayout: null,
        locationPositions: buildLocationLayout(graph, groups, groupEdges),
        topologyKey,
      };
    }
    return {
      connectionLayout: buildConnectionLayout(graph, groups, focusedGroupKey, pinnedNodeKeys),
      locationPositions: null,
      topologyKey,
    };
  }, [graph, groups, viewMode, focusedGroupKey, pinnedNodeKeys, groupEdges, topologyKey]);
}

const EMPTY_KEYS: Set<string> = new Set();
const EMPTY_GROUP_EDGES: TopologyGroupEdge[] = [];
