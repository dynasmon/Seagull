import { useMemo } from "react";

import {
  buildConnectionLayout,
  buildLocationLayout,
  topologyNodeSetKey,
  type TopologyGroupLayoutPoint,
  type TopologyLayout,
} from "../lib/topologyLayout";
import type { TopologyGraph, TopologyGroup, TopologyViewMode } from "../types";

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
): LayoutState {
  const topologyKey = useMemo(() => topologyNodeSetKey(graph), [graph]);

  return useMemo(() => {
    if (!graph) return { connectionLayout: null, locationPositions: null, topologyKey };
    if (viewMode === "location") {
      return { connectionLayout: null, locationPositions: buildLocationLayout(graph, groups), topologyKey };
    }
    return {
      connectionLayout: buildConnectionLayout(graph, groups, focusedGroupKey),
      locationPositions: null,
      topologyKey,
    };
  }, [graph, groups, viewMode, focusedGroupKey, topologyKey]);
}
