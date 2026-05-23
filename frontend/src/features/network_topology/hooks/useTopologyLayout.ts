import { useEffect, useMemo, useRef, useState } from "react";

import {
  createElkLayoutHandle,
  topologyNodeSetKey,
  type ElkLayoutHandle,
  type TopologyGroupLayoutPoint,
  type TopologyLayout,
} from "../lib/topologyLayoutELK";
import type {
  TopologyGraph,
  TopologyGroup,
  TopologyGroupEdge,
  TopologyViewMode,
} from "../types";

type LayoutState = {
  connectionLayout: TopologyLayout | null;
  locationPositions: Map<string, TopologyGroupLayoutPoint> | null;
  topologyKey: string;
};

const EMPTY_STATE: LayoutState = {
  connectionLayout: null,
  locationPositions: null,
  topologyKey: "",
};

export function useTopologyLayout(
  graph: TopologyGraph | null,
  groups: TopologyGroup[],
  groupEdges: TopologyGroupEdge[],
  viewMode: TopologyViewMode,
): LayoutState {
  const handleRef = useRef<ElkLayoutHandle | null>(null);
  const [state, setState] = useState<LayoutState>(EMPTY_STATE);
  const seqRef = useRef(0);

  useEffect(() => {
    const handle = createElkLayoutHandle();
    handleRef.current = handle;
    return () => {
      handleRef.current = null;
      handle.terminate();
    };
  }, []);

  const topologyKey = useMemo(() => topologyNodeSetKey(graph), [graph]);
  const groupKey = useMemo(
    () => groups.map((g) => g.group_key).sort().join("|"),
    [groups],
  );
  const groupEdgeKey = useMemo(
    () => groupEdges.map((e) => e.edge_key).sort().join("|"),
    [groupEdges],
  );

  useEffect(() => {
    const handle = handleRef.current;
    if (!handle || !graph) {
      setState({ connectionLayout: null, locationPositions: null, topologyKey });
      return;
    }
    const seq = ++seqRef.current;
    let cancelled = false;
    void handle
      .computeLayout(graph, groups, groupEdges, viewMode)
      .then((result) => {
        if (cancelled || seq !== seqRef.current) return;
        setState({
          connectionLayout: result.connectionLayout,
          locationPositions: result.locationPositions,
          topologyKey,
        });
      })
      .catch(() => {
        if (cancelled || seq !== seqRef.current) return;
        setState({ connectionLayout: null, locationPositions: null, topologyKey });
      });
    return () => {
      cancelled = true;
    };
  }, [graph, groups, groupEdges, viewMode, topologyKey, groupKey, groupEdgeKey]);

  return state;
}
