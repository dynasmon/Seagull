import { useEffect, useMemo, useState } from "react";

import { useUrlQueryState } from "@/shared/hooks/useUrlQueryState";

import {
  DEFAULT_TOPOLOGY_FILTERS,
  parseTopologyFilters,
  serializeTopologyFilters,
  topologyFilterKey,
} from "../lib/filtering/filters";
import type { TopologyFilters } from "../types";

export function useNetworkTopologyFilters() {
  const [appliedFilters, setAppliedFilters] = useUrlQueryState<TopologyFilters>({
    parse: parseTopologyFilters,
    serialize: serializeTopologyFilters,
    replace: true,
  });
  const [draftFilters, setDraftFilters] = useState<TopologyFilters>(appliedFilters);
  const appliedKey = useMemo(() => topologyFilterKey(appliedFilters), [appliedFilters]);
  const draftKey = useMemo(() => topologyFilterKey(draftFilters), [draftFilters]);

  useEffect(() => {
    setDraftFilters(appliedFilters);
  }, [appliedKey, appliedFilters]);

  return {
    appliedFilters,
    draftFilters,
    setDraftFilters,
    applyFilters: () => setAppliedFilters(draftFilters),
    applyWith: (nextFilters: TopologyFilters) => {
      setDraftFilters(nextFilters);
      setAppliedFilters(nextFilters);
    },
    resetFilters: () => {
      setDraftFilters(DEFAULT_TOPOLOGY_FILTERS);
      setAppliedFilters(DEFAULT_TOPOLOGY_FILTERS);
    },
    isDirty: appliedKey !== draftKey,
    appliedKey,
  };
}
