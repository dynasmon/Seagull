import { useCallback, useState } from "react";

export type TopologySelectionKind = "node" | "edge" | "group";

export type TopologySelection = {
  kind: TopologySelectionKind;
  key: string;
} | null;

export function useTopologyWorkspaceState() {
  const [filterRailOpen, setFilterRailOpen] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchMatchIndex, setSearchMatchIndex] = useState(0);
  const [selection, setSelection] = useState<TopologySelection>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [focusedGroupKey, setFocusedGroupKey] = useState<string | null>(null);

  const clearSelection = useCallback(() => setSelection(null), []);

  const selectNode = useCallback((key: string) => {
    setSelection({ kind: "node", key });
  }, []);

  const selectEdge = useCallback((key: string) => {
    setSelection({ kind: "edge", key });
  }, []);

  const selectGroup = useCallback((key: string) => {
    setSelection({ kind: "group", key });
  }, []);

  const nextSearchMatch = useCallback((total: number) => {
    setSearchMatchIndex((prev) => (total > 0 ? (prev + 1) % total : 0));
  }, []);

  const prevSearchMatch = useCallback((total: number) => {
    setSearchMatchIndex((prev) => (total > 0 ? (prev - 1 + total) % total : 0));
  }, []);

  const toggleFullscreen = useCallback(() => setIsFullscreen((prev) => !prev), []);

  const clearFocusedGroup = useCallback(() => setFocusedGroupKey(null), []);

  return {
    filterRailOpen,
    setFilterRailOpen,
    searchQuery,
    setSearchQuery,
    searchMatchIndex,
    setSearchMatchIndex,
    nextSearchMatch,
    prevSearchMatch,
    selection,
    setSelection,
    clearSelection,
    selectNode,
    selectEdge,
    selectGroup,
    isFullscreen,
    toggleFullscreen,
    focusedGroupKey,
    setFocusedGroupKey,
    clearFocusedGroup,
  };
}
