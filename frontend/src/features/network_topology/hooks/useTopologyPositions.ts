import { useCallback, useState } from "react";

import type { TopologyViewMode } from "../types";

type PositionMap = Record<string, { x: number; y: number }>;

function storageKey(viewMode: TopologyViewMode): string {
  return `seagull:topology:positions:${viewMode}`;
}

function readPositions(viewMode: TopologyViewMode): PositionMap {
  try {
    const raw = localStorage.getItem(storageKey(viewMode));
    return raw ? (JSON.parse(raw) as PositionMap) : {};
  } catch {
    return {};
  }
}

export function useTopologyPositions(viewMode: TopologyViewMode) {
  // Keyed by viewMode so switching views is synchronous — no useEffect needed.
  const [posMap, setPosMap] = useState<Partial<Record<string, PositionMap>>>(() => ({
    [viewMode]: readPositions(viewMode),
  }));

  // Read from cache; fall back to localStorage synchronously on first access for a mode.
  const positions: PositionMap = posMap[viewMode] ?? readPositions(viewMode);

  const setPosition = useCallback(
    (nodeId: string, x: number, y: number) => {
      setPosMap((prev) => {
        const current = prev[viewMode] ?? {};
        const next = { ...current, [nodeId]: { x, y } };
        try { localStorage.setItem(storageKey(viewMode), JSON.stringify(next)); } catch {}
        return { ...prev, [viewMode]: next };
      });
    },
    [viewMode],
  );

  const resetPositions = useCallback(() => {
    setPosMap((prev) => ({ ...prev, [viewMode]: {} }));
    try { localStorage.removeItem(storageKey(viewMode)); } catch {}
  }, [viewMode]);

  return {
    positions,
    setPosition,
    resetPositions,
    hasCustomPositions: Object.keys(positions).length > 0,
  };
}
