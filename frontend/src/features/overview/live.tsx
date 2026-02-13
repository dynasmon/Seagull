import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import { getOverview } from "./api";
import type { OverviewSnapshot } from "./types";

const POLL_MS = 5000;
const WINDOW_MINUTES = 60;

type OverviewLiveCtx = {
  snapshot: OverviewSnapshot | null;
  isLoading: boolean;
  error: string | null;
  lastUpdatedAt: Date | null;
  windowMinutes: number;
  refresh: () => Promise<void>;
};

const OverviewLiveContext = createContext<OverviewLiveCtx | null>(null);

export function OverviewLiveProvider({ children }: { children: ReactNode }) {
  const [snapshot, setSnapshot] = useState<OverviewSnapshot | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);

  const inFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;

    try {
      const data = await getOverview({ window_minutes: WINDOW_MINUTES });
      setSnapshot(data);
      setError(null);
      setLastUpdatedAt(new Date());
    } catch (e: any) {
      setError(e?.message || "Failed to load overview");
    } finally {
      setIsLoading(false);
      inFlight.current = false;
    }
  }, []);

  useEffect(() => {
    let alive = true;

    refresh();

    const timer = window.setInterval(() => {
      if (!alive) return;
      refresh();
    }, POLL_MS);

    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [refresh]);

  const value = useMemo<OverviewLiveCtx>(
    () => ({
      snapshot,
      isLoading,
      error,
      lastUpdatedAt,
      windowMinutes: WINDOW_MINUTES,
      refresh
    }),
    [snapshot, isLoading, error, lastUpdatedAt, refresh]
  );

  return <OverviewLiveContext.Provider value={value}>{children}</OverviewLiveContext.Provider>;
}

export function useOverviewLive() {
  const ctx = useContext(OverviewLiveContext);
  if (!ctx) throw new Error("useOverviewLive must be used within OverviewLiveProvider");
  return ctx;
}
