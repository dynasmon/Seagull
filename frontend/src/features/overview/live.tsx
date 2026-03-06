import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import { getOverview } from "./api";
import type { OverviewSnapshot } from "./types";

const POLL_MS = 5000;
const WINDOW_MINUTES = 60;
const SNAPSHOT_CACHE_KEY = "nw_overview_snapshot_v1";
const FULL_REFRESH_MS = 15000;

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
  const [snapshot, setSnapshot] = useState<OverviewSnapshot | null>(() => {
    try {
      const raw = sessionStorage.getItem(SNAPSHOT_CACHE_KEY);
      if (!raw) return null;
      return JSON.parse(raw) as OverviewSnapshot;
    } catch {
      return null;
    }
  });
  const [isLoading, setIsLoading] = useState(() => {
    try {
      return !Boolean(sessionStorage.getItem(SNAPSHOT_CACHE_KEY));
    } catch {
      return true;
    }
  });
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);

  const inFlight = useRef(false);
  const snapshotRef = useRef<OverviewSnapshot | null>(snapshot);
  const lastFullAtRef = useRef(0);

  useEffect(() => {
    snapshotRef.current = snapshot;
  }, [snapshot]);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;

    try {
      const fast = await getOverview({ window_minutes: WINDOW_MINUTES, lite: true });
      const prev = snapshotRef.current;
      const mergedFast: OverviewSnapshot = {
        ...fast,
        ports: prev?.ports ?? fast.ports,
        top_sources: prev?.top_sources ?? fast.top_sources,
        recent_alerts: prev?.recent_alerts ?? fast.recent_alerts,
        ddos_alerts: prev?.ddos_alerts ?? fast.ddos_alerts,
        recent_ssh: prev?.recent_ssh ?? fast.recent_ssh,
        raw_events: prev?.raw_events ?? fast.raw_events,
      };
      setSnapshot(mergedFast);
      setError(null);
      setLastUpdatedAt(new Date());

      const needFull = !snapshotRef.current || (Date.now() - lastFullAtRef.current) >= FULL_REFRESH_MS;
      if (needFull) {
        const full = await getOverview({ window_minutes: WINDOW_MINUTES });
        setSnapshot(full);
        lastFullAtRef.current = Date.now();
        try {
          sessionStorage.setItem(SNAPSHOT_CACHE_KEY, JSON.stringify(full));
        } catch {
          // no-op: cache is best-effort
        }
      } else {
        try {
          sessionStorage.setItem(SNAPSHOT_CACHE_KEY, JSON.stringify(mergedFast));
        } catch {
          // no-op: cache is best-effort
        }
      }
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
