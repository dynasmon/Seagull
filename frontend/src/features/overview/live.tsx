import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import { usePortalRealtime, usePortalRealtimeSubscription } from "@/shared/realtime";
import type { RealtimeConnectionStatus } from "@/shared/realtime";
import { isAbortError } from "@/shared/lib/http";

import { getOverview, getStormStatus } from "./api";
import {
  applyOverviewRealtimeAlertsDelta,
  applyOverviewRealtimePatch,
  mergeStormStatus,
  nextRealtimeInvalidationDelayMs,
} from "./live_realtime";
import type { OverviewSnapshot, StormStatus } from "./types";

const FALLBACK_POLL_MS = 5000;
const REALTIME_BASELINE_POLL_MS = 45000;
const WINDOW_MINUTES = 60;
const SNAPSHOT_CACHE_KEY = "nw_overview_snapshot_v1";
const FULL_REFRESH_MS = 15000;
const FULL_REFRESH_TIMEOUT_MS = 6000;
const INVALIDATE_MIN_REFRESH_MS = 2500;
const INVALIDATE_DEBOUNCE_MS = 300;
const STORM_FALLBACK_POLL_MS = 3000;
const STORM_BASELINE_POLL_MS = 15000;

type OverviewLiveCtx = {
  snapshot: OverviewSnapshot | null;
  storm: StormStatus | null;
  realtimeStatus: RealtimeConnectionStatus;
  isLoading: boolean;
  error: string | null;
  lastUpdatedAt: Date | null;
  windowMinutes: number;
  refresh: () => Promise<void>;
};

const OverviewLiveContext = createContext<OverviewLiveCtx | null>(null);

export function OverviewLiveProvider({ children }: { children: ReactNode }) {
  const { status: realtimeStatus } = usePortalRealtime();

  const [snapshot, setSnapshot] = useState<OverviewSnapshot | null>(() => {
    try {
      const raw = sessionStorage.getItem(SNAPSHOT_CACHE_KEY);
      if (!raw) return null;
      return JSON.parse(raw) as OverviewSnapshot;
    } catch {
      return null;
    }
  });
  const [storm, setStorm] = useState<StormStatus | null>(null);
  const [isLoading, setIsLoading] = useState(() => {
    try {
      return !Boolean(sessionStorage.getItem(SNAPSHOT_CACHE_KEY));
    } catch {
      return true;
    }
  });
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);

  const snapshotRef = useRef<OverviewSnapshot | null>(snapshot);
  const stormRef = useRef<StormStatus | null>(storm);
  const lastFullAtRef = useRef(0);
  const refreshSeqRef = useRef(0);
  const fastAbortRef = useRef<AbortController | null>(null);
  const fullAbortRef = useRef<AbortController | null>(null);
  const fullPendingRef = useRef(false);
  const lastRefreshAtRef = useRef(0);
  const invalidateTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    snapshotRef.current = snapshot;
  }, [snapshot]);

  useEffect(() => {
    stormRef.current = storm;
  }, [storm]);

  const refresh = useCallback(async () => {
    const mySeq = ++refreshSeqRef.current;
    lastRefreshAtRef.current = Date.now();

    fastAbortRef.current?.abort();
    const fastController = new AbortController();
    fastAbortRef.current = fastController;

    try {
      const fast = await getOverview(
        { window_minutes: WINDOW_MINUTES, lite: true },
        { signal: fastController.signal, timeoutMs: FULL_REFRESH_TIMEOUT_MS },
      );
      if (refreshSeqRef.current !== mySeq) return;
      const prevEnd = Date.parse(snapshotRef.current?.meta?.window_end || "");
      const nextFastEnd = Date.parse(fast?.meta?.window_end || "");
      if (Number.isFinite(prevEnd) && Number.isFinite(nextFastEnd) && nextFastEnd < prevEnd) {
        return;
      }

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
      try {
        sessionStorage.setItem(SNAPSHOT_CACHE_KEY, JSON.stringify(mergedFast));
      } catch {
        // no-op: cache is best-effort
      }

      const needFull = !snapshotRef.current || (Date.now() - lastFullAtRef.current) >= FULL_REFRESH_MS;
      if (needFull && !fullPendingRef.current) {
        fullPendingRef.current = true;
        const fullController = new AbortController();
        fullAbortRef.current = fullController;

        void getOverview(
          { window_minutes: WINDOW_MINUTES },
          { signal: fullController.signal, timeoutMs: FULL_REFRESH_TIMEOUT_MS },
        )
          .then((full) => {
            if (refreshSeqRef.current !== mySeq) return;
            const currentEnd = Date.parse(snapshotRef.current?.meta?.window_end || "");
            const incomingEnd = Date.parse(full?.meta?.window_end || "");
            if (Number.isFinite(currentEnd) && Number.isFinite(incomingEnd) && incomingEnd < currentEnd) {
              return;
            }
            setSnapshot(full);
            lastFullAtRef.current = Date.now();
            try {
              sessionStorage.setItem(SNAPSHOT_CACHE_KEY, JSON.stringify(full));
            } catch {
              // no-op
            }
          })
          .catch((e: unknown) => {
            if (isAbortError(e)) return;
          })
          .finally(() => {
            if (fullAbortRef.current === fullController) {
              fullAbortRef.current = null;
            }
            fullPendingRef.current = false;
          });
      }
    } catch (e: unknown) {
      if (isAbortError(e)) return;
      if (refreshSeqRef.current !== mySeq) return;
      const message = e && typeof e === "object" && "message" in e ? String((e as { message: unknown }).message || "") : "";
      setError(message || "Failed to load overview");
    } finally {
      if (fastAbortRef.current === fastController) {
        fastAbortRef.current = null;
      }
      if (refreshSeqRef.current === mySeq) {
        setIsLoading(false);
      }
    }
  }, []);

  const scheduleRefreshFromInvalidate = useCallback(() => {
    if (invalidateTimerRef.current) return;
    const delayMs = nextRealtimeInvalidationDelayMs({
      nowMs: Date.now(),
      lastRefreshAtMs: lastRefreshAtRef.current,
      minIntervalMs: INVALIDATE_MIN_REFRESH_MS,
      debounceMs: INVALIDATE_DEBOUNCE_MS,
    });
    invalidateTimerRef.current = window.setTimeout(() => {
      invalidateTimerRef.current = null;
      void refresh();
    }, delayMs);
  }, [refresh]);

  usePortalRealtimeSubscription("ui.overview.kpi.patch", (event) => {
    setSnapshot((prev) => {
      const next = applyOverviewRealtimePatch(prev, event.payload || {});
      if (!next) return next;
      try {
        sessionStorage.setItem(SNAPSHOT_CACHE_KEY, JSON.stringify(next));
      } catch {
        // no-op
      }
      return next;
    });
    setStorm((prev) => {
      const patch: Partial<StormStatus> = {
        phase: event.payload?.phase,
        reason: event.payload?.reason,
      };
      if (typeof event.payload?.backlog_events === "number") {
        patch.backlog_events = event.payload.backlog_events;
      }
      if (typeof event.payload?.backlog_messages === "number") {
        patch.backlog_messages = event.payload.backlog_messages;
      }
      if (typeof event.payload?.protection_active === "boolean") {
        patch.active = event.payload.protection_active;
      }
      return mergeStormStatus(prev, patch);
    });
    setLastUpdatedAt(new Date());
  });

  usePortalRealtimeSubscription("ui.overview.invalidate", () => {
    scheduleRefreshFromInvalidate();
  });

  usePortalRealtimeSubscription("ui.alerts.invalidate", () => {
    scheduleRefreshFromInvalidate();
  });

  usePortalRealtimeSubscription("ui.overview.storm.patch", (event) => {
    setStorm((prev) => mergeStormStatus(prev, (event.payload || {}) as Partial<StormStatus>));
    setLastUpdatedAt(new Date());
  });

  usePortalRealtimeSubscription("ui.alerts.delta.patch", (event) => {
    setSnapshot((prev) => {
      const next = applyOverviewRealtimeAlertsDelta(prev, event.payload || {}, event.timestamp);
      if (!next) return next;
      try {
        sessionStorage.setItem(SNAPSHOT_CACHE_KEY, JSON.stringify(next));
      } catch {
        // no-op
      }
      return next;
    });
    setLastUpdatedAt(new Date());
  });

  useEffect(() => {
    let alive = true;
    const intervalMs = realtimeStatus === "open" ? REALTIME_BASELINE_POLL_MS : FALLBACK_POLL_MS;

    void refresh();
    const timer = window.setInterval(() => {
      if (!alive) return;
      void refresh();
    }, intervalMs);

    return () => {
      alive = false;
      fastAbortRef.current?.abort();
      fullAbortRef.current?.abort();
      if (invalidateTimerRef.current) {
        window.clearTimeout(invalidateTimerRef.current);
        invalidateTimerRef.current = null;
      }
      window.clearInterval(timer);
    };
  }, [refresh, realtimeStatus]);

  useEffect(() => {
    if (realtimeStatus === "open") {
      scheduleRefreshFromInvalidate();
    }
  }, [realtimeStatus, scheduleRefreshFromInvalidate]);

  useEffect(() => {
    let alive = true;
    const intervalMs = realtimeStatus === "open" ? STORM_BASELINE_POLL_MS : STORM_FALLBACK_POLL_MS;

    const tick = async () => {
      try {
        const status = await getStormStatus({ timeoutMs: FULL_REFRESH_TIMEOUT_MS });
        if (!alive) return;
        setStorm((prev) => mergeStormStatus(prev, status));
      } catch {
        if (!alive) return;
        if (!stormRef.current) setStorm(null);
      }
    };

    void tick();
    const timer = window.setInterval(() => {
      if (!alive) return;
      void tick();
    }, intervalMs);

    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [realtimeStatus]);

  const value = useMemo<OverviewLiveCtx>(
    () => ({
      snapshot,
      storm,
      realtimeStatus,
      isLoading,
      error,
      lastUpdatedAt,
      windowMinutes: WINDOW_MINUTES,
      refresh,
    }),
    [snapshot, storm, realtimeStatus, isLoading, error, lastUpdatedAt, refresh],
  );

  return <OverviewLiveContext.Provider value={value}>{children}</OverviewLiveContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useOverviewLive() {
  const ctx = useContext(OverviewLiveContext);
  if (!ctx) throw new Error("useOverviewLive must be used within OverviewLiveProvider");
  return ctx;
}
