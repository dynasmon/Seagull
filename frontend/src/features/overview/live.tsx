import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import { usePortalRealtime, usePortalRealtimeSubscription } from "@/shared/realtime";
import type { RealtimeConnectionStatus } from "@/shared/realtime";
import { isAbortError } from "@/shared/lib/http";

import { getOverview, getStormStatus } from "./api";
import {
  applyOverviewRealtimeAlertCreated,
  applyOverviewRealtimeAlertUpdated,
  applyOverviewRealtimeAlertsDelta,
  applyOverviewRealtimePatch,
  applyStormStatusToOverviewSnapshot,
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
const REALTIME_KPI_FLUSH_MS = 180;
const REALTIME_ALERTS_FLUSH_MS = 220;
const REALTIME_STORM_FLUSH_MS = 220;
const REALTIME_BURST_WINDOW_MS = 1000;
const REALTIME_KPI_BURST_LIMIT = 60;
const REALTIME_ALERTS_BURST_LIMIT = 80;
const REALTIME_STORM_BURST_LIMIT = 80;

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
  const fullRefreshSeqRef = useRef(0);
  const fastAbortRef = useRef<AbortController | null>(null);
  const fullAbortRef = useRef<AbortController | null>(null);
  const fullPendingRef = useRef(false);
  const lastRefreshAtRef = useRef(0);
  const invalidateTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const kpiFlushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stormFlushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const alertsFlushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const kpiPendingRef = useRef<Record<string, unknown> | null>(null);
  const stormPendingRef = useRef<Record<string, unknown> | null>(null);
  const alertsPendingRef = useRef<Array<{ payload: Record<string, unknown>; timestamp: string }>>([]);
  const kpiBurstStartRef = useRef(0);
  const kpiBurstCountRef = useRef(0);
  const stormBurstStartRef = useRef(0);
  const stormBurstCountRef = useRef(0);
  const alertsBurstStartRef = useRef(0);
  const alertsBurstCountRef = useRef(0);

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
        const myFullSeq = ++fullRefreshSeqRef.current;
        fullAbortRef.current = fullController;

        void getOverview(
          { window_minutes: WINDOW_MINUTES },
          { signal: fullController.signal, timeoutMs: FULL_REFRESH_TIMEOUT_MS },
        )
          .then((full) => {
            if (fullRefreshSeqRef.current !== myFullSeq) return;
            const currentEnd = Date.parse(snapshotRef.current?.meta?.window_end || "");
            const incomingEnd = Date.parse(full?.meta?.window_end || "");
            if (Number.isFinite(currentEnd) && Number.isFinite(incomingEnd) && incomingEnd < currentEnd) {
              return;
            }
            setSnapshot(full);
            setError(null);
            setLastUpdatedAt(new Date());
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

  const consumeBurstBudget = useCallback(
    (startRef: { current: number }, countRef: { current: number }, limit: number): boolean => {
      const now = Date.now();
      if ((now - startRef.current) > REALTIME_BURST_WINDOW_MS) {
        startRef.current = now;
        countRef.current = 0;
      }
      countRef.current += 1;
      if (countRef.current > limit) {
        scheduleRefreshFromInvalidate();
        return false;
      }
      return true;
    },
    [scheduleRefreshFromInvalidate],
  );

  const flushKpiPending = useCallback(() => {
    kpiFlushTimerRef.current = null;
    const pending = kpiPendingRef.current;
    if (!pending) return;
    kpiPendingRef.current = null;
    setSnapshot((prev) => {
      const next = applyOverviewRealtimePatch(prev, pending as any);
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
        phase: pending?.phase as any,
        reason: pending?.reason as any,
      };
      if (typeof pending?.backlog_events === "number") {
        patch.backlog_events = pending.backlog_events as number;
      }
      if (typeof pending?.backlog_messages === "number") {
        patch.backlog_messages = pending.backlog_messages as number;
      }
      if (typeof pending?.protection_active === "boolean") {
        patch.active = pending.protection_active as boolean;
      }
      return mergeStormStatus(prev, patch);
    });
    setLastUpdatedAt(new Date());
  }, []);

  const scheduleKpiFlush = useCallback(() => {
    if (kpiFlushTimerRef.current) return;
    kpiFlushTimerRef.current = window.setTimeout(flushKpiPending, REALTIME_KPI_FLUSH_MS);
  }, [flushKpiPending]);

  const flushStormPending = useCallback(() => {
    stormFlushTimerRef.current = null;
    const pending = stormPendingRef.current;
    if (!pending) return;
    stormPendingRef.current = null;
    setStorm((prev) => mergeStormStatus(prev, pending as Partial<StormStatus>));
    setSnapshot((prev) => {
      const next = applyStormStatusToOverviewSnapshot(prev, pending as Partial<StormStatus>);
      if (!next || next === prev) return next;
      try {
        sessionStorage.setItem(SNAPSHOT_CACHE_KEY, JSON.stringify(next));
      } catch {
        // no-op
      }
      return next;
    });
    setLastUpdatedAt(new Date());
  }, []);

  const scheduleStormFlush = useCallback(() => {
    if (stormFlushTimerRef.current) return;
    stormFlushTimerRef.current = window.setTimeout(flushStormPending, REALTIME_STORM_FLUSH_MS);
  }, [flushStormPending]);

  const flushAlertsPending = useCallback(() => {
    alertsFlushTimerRef.current = null;
    const queued = alertsPendingRef.current;
    if (queued.length === 0) return;
    alertsPendingRef.current = [];
    setSnapshot((prev) => {
      let next = prev;
      for (const item of queued) {
        next = applyOverviewRealtimeAlertsDelta(next, item.payload as any, item.timestamp);
      }
      if (!next || next === prev) return next;
      try {
        sessionStorage.setItem(SNAPSHOT_CACHE_KEY, JSON.stringify(next));
      } catch {
        // no-op
      }
      return next;
    });
    setLastUpdatedAt(new Date());
  }, []);

  const scheduleAlertsFlush = useCallback(() => {
    if (alertsFlushTimerRef.current) return;
    alertsFlushTimerRef.current = window.setTimeout(flushAlertsPending, REALTIME_ALERTS_FLUSH_MS);
  }, [flushAlertsPending]);

  const enqueueKpiPatch = useCallback((payload: Record<string, unknown>) => {
    const previous = kpiPendingRef.current || {};
    kpiPendingRef.current = {
      ...previous,
      ...payload,
      events_5m_delta:
        (typeof previous.events_5m_delta === "number" ? previous.events_5m_delta : 0) +
        (typeof payload.events_5m_delta === "number" ? payload.events_5m_delta : 0),
    };
    scheduleKpiFlush();
  }, [scheduleKpiFlush]);

  const enqueueStormPatch = useCallback((payload: Record<string, unknown>) => {
    stormPendingRef.current = {
      ...(stormPendingRef.current || {}),
      ...payload,
    };
    scheduleStormFlush();
  }, [scheduleStormFlush]);

  usePortalRealtimeSubscription("ui.overview.kpi.patch", (event) => {
    if (!consumeBurstBudget(kpiBurstStartRef, kpiBurstCountRef, REALTIME_KPI_BURST_LIMIT)) return;
    enqueueKpiPatch((event.payload || {}) as Record<string, unknown>);
  });

  usePortalRealtimeSubscription("overview.patch", (event) => {
    if (!consumeBurstBudget(kpiBurstStartRef, kpiBurstCountRef, REALTIME_KPI_BURST_LIMIT)) return;
    enqueueKpiPatch((event.payload || {}) as Record<string, unknown>);
  });

  usePortalRealtimeSubscription("ui.overview.invalidate", () => {
    scheduleRefreshFromInvalidate();
  });

  usePortalRealtimeSubscription("overview.invalidate", () => {
    scheduleRefreshFromInvalidate();
  });

  usePortalRealtimeSubscription("ui.alerts.invalidate", () => {
    scheduleRefreshFromInvalidate();
  });

  usePortalRealtimeSubscription("alerts.invalidate", () => {
    scheduleRefreshFromInvalidate();
  });

  usePortalRealtimeSubscription("ui.overview.storm.patch", (event) => {
    if (!consumeBurstBudget(stormBurstStartRef, stormBurstCountRef, REALTIME_STORM_BURST_LIMIT)) return;
    enqueueStormPatch((event.payload || {}) as Record<string, unknown>);
  });

  usePortalRealtimeSubscription("storm.status", (event) => {
    if (!consumeBurstBudget(stormBurstStartRef, stormBurstCountRef, REALTIME_STORM_BURST_LIMIT)) return;
    enqueueStormPatch((event.payload || {}) as Record<string, unknown>);
  });

  usePortalRealtimeSubscription("ui.alerts.delta.patch", (event) => {
    if (!consumeBurstBudget(alertsBurstStartRef, alertsBurstCountRef, REALTIME_ALERTS_BURST_LIMIT)) return;
    alertsPendingRef.current.push({
      payload: (event.payload || {}) as Record<string, unknown>,
      timestamp: String(event.timestamp || ""),
    });
    if (alertsPendingRef.current.length > REALTIME_ALERTS_BURST_LIMIT) {
      alertsPendingRef.current = [];
      scheduleRefreshFromInvalidate();
      return;
    }
    scheduleAlertsFlush();
  });

  usePortalRealtimeSubscription("alert.created", (event) => {
    if (!consumeBurstBudget(alertsBurstStartRef, alertsBurstCountRef, REALTIME_ALERTS_BURST_LIMIT)) return;
    setSnapshot((prev) => {
      const next = applyOverviewRealtimeAlertCreated(prev, event.payload as any, String(event.timestamp || ""));
      if (!next || next === prev) return next;
      try {
        sessionStorage.setItem(SNAPSHOT_CACHE_KEY, JSON.stringify(next));
      } catch {
        // no-op
      }
      return next;
    });
    setLastUpdatedAt(new Date());
  });

  usePortalRealtimeSubscription("alert.updated", (event) => {
    if (!consumeBurstBudget(alertsBurstStartRef, alertsBurstCountRef, REALTIME_ALERTS_BURST_LIMIT)) return;
    setSnapshot((prev) => {
      const next = applyOverviewRealtimeAlertUpdated(prev, event.payload as any);
      if (!next || next === prev) return next;
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
      if (kpiFlushTimerRef.current) {
        window.clearTimeout(kpiFlushTimerRef.current);
        kpiFlushTimerRef.current = null;
      }
      if (stormFlushTimerRef.current) {
        window.clearTimeout(stormFlushTimerRef.current);
        stormFlushTimerRef.current = null;
      }
      if (alertsFlushTimerRef.current) {
        window.clearTimeout(alertsFlushTimerRef.current);
        alertsFlushTimerRef.current = null;
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
        setSnapshot((prev) => {
          const next = applyStormStatusToOverviewSnapshot(prev, status);
          if (!next || next === prev) return next;
          try {
            sessionStorage.setItem(SNAPSHOT_CACHE_KEY, JSON.stringify(next));
          } catch {
            // no-op
          }
          return next;
        });
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
