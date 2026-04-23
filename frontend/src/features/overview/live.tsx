import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import { useLiveRefresh, usePortalRealtime, usePortalRealtimeSubscription } from "@/shared/realtime";
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
  reconcileFetchedOverviewSnapshot,
} from "./live_realtime";
import { DEFAULT_OVERVIEW_WINDOW_MINUTES, type OverviewResolvedQuery } from "./query";
import type { OverviewSnapshot, StormStatus } from "./types";

const SNAPSHOT_CACHE_PREFIX = "nw_overview_snapshot_v2";
const FULL_REFRESH_MS = 15000;
const FULL_REFRESH_TIMEOUT_MS = 6000;
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

function snapshotCacheKey(query: OverviewResolvedQuery): string {
  return `${SNAPSHOT_CACHE_PREFIX}:${query.cacheKey}`;
}

function readCachedSnapshot(key: string): OverviewSnapshot | null {
  try {
    const raw = sessionStorage.getItem(key);
    if (!raw) return null;
    return JSON.parse(raw) as OverviewSnapshot;
  } catch {
    return null;
  }
}

function writeCachedSnapshot(key: string, payload: OverviewSnapshot): void {
  try {
    sessionStorage.setItem(key, JSON.stringify(payload));
  } catch {
    // no-op: cache is best-effort
  }
}

function buildOverviewParams(query: OverviewResolvedQuery, lite: boolean) {
  return {
    window_minutes: query.windowMinutes,
    start_ts: query.startTs,
    end_ts: query.endTs,
    lite,
  };
}

export function OverviewLiveProvider({
  children,
  query,
}: {
  children: ReactNode;
  query: OverviewResolvedQuery;
}) {
  const { status: realtimeStatus } = usePortalRealtime();
  const realtimeEnabled = !query.fixedRange;
  const cacheKey = useMemo(() => snapshotCacheKey(query), [query]);

  const [snapshot, setSnapshot] = useState<OverviewSnapshot | null>(() => readCachedSnapshot(cacheKey));
  const [storm, setStorm] = useState<StormStatus | null>(null);
  const [isLoading, setIsLoading] = useState(() => !readCachedSnapshot(cacheKey));
  const [error, setError] = useState<string | null>(null);

  const snapshotRef = useRef<OverviewSnapshot | null>(snapshot);
  const stormRef = useRef<StormStatus | null>(storm);
  const queryRef = useRef<OverviewResolvedQuery>(query);
  const cacheKeyRef = useRef(cacheKey);
  const realtimeEnabledRef = useRef(realtimeEnabled);
  const lastFullAtRef = useRef(0);
  const refreshSeqRef = useRef(0);
  const fullRefreshSeqRef = useRef(0);
  const fastAbortRef = useRef<AbortController | null>(null);
  const fullAbortRef = useRef<AbortController | null>(null);
  const fullPendingRef = useRef(false);
  const lastSnapshotMutationAtRef = useRef(0);
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

  const persistSnapshot = useCallback((payload: OverviewSnapshot) => {
    writeCachedSnapshot(cacheKeyRef.current, payload);
  }, []);

  useEffect(() => {
    snapshotRef.current = snapshot;
    if (snapshot) lastSnapshotMutationAtRef.current = Date.now();
  }, [snapshot]);

  useEffect(() => {
    stormRef.current = storm;
  }, [storm]);

  useEffect(() => {
    queryRef.current = query;
    cacheKeyRef.current = cacheKey;
    realtimeEnabledRef.current = realtimeEnabled;
  }, [cacheKey, query, realtimeEnabled]);

  const refresh = useCallback(async () => {
    const activeQuery = queryRef.current;
    const activeCacheKey = cacheKeyRef.current;
    const mySeq = ++refreshSeqRef.current;
    const requestStartedAt = Date.now();

    fastAbortRef.current?.abort();
    const fastController = new AbortController();
    fastAbortRef.current = fastController;

    try {
      if (activeQuery.fixedRange) {
        const full = await getOverview(
          buildOverviewParams(activeQuery, false),
          { signal: fastController.signal, timeoutMs: FULL_REFRESH_TIMEOUT_MS },
        );
        if (refreshSeqRef.current !== mySeq) return;
        setSnapshot(full);
        setError(null);
        writeCachedSnapshot(activeCacheKey, full);
        return;
      }

      const fast = await getOverview(
        buildOverviewParams(activeQuery, true),
        { signal: fastController.signal, timeoutMs: FULL_REFRESH_TIMEOUT_MS },
      );
      if (refreshSeqRef.current !== mySeq) return;

      const prevEnd = Date.parse(snapshotRef.current?.meta?.window_end || "");
      const nextFastEnd = Date.parse(fast?.meta?.window_end || "");
      if (Number.isFinite(prevEnd) && Number.isFinite(nextFastEnd) && nextFastEnd < prevEnd) {
        return;
      }

      const mergedFast = reconcileFetchedOverviewSnapshot(snapshotRef.current, fast, {
        preserveLiveFields: lastSnapshotMutationAtRef.current > requestStartedAt,
      });
      setSnapshot(mergedFast);
      setError(null);
      writeCachedSnapshot(activeCacheKey, mergedFast);

      const needFull = !snapshotRef.current || (Date.now() - lastFullAtRef.current) >= FULL_REFRESH_MS;
      if (needFull && !fullPendingRef.current) {
        fullPendingRef.current = true;
        const fullController = new AbortController();
        const myFullSeq = ++fullRefreshSeqRef.current;
        const fullRequestStartedAt = Date.now();
        fullAbortRef.current = fullController;

        void getOverview(
          buildOverviewParams(activeQuery, false),
          { signal: fullController.signal, timeoutMs: FULL_REFRESH_TIMEOUT_MS },
        )
          .then((full) => {
            if (fullRefreshSeqRef.current !== myFullSeq) return;
            const currentEnd = Date.parse(snapshotRef.current?.meta?.window_end || "");
            const incomingEnd = Date.parse(full?.meta?.window_end || "");
            if (Number.isFinite(currentEnd) && Number.isFinite(incomingEnd) && incomingEnd < currentEnd) {
              return;
            }
            const reconciled = reconcileFetchedOverviewSnapshot(snapshotRef.current, full, {
              preserveLiveFields: lastSnapshotMutationAtRef.current > fullRequestStartedAt,
            });
            setSnapshot(reconciled);
            setError(null);
            lastFullAtRef.current = Date.now();
            writeCachedSnapshot(activeCacheKey, reconciled);
          })
          .catch((e: unknown) => {
            if (isAbortError(e)) return;
          })
          .finally(() => {
            if (fullAbortRef.current === fullController) fullAbortRef.current = null;
            fullPendingRef.current = false;
          });
      }
    } catch (e: unknown) {
      if (isAbortError(e)) return;
      if (refreshSeqRef.current !== mySeq) return;
      const message = e && typeof e === "object" && "message" in e ? String((e as { message: unknown }).message || "") : "";
      setError(message || "Failed to load overview");
    } finally {
      if (fastAbortRef.current === fastController) fastAbortRef.current = null;
      if (refreshSeqRef.current === mySeq) setIsLoading(false);
    }
  }, []);

  const overviewLive = useLiveRefresh({
    enabled: realtimeEnabled,
    profile: "hot-operational",
    refresh,
    immediate: false,
  });

  const stormLive = useLiveRefresh({
    enabled: realtimeEnabled,
    profile: "hot-operational",
    immediate: false,
    refresh: async () => {
      try {
        const status = await getStormStatus({ timeoutMs: FULL_REFRESH_TIMEOUT_MS });
        setStorm((prev) => mergeStormStatus(prev, status));
        setSnapshot((prev) => {
          const next = applyStormStatusToOverviewSnapshot(prev, status);
          if (!next || next === prev) return next;
          lastSnapshotMutationAtRef.current = Date.now();
          persistSnapshot(next);
          return next;
        });
        overviewLive.markUpdated();
      } catch {
        if (!stormRef.current) setStorm(null);
      }
    },
  });

  useEffect(() => {
    fastAbortRef.current?.abort();
    fullAbortRef.current?.abort();
    fullPendingRef.current = false;
    lastFullAtRef.current = 0;
    kpiPendingRef.current = null;
    stormPendingRef.current = null;
    alertsPendingRef.current = [];
    const cached = readCachedSnapshot(cacheKey);
    snapshotRef.current = cached;
    setSnapshot(cached);
    setStorm(null);
    setError(null);
    setIsLoading(!cached);
    void refresh();
    if (realtimeEnabled) void stormLive.refreshNow();
  }, [cacheKey, refresh, realtimeEnabled, stormLive.refreshNow]);

  const scheduleRefreshFromInvalidate = useCallback(() => {
    if (!realtimeEnabledRef.current) return;
    overviewLive.invalidate();
  }, [overviewLive.invalidate]);

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
      lastSnapshotMutationAtRef.current = Date.now();
      persistSnapshot(next);
      return next;
    });
    setStorm((prev) => {
      const patch: Partial<StormStatus> = {
        phase: pending?.phase as StormStatus["phase"],
        reason: pending?.reason as string,
      };
      if (typeof pending?.backlog_events === "number") patch.backlog_events = pending.backlog_events;
      if (typeof pending?.backlog_messages === "number") patch.backlog_messages = pending.backlog_messages;
      if (typeof pending?.protection_active === "boolean") patch.active = pending.protection_active;
      return mergeStormStatus(prev, patch);
    });
    overviewLive.markUpdated();
  }, [overviewLive, persistSnapshot]);

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
      lastSnapshotMutationAtRef.current = Date.now();
      persistSnapshot(next);
      return next;
    });
    overviewLive.markUpdated();
  }, [overviewLive, persistSnapshot]);

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
      lastSnapshotMutationAtRef.current = Date.now();
      persistSnapshot(next);
      return next;
    });
    overviewLive.markUpdated();
  }, [overviewLive, persistSnapshot]);

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
    if (!realtimeEnabledRef.current) return;
    if (!consumeBurstBudget(kpiBurstStartRef, kpiBurstCountRef, REALTIME_KPI_BURST_LIMIT)) return;
    enqueueKpiPatch((event.payload || {}) as Record<string, unknown>);
  });

  usePortalRealtimeSubscription("overview.patch", (event) => {
    if (!realtimeEnabledRef.current) return;
    if (!consumeBurstBudget(kpiBurstStartRef, kpiBurstCountRef, REALTIME_KPI_BURST_LIMIT)) return;
    enqueueKpiPatch((event.payload || {}) as Record<string, unknown>);
  });

  usePortalRealtimeSubscription("ui.overview.invalidate", () => {
    if (!realtimeEnabledRef.current) return;
    scheduleRefreshFromInvalidate();
  });

  usePortalRealtimeSubscription("overview.invalidate", () => {
    if (!realtimeEnabledRef.current) return;
    scheduleRefreshFromInvalidate();
  });

  usePortalRealtimeSubscription("ui.alerts.invalidate", () => {
    if (!realtimeEnabledRef.current) return;
    scheduleRefreshFromInvalidate();
  });

  usePortalRealtimeSubscription("alerts.invalidate", () => {
    if (!realtimeEnabledRef.current) return;
    scheduleRefreshFromInvalidate();
  });

  usePortalRealtimeSubscription("ui.overview.storm.patch", (event) => {
    if (!realtimeEnabledRef.current) return;
    if (!consumeBurstBudget(stormBurstStartRef, stormBurstCountRef, REALTIME_STORM_BURST_LIMIT)) return;
    enqueueStormPatch((event.payload || {}) as Record<string, unknown>);
  });

  usePortalRealtimeSubscription("storm.status", (event) => {
    if (!realtimeEnabledRef.current) return;
    if (!consumeBurstBudget(stormBurstStartRef, stormBurstCountRef, REALTIME_STORM_BURST_LIMIT)) return;
    enqueueStormPatch((event.payload || {}) as Record<string, unknown>);
  });

  usePortalRealtimeSubscription("ui.alerts.delta.patch", (event) => {
    if (!realtimeEnabledRef.current) return;
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
    if (!realtimeEnabledRef.current) return;
    if (!consumeBurstBudget(alertsBurstStartRef, alertsBurstCountRef, REALTIME_ALERTS_BURST_LIMIT)) return;
    setSnapshot((prev) => {
      const next = applyOverviewRealtimeAlertCreated(prev, event.payload as any, String(event.timestamp || ""));
      if (!next || next === prev) return next;
      lastSnapshotMutationAtRef.current = Date.now();
      persistSnapshot(next);
      return next;
    });
    overviewLive.markUpdated();
  });

  usePortalRealtimeSubscription("alert.updated", (event) => {
    if (!realtimeEnabledRef.current) return;
    if (!consumeBurstBudget(alertsBurstStartRef, alertsBurstCountRef, REALTIME_ALERTS_BURST_LIMIT)) return;
    setSnapshot((prev) => {
      const next = applyOverviewRealtimeAlertUpdated(prev, event.payload as any);
      if (!next || next === prev) return next;
      lastSnapshotMutationAtRef.current = Date.now();
      persistSnapshot(next);
      return next;
    });
    overviewLive.markUpdated();
  });

  useEffect(() => {
    return () => {
      fastAbortRef.current?.abort();
      fullAbortRef.current?.abort();
      if (kpiFlushTimerRef.current) window.clearTimeout(kpiFlushTimerRef.current);
      if (stormFlushTimerRef.current) window.clearTimeout(stormFlushTimerRef.current);
      if (alertsFlushTimerRef.current) window.clearTimeout(alertsFlushTimerRef.current);
    };
  }, []);

  const value = useMemo<OverviewLiveCtx>(
    () => ({
      snapshot,
      storm,
      realtimeStatus,
      isLoading,
      error,
      lastUpdatedAt: realtimeEnabled ? overviewLive.state.lastUpdatedAt : null,
      windowMinutes: query.windowMinutes || DEFAULT_OVERVIEW_WINDOW_MINUTES,
      refresh,
    }),
    [error, isLoading, overviewLive.state.lastUpdatedAt, query.windowMinutes, realtimeEnabled, realtimeStatus, refresh, snapshot, storm],
  );

  return <OverviewLiveContext.Provider value={value}>{children}</OverviewLiveContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useOverviewLive() {
  const ctx = useContext(OverviewLiveContext);
  if (!ctx) throw new Error("useOverviewLive must be used within OverviewLiveProvider");
  return ctx;
}
