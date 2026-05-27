import { useCallback, useEffect, useRef, useState } from "react";

import { usePortalRealtimeSubscription } from "@/shared/realtime";
import type { PortalRealtimeEventPayloadMap } from "@/shared/realtime";

import { getAlertsPage } from "../api";
import { ALERTS_RT_BURST_LIMIT, ALERTS_RT_BURST_WINDOW_MS, ALERTS_RT_FLUSH_MS } from "../constants";
import type { ViewCfg } from "../constants";
import { mergeUniqueById } from "../lib/alertFilters";
import { buildAlertFromRealtimeDelta } from "../lib/alertRealtime";
import type { Alert } from "../types";

export function useAlertsData(view: ViewCfg, onAlertUpdated: (alert: Alert) => void) {
  const viewRef = useRef(view);
  useEffect(() => {
    viewRef.current = view;
  }, [view]);

  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const alertsRef = useRef<Alert[]>([]);
  useEffect(() => {
    alertsRef.current = alerts;
  }, [alerts]);

  const reqSeq = useRef(0);
  const moreSeq = useRef(0);
  const nextCursorRef = useRef<string | null>(null);
  const hasMoreRef = useRef(false);
  const drawerOpenRef = useRef(false);
  const selectedIdRef = useRef<number | null>(null);

  const realtimeFlushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const realtimeInvalidateTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const realtimePendingRef = useRef<
    Array<{ payload: PortalRealtimeEventPayloadMap["ui.alerts.delta.patch"]; timestamp: string }>
  >([]);
  const realtimeBurstWindowStartRef = useRef(0);
  const realtimeBurstCountRef = useRef(0);

  useEffect(() => {
    nextCursorRef.current = nextCursor;
    hasMoreRef.current = hasMore;
  }, [nextCursor, hasMore]);

  const scheduleRealtimeInvalidateRefresh = useCallback(() => {
    if (realtimeInvalidateTimerRef.current) return;
    realtimeInvalidateTimerRef.current = window.setTimeout(() => {
      realtimeInvalidateTimerRef.current = null;
      void loadHead("merge");
    }, 300);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const flushRealtimeDeltaQueue = useCallback(() => {
    realtimeFlushTimerRef.current = null;
    const queued = realtimePendingRef.current;
    if (queued.length === 0) return;
    realtimePendingRef.current = [];

    const v = viewRef.current;
    const severityFilter = String(v.severity || "all").toLowerCase();
    const ruleFilter = String(v.rule_id || "").trim().toLowerCase();
    const statusFilter = String(v.status || "all").toLowerCase();
    if (severityFilter !== "all" || statusFilter !== "all" || ruleFilter) {
      scheduleRealtimeInvalidateRefresh();
      return;
    }

    setAlerts((prev) => {
      let next = prev;
      for (const item of queued) {
        const action = String(item.payload?.action || "patch").toLowerCase();
        const projected = buildAlertFromRealtimeDelta(item.payload, item.timestamp);
        if (!projected) continue;
        const idx = next.findIndex((row) => row.id === projected.id);
        if (idx >= 0) {
          const current = next[idx];
          const merged: Alert = {
            ...current,
            ...projected,
            description: projected.description || current.description,
            created_at: current.created_at || projected.created_at,
            details: current.details ?? projected.details ?? null,
          };
          if (
            merged.rule_id === current.rule_id &&
            merged.severity === current.severity &&
            merged.src_ip === current.src_ip &&
            merged.dst_ip === current.dst_ip &&
            merged.dst_port === current.dst_port &&
            merged.description === current.description
          ) {
            continue;
          }
          const cloned = next.slice();
          cloned[idx] = merged;
          next = cloned;
          continue;
        }
        if (action === "upsert") {
          next = [projected, ...next].slice(0, Math.max(25, viewRef.current.page_size));
        }
      }
      return next;
    });
    setLastRefresh(new Date());
  }, [scheduleRealtimeInvalidateRefresh]);

  const scheduleRealtimeDeltaFlush = useCallback(() => {
    if (realtimeFlushTimerRef.current) return;
    realtimeFlushTimerRef.current = window.setTimeout(() => {
      flushRealtimeDeltaQueue();
    }, ALERTS_RT_FLUSH_MS);
  }, [flushRealtimeDeltaQueue]);

  const loadHead = useCallback(
    async (mode: "reset" | "merge" = "reset") => {
      const mySeq = ++reqSeq.current;
      setLoading(true);
      setError(null);

      const { severity, status, rule_id, page_size } = viewRef.current;

      try {
        const page = await getAlertsPage({
          page_size,
          severity: severity && severity !== "all" ? severity : undefined,
          status: status && status !== "all" ? status : undefined,
          rule_id: rule_id ? rule_id : undefined,
        });
        if (reqSeq.current !== mySeq) return;

        setLastRefresh(new Date());

        if (mode === "reset" || alertsRef.current.length === 0) {
          setAlerts(page.items);
          setNextCursor(page.next_cursor);
          setHasMore(Boolean(page.has_more));

          const selectedId = selectedIdRef.current;
          if (selectedId !== null) {
            const still = page.items.find((x) => x.id === selectedId);
            if (still) {
              onAlertUpdated(still);
            } else if (drawerOpenRef.current) {
              onAlertUpdated({ id: -1 } as Alert);
            }
          }
        } else {
          setAlerts((prev) => mergeUniqueById(page.items, prev));
          setHasMore((prev) => prev || Boolean(page.has_more));
          setNextCursor((prev) => (prev ? prev : page.next_cursor));
        }
      } catch (e: any) {
        if (reqSeq.current !== mySeq) return;
        setError(e?.message || "Failed to load alerts");
        if (alertsRef.current.length === 0) {
          setAlerts([]);
          setNextCursor(null);
          setHasMore(false);
          onAlertUpdated({ id: -1 } as Alert);
        }
      } finally {
        if (reqSeq.current !== mySeq) return;
        setLoading(false);
      }
    },
    [onAlertUpdated],
  );

  const loadMore = useCallback(async () => {
    const cursor = nextCursorRef.current;
    if (!hasMoreRef.current || !cursor) return;
    if (loadingMore) return;

    const mySeq = ++moreSeq.current;
    setLoadingMore(true);
    setError(null);

    const { severity, status, rule_id, page_size } = viewRef.current;

    try {
      const page = await getAlertsPage({
        page_size,
        cursor,
        severity: severity && severity !== "all" ? severity : undefined,
        status: status && status !== "all" ? status : undefined,
        rule_id: rule_id ? rule_id : undefined,
      });
      if (moreSeq.current !== mySeq) return;

      setAlerts((prev) => mergeUniqueById(prev, page.items));
      setNextCursor(page.next_cursor);
      setHasMore(Boolean(page.has_more));
      setLastRefresh((prev) => prev ?? new Date());
    } catch (e: any) {
      if (moreSeq.current !== mySeq) return;
      setError(e?.message || "Failed to load more alerts");
    } finally {
      if (moreSeq.current !== mySeq) return;
      setLoadingMore(false);
    }
  }, [loadingMore]);

  usePortalRealtimeSubscription("ui.alerts.delta.patch", (event) => {
    const now = Date.now();
    if (now - realtimeBurstWindowStartRef.current > ALERTS_RT_BURST_WINDOW_MS) {
      realtimeBurstWindowStartRef.current = now;
      realtimeBurstCountRef.current = 0;
    }
    realtimeBurstCountRef.current += 1;
    if (realtimeBurstCountRef.current > ALERTS_RT_BURST_LIMIT) {
      realtimePendingRef.current = [];
      scheduleRealtimeInvalidateRefresh();
      return;
    }

    realtimePendingRef.current.push({
      payload: (event.payload || {}) as PortalRealtimeEventPayloadMap["ui.alerts.delta.patch"],
      timestamp: String(event.timestamp || new Date().toISOString()),
    });
    if (realtimePendingRef.current.length > ALERTS_RT_BURST_LIMIT) {
      realtimePendingRef.current = [];
      scheduleRealtimeInvalidateRefresh();
      return;
    }
    scheduleRealtimeDeltaFlush();
  });

  usePortalRealtimeSubscription("ui.alerts.invalidate", () => {
    realtimePendingRef.current = [];
    scheduleRealtimeInvalidateRefresh();
  });

  useEffect(() => {
    loadHead("reset");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    return () => {
      if (realtimeFlushTimerRef.current) {
        window.clearTimeout(realtimeFlushTimerRef.current);
        realtimeFlushTimerRef.current = null;
      }
      if (realtimeInvalidateTimerRef.current) {
        window.clearTimeout(realtimeInvalidateTimerRef.current);
        realtimeInvalidateTimerRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    setAlerts([]);
    setNextCursor(null);
    setHasMore(false);
    setError(null);
    setLastRefresh(null);
    loadHead("reset");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view.severity, view.status, view.rule_id, view.page_size]);

  function updateAlert(updated: Alert) {
    setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
  }

  function setDrawerOpenRef(open: boolean) {
    drawerOpenRef.current = open;
  }

  function setSelectedIdRef(id: number | null) {
    selectedIdRef.current = id;
  }

  return {
    loading,
    loadingMore,
    error,
    alerts,
    nextCursor,
    hasMore,
    lastRefresh,
    loadHead,
    loadMore,
    updateAlert,
    setDrawerOpenRef,
    setSelectedIdRef,
  };
}

export type AlertsData = ReturnType<typeof useAlertsData>;
