import { useEffect, useMemo, useRef, useState } from "react";

import { getErrorMessage } from "@/shared/lib/errors";
import { useLiveRefresh, usePortalRealtimeSubscription } from "@/shared/realtime";

import { getThreatGeo } from "./api";
import type { ThreatGeoResponse, ThreatSourceMode } from "./types";

export type ThreatGeoQuery = {
  sinceMinutes: number;
  limit: number;
  severity: string | null;
  source: ThreatSourceMode;
};

type CachedResponse = {
  data: ThreatGeoResponse;
  fetchedAt: number;
};

const RESPONSE_CACHE_MAX_ENTRIES = 24;
const RESPONSE_FRESH_MS = 60_000;

const responseCache = new Map<string, CachedResponse>();

function queryCacheKey(query: ThreatGeoQuery): string {
  return [query.sinceMinutes, query.limit, query.severity ?? "", query.source].join("|");
}

function readCachedResponse(key: string): CachedResponse | null {
  return responseCache.get(key) ?? null;
}

function writeCachedResponse(key: string, data: ThreatGeoResponse): void {
  responseCache.delete(key);
  responseCache.set(key, { data, fetchedAt: Date.now() });
  for (const staleKey of responseCache.keys()) {
    if (responseCache.size <= RESPONSE_CACHE_MAX_ENTRIES) break;
    responseCache.delete(staleKey);
  }
}

export function useThreatGeo(query: ThreatGeoQuery) {
  const cacheKey = queryCacheKey(query);
  const [data, setData] = useState<ThreatGeoResponse | null>(() => readCachedResponse(cacheKey)?.data ?? null);
  const [error, setError] = useState<string | null>(null);

  const queryRef = useRef(query);
  useEffect(() => {
    queryRef.current = query;
  }, [query]);
  const reqSeq = useRef(0);
  const activeKeyRef = useRef<string | null>(null);

  const live = useLiveRefresh({
    profile: "operational",
    refresh: async ({ signal }) => {
      const requestQuery = queryRef.current;
      const requestKey = queryCacheKey(requestQuery);
      const seq = ++reqSeq.current;
      const next = await getThreatGeo(
        {
          since_minutes: requestQuery.sinceMinutes,
          limit: requestQuery.limit,
          severity: requestQuery.severity,
          source: requestQuery.source,
        },
        { signal },
      );
      writeCachedResponse(requestKey, next);
      if (reqSeq.current !== seq) return;
      if (queryCacheKey(queryRef.current) !== requestKey) return;
      setData(next);
      setError(null);
    },
    onError: (e) => {
      setError(getErrorMessage(e, "Failed to load the threat map"));
    },
  });

  const { refreshNow, invalidate } = live;

  useEffect(() => {
    if (activeKeyRef.current === null) {
      activeKeyRef.current = cacheKey;
      return;
    }
    if (activeKeyRef.current === cacheKey) return;
    activeKeyRef.current = cacheKey;

    const cached = readCachedResponse(cacheKey);
    if (cached) {
      setData(cached.data);
      setError(null);
      if (Date.now() - cached.fetchedAt <= RESPONSE_FRESH_MS) return;
    }
    void refreshNow();
  }, [cacheKey, refreshNow]);

  usePortalRealtimeSubscription("ui.alerts.invalidate", () => {
    invalidate();
  });

  return useMemo(
    () => ({
      data,
      error,
      isLoading: !data && !error,
      isRefreshing: live.state.isRefreshing,
      lastUpdatedAt: live.state.lastUpdatedAt,
      refresh: refreshNow,
    }),
    [data, error, live.state.isRefreshing, live.state.lastUpdatedAt, refreshNow],
  );
}
