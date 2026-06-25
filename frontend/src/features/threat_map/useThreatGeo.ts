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

export function useThreatGeo(query: ThreatGeoQuery) {
  const [data, setData] = useState<ThreatGeoResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const queryRef = useRef(query);
  useEffect(() => {
    queryRef.current = query;
  }, [query]);
  const reqSeq = useRef(0);
  const didBoot = useRef(false);

  const live = useLiveRefresh({
    profile: "operational",
    refresh: async ({ signal }) => {
      const seq = ++reqSeq.current;
      const next = await getThreatGeo(
        {
          since_minutes: queryRef.current.sinceMinutes,
          limit: queryRef.current.limit,
          severity: queryRef.current.severity,
          source: queryRef.current.source,
        },
        { signal },
      );
      if (reqSeq.current !== seq) return;
      setData(next);
      setError(null);
    },
    onError: (e) => {
      setError(getErrorMessage(e, "Failed to load the threat map"));
    },
  });

  const { refreshNow, invalidate } = live;

  useEffect(() => {
    if (!didBoot.current) {
      didBoot.current = true;
      return;
    }
    void refreshNow();
  }, [query.sinceMinutes, query.limit, query.severity, query.source, refreshNow]);

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
