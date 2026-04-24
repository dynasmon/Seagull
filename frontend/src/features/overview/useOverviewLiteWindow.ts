import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { isAbortError } from "@/shared/lib/http";

import { getOverview } from "./api";
import {
  DEFAULT_OVERVIEW_WINDOW_MINUTES,
  localInputToIso,
  resolveOverviewQuery,
  type OverviewQueryState,
  type OverviewResolvedQuery,
} from "./query";
import type { OverviewSnapshot } from "./types";

const REFRESH_INTERVAL_MS = 15_000;
const REQUEST_TIMEOUT_MS = 6_000;

type OverviewLiteSnapshot = Pick<OverviewSnapshot, "meta" | "traffic" | "ddos" | "ddos_volume">;

function toOverviewLiteSnapshot(payload: OverviewSnapshot): OverviewLiteSnapshot {
  return {
    meta: payload.meta,
    traffic: payload.traffic,
    ddos: payload.ddos,
    ddos_volume: payload.ddos_volume,
  };
}

function normalizeWindowMinutes(value: number, fallback: number): number {
  const parsed = Math.trunc(Number(value) || 0);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.max(5, Math.min(1440, parsed));
}

function errorMessage(error: unknown): string {
  if (!error || typeof error !== "object") return "";
  if ("message" in error) return String((error as { message?: unknown }).message || "").trim();
  return "";
}

export type OverviewLiteWindowState = {
  query: OverviewQueryState;
  draft: { from: string; to: string };
  snapshot: OverviewLiteSnapshot | null;
  isLoading: boolean;
  error: string | null;
  applyDisabled: boolean;
  isUsingBaseQuery: boolean;
  onDraftChange: (field: "from" | "to", value: string) => void;
  onApplyRange: () => void;
  onSetLiveWindow: (minutes: number) => void;
  onResetToLive: () => void;
};

export function useOverviewLiteWindow({
  baseQuery,
  initialQuery,
}: {
  baseQuery: OverviewResolvedQuery;
  initialQuery?: OverviewQueryState;
}): OverviewLiteWindowState {
  const fallbackWindowMinutes = baseQuery.windowMinutes || DEFAULT_OVERVIEW_WINDOW_MINUTES;
  const seedQuery = useMemo<OverviewQueryState>(
    () =>
      initialQuery ?? {
        windowMinutes: fallbackWindowMinutes,
        from: "",
        to: "",
      },
    [fallbackWindowMinutes, initialQuery],
  );

  const [query, setQuery] = useState<OverviewQueryState>(seedQuery);
  const [draft, setDraft] = useState<{ from: string; to: string }>({
    from: seedQuery.from,
    to: seedQuery.to,
  });
  const [snapshot, setSnapshot] = useState<OverviewLiteSnapshot | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const requestSeqRef = useRef(0);
  const resolvedQuery = useMemo(() => resolveOverviewQuery(query), [query]);
  const isUsingBaseQuery = resolvedQuery.cacheKey === baseQuery.cacheKey;

  useEffect(() => {
    setDraft({ from: query.from, to: query.to });
  }, [query.from, query.to]);

  const draftStartIso = localInputToIso(draft.from);
  const draftEndIso = localInputToIso(draft.to);
  const draftRangeReversed =
    draftStartIso !== undefined &&
    draftEndIso !== undefined &&
    Date.parse(draftStartIso) > Date.parse(draftEndIso);
  const applyDisabled =
    (Boolean(draft.from) && !draftStartIso) ||
    (Boolean(draft.to) && !draftEndIso) ||
    draftRangeReversed;

  const fetchWindowSnapshot = useCallback(
    async (signal: AbortSignal) => {
      const response = await getOverview(
        {
          window_minutes: resolvedQuery.windowMinutes,
          start_ts: resolvedQuery.startTs,
          end_ts: resolvedQuery.endTs,
          lite: true,
        },
        { signal, timeoutMs: REQUEST_TIMEOUT_MS },
      );
      return toOverviewLiteSnapshot(response);
    },
    [resolvedQuery.endTs, resolvedQuery.startTs, resolvedQuery.windowMinutes],
  );

  useEffect(() => {
    if (isUsingBaseQuery) {
      requestSeqRef.current += 1;
      setSnapshot(null);
      setIsLoading(false);
      setError(null);
      return;
    }

    let disposed = false;
    let activeController = new AbortController();
    let intervalId: ReturnType<typeof setInterval> | null = null;

    const runFetch = async (signal: AbortSignal) => {
      const seq = ++requestSeqRef.current;
      setIsLoading(true);
      try {
        const next = await fetchWindowSnapshot(signal);
        if (disposed || requestSeqRef.current !== seq) return;
        setSnapshot(next);
        setError(null);
      } catch (err: unknown) {
        if (isAbortError(err) || disposed || requestSeqRef.current !== seq) return;
        setError(errorMessage(err) || "Failed to refresh chart range");
      } finally {
        if (!disposed && requestSeqRef.current === seq) {
          setIsLoading(false);
        }
      }
    };

    void runFetch(activeController.signal);

    if (!resolvedQuery.fixedRange) {
      intervalId = window.setInterval(() => {
        activeController.abort();
        activeController = new AbortController();
        void runFetch(activeController.signal);
      }, REFRESH_INTERVAL_MS);
    }

    return () => {
      disposed = true;
      activeController.abort();
      if (intervalId !== null) window.clearInterval(intervalId);
    };
  }, [fetchWindowSnapshot, isUsingBaseQuery, resolvedQuery.cacheKey, resolvedQuery.fixedRange]);

  const onDraftChange = useCallback((field: "from" | "to", value: string) => {
    setDraft((prev) => ({ ...prev, [field]: value }));
  }, []);

  const onApplyRange = useCallback(() => {
    if (applyDisabled) return;
    setQuery((prev) => ({
      ...prev,
      from: draft.from.trim(),
      to: draft.to.trim(),
    }));
  }, [applyDisabled, draft.from, draft.to]);

  const onSetLiveWindow = useCallback(
    (minutes: number) => {
      setQuery({
        windowMinutes: normalizeWindowMinutes(minutes, fallbackWindowMinutes),
        from: "",
        to: "",
      });
    },
    [fallbackWindowMinutes],
  );

  const onResetToLive = useCallback(() => {
    setQuery((prev) => ({
      windowMinutes: normalizeWindowMinutes(prev.windowMinutes, fallbackWindowMinutes),
      from: "",
      to: "",
    }));
  }, [fallbackWindowMinutes]);

  return {
    query,
    draft,
    snapshot,
    isLoading,
    error,
    applyDisabled,
    isUsingBaseQuery,
    onDraftChange,
    onApplyRange,
    onSetLiveWindow,
    onResetToLive,
  };
}

export default useOverviewLiteWindow;
