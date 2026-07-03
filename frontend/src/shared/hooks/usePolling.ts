import { useCallback, useEffect, useMemo, useReducer, useRef } from "react";

import { apiGet, isAbortError } from "@/shared/lib/http";
import {
  resolveLiveRefreshProfile,
  useLiveRefresh,
  type LiveRefreshCadenceProfile,
  type LiveRefreshContext,
  type LiveRefreshProfileName,
} from "@/shared/realtime";

export type PollingState<T> = {
  data: T | null;
  error: unknown;
  settled: boolean;
};

export type PollingAction<T> =
  | { type: "success"; data: T }
  | { type: "failure"; error: unknown }
  | { type: "path-changed" }
  | { type: "reset" };

export function createInitialPollingState<T>(): PollingState<T> {
  return { data: null, error: null, settled: false };
}

export function pollingStateReducer<T>(state: PollingState<T>, action: PollingAction<T>): PollingState<T> {
  switch (action.type) {
    case "success":
      return { data: action.data, error: null, settled: true };
    case "failure":
      return { ...state, error: action.error, settled: true };
    case "path-changed":
      return state.error === null ? state : { ...state, error: null };
    case "reset":
      return state.data === null && state.error === null && !state.settled ? state : createInitialPollingState<T>();
  }
}

export type UsePollingOptions = {
  enabled?: boolean;
  profile?: LiveRefreshProfileName | LiveRefreshCadenceProfile;
  pauseWhenHidden?: boolean;
  cacheMs?: number;
  onError?: (error: unknown) => void;
};

export type UsePollingResult<T> = {
  data: T | null;
  error: unknown;
  loading: boolean;
  refreshing: boolean;
  refresh: () => Promise<void>;
  live: ReturnType<typeof useLiveRefresh>;
};

export function usePolling<T>(path: string | null | undefined, options: UsePollingOptions = {}): UsePollingResult<T> {
  const { cacheMs, onError, pauseWhenHidden = true } = options;
  const hasPath = typeof path === "string" && path.length > 0;
  const enabled = hasPath && (options.enabled ?? true);

  const [state, dispatch] = useReducer(pollingStateReducer<T>, createInitialPollingState<T>());

  const pathRef = useRef<string | null>(hasPath ? path : null);
  useEffect(() => {
    pathRef.current = typeof path === "string" && path.length > 0 ? path : null;
  }, [path]);

  const fetchOnce = useCallback(
    async (context: LiveRefreshContext) => {
      const target = typeof path === "string" && path.length > 0 ? path : null;
      if (!target) return;
      try {
        const out = await apiGet<T>(target, {
          cacheMs,
          force: context.reason === "manual",
          signal: context.signal,
        });
        if (pathRef.current !== target) return;
        dispatch({ type: "success", data: out });
      } catch (error) {
        if (isAbortError(error) || pathRef.current !== target) return;
        dispatch({ type: "failure", error });
        throw error;
      }
    },
    [cacheMs, path],
  );

  const profile = useMemo(() => {
    const resolved = resolveLiveRefreshProfile(options.profile);
    if (!pauseWhenHidden || resolved.hiddenMs === null) return resolved;
    return { ...resolved, hiddenMs: null };
  }, [options.profile, pauseWhenHidden]);

  const live = useLiveRefresh({
    enabled,
    profile,
    refresh: fetchOnce,
    onError,
  });
  const { invalidate, refreshNow } = live;

  const isFirstPathRef = useRef(true);
  useEffect(() => {
    if (typeof path !== "string" || path.length === 0) {
      isFirstPathRef.current = true;
      dispatch({ type: "reset" });
      return;
    }
    if (isFirstPathRef.current) {
      isFirstPathRef.current = false;
      return;
    }
    dispatch({ type: "path-changed" });
    invalidate("dependency", { immediate: true, supersede: true });
  }, [invalidate, path]);

  const loading = enabled && !state.settled;
  const refreshing = live.state.isRefreshing && state.settled;

  return useMemo(
    () => ({
      data: state.data,
      error: state.error,
      loading,
      refreshing,
      refresh: refreshNow,
      live,
    }),
    [live, loading, refreshNow, refreshing, state.data, state.error],
  );
}
