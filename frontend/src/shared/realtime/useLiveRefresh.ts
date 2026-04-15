import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { isAbortError } from "@/shared/lib/http";
import { usePortalRealtime } from "@/shared/realtime/context";
import type { RealtimeConnectionStatus } from "@/shared/realtime/client";

import {
  resolveLiveRefreshProfile,
  type LiveRefreshCadenceProfile,
  type LiveRefreshProfileName,
} from "./cadence";

export type LiveRefreshReason =
  | "mount"
  | "manual"
  | "invalidate"
  | "reconcile"
  | "fallback"
  | "reconnect"
  | "visible"
  | "dependency";

export type LiveRefreshContext = {
  signal: AbortSignal;
  reason: LiveRefreshReason;
  realtimeStatus: RealtimeConnectionStatus;
  isVisible: boolean;
};

export type LiveRefreshState = {
  profile: LiveRefreshCadenceProfile;
  realtimeStatus: RealtimeConnectionStatus;
  isVisible: boolean;
  isRefreshing: boolean;
  isLive: boolean;
  isFallbackPolling: boolean;
  isReconnecting: boolean;
  lastUpdatedAt: Date | null;
  lastStartedAt: Date | null;
  lastReason: LiveRefreshReason | null;
};

type UseLiveRefreshOptions = {
  enabled?: boolean;
  profile?: LiveRefreshProfileName | LiveRefreshCadenceProfile;
  refresh: (context: LiveRefreshContext) => Promise<void> | void;
  onError?: (error: unknown, context: LiveRefreshContext) => void;
  immediate?: boolean;
};

type RefreshRequestOptions = {
  immediate?: boolean;
  supersede?: boolean;
};

function readVisibility(): boolean {
  if (typeof document === "undefined") return true;
  return document.visibilityState !== "hidden";
}

export function useLiveRefresh(options: UseLiveRefreshOptions) {
  const { enabled = true, onError } = options;
  const { status: realtimeStatus, noteFallbackPollingActivation } = usePortalRealtime();
  const profile = useMemo(() => resolveLiveRefreshProfile(options.profile), [options.profile]);

  const [isVisible, setIsVisible] = useState<boolean>(() => readVisibility());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);
  const [lastStartedAt, setLastStartedAt] = useState<Date | null>(null);
  const [lastReason, setLastReason] = useState<LiveRefreshReason | null>(null);

  const refreshRef = useRef(options.refresh);
  const onErrorRef = useRef(onError);
  const realtimeStatusRef = useRef(realtimeStatus);
  const enabledRef = useRef(enabled);
  const profileRef = useRef(profile);
  const isVisibleRef = useRef(isVisible);
  const lastStartMsRef = useRef(0);
  const currentControllerRef = useRef<AbortController | null>(null);
  const inFlightPromiseRef = useRef<Promise<void> | null>(null);
  const queuedReasonRef = useRef<LiveRefreshReason | null>(null);
  const queuedImmediateRef = useRef(false);
  const deferredTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const invalidateTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cadenceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevRealtimeStatusRef = useRef(realtimeStatus);
  const prevVisibleRef = useRef(isVisible);
  const mountReasonRef = useRef<LiveRefreshReason>("mount");
  const prevFallbackPollingRef = useRef(enabled && realtimeStatus !== "open");

  useEffect(() => {
    refreshRef.current = options.refresh;
  }, [options.refresh]);

  useEffect(() => {
    onErrorRef.current = onError;
  }, [onError]);

  useEffect(() => {
    realtimeStatusRef.current = realtimeStatus;
  }, [realtimeStatus]);

  useEffect(() => {
    enabledRef.current = enabled;
  }, [enabled]);

  useEffect(() => {
    profileRef.current = profile;
  }, [profile]);

  useEffect(() => {
    isVisibleRef.current = isVisible;
  }, [isVisible]);

  const clearDeferredTimer = useCallback(() => {
    if (!deferredTimerRef.current) return;
    window.clearTimeout(deferredTimerRef.current);
    deferredTimerRef.current = null;
  }, []);

  const clearInvalidateTimer = useCallback(() => {
    if (!invalidateTimerRef.current) return;
    window.clearTimeout(invalidateTimerRef.current);
    invalidateTimerRef.current = null;
  }, []);

  const clearCadenceTimer = useCallback(() => {
    if (!cadenceTimerRef.current) return;
    window.clearTimeout(cadenceTimerRef.current);
    cadenceTimerRef.current = null;
  }, []);

  const queueRefresh = useCallback((reason: LiveRefreshReason, immediate: boolean) => {
    queuedReasonRef.current = reason;
    queuedImmediateRef.current = queuedImmediateRef.current || immediate;
  }, []);

  const runRefresh = useCallback(
    (reason: LiveRefreshReason): Promise<void> => {
      if (!enabledRef.current) return Promise.resolve();

      const controller = new AbortController();
      currentControllerRef.current = controller;
      const context: LiveRefreshContext = {
        signal: controller.signal,
        reason,
        realtimeStatus: realtimeStatusRef.current,
        isVisible: isVisibleRef.current,
      };

      lastStartMsRef.current = Date.now();
      setLastStartedAt(new Date(lastStartMsRef.current));
      setLastReason(reason);
      setIsRefreshing(true);

      const promise = Promise.resolve(refreshRef.current(context))
        .then(() => {
          setLastUpdatedAt(new Date());
        })
        .catch((error: unknown) => {
          if (isAbortError(error)) return;
          onErrorRef.current?.(error, context);
        })
        .finally(() => {
          if (currentControllerRef.current === controller) {
            currentControllerRef.current = null;
          }
          if (inFlightPromiseRef.current === promise) {
            inFlightPromiseRef.current = null;
          }
          setIsRefreshing(false);

          const queuedReason = queuedReasonRef.current;
          const queuedImmediate = queuedImmediateRef.current;
          if (!queuedReason || !enabledRef.current) return;
          queuedReasonRef.current = null;
          queuedImmediateRef.current = false;
          void requestRefresh(queuedReason, { immediate: queuedImmediate });
        });

      inFlightPromiseRef.current = promise;
      return promise;
    },
    [],
  );

  const requestRefresh = useCallback(
    (reason: LiveRefreshReason, requestOptions: RefreshRequestOptions = {}) => {
      if (!enabledRef.current) return Promise.resolve();

      const activeProfile = profileRef.current;
      const now = Date.now();

      if (requestOptions.supersede) {
        currentControllerRef.current?.abort();
      }

      if (inFlightPromiseRef.current && !requestOptions.supersede) {
        queueRefresh(reason, Boolean(requestOptions.immediate));
        return inFlightPromiseRef.current;
      }

      clearDeferredTimer();

      const minGapMs = activeProfile.minGapMs;
      const elapsedMs = now - lastStartMsRef.current;
      if (!requestOptions.immediate && elapsedMs < minGapMs) {
        const delayMs = minGapMs - elapsedMs;
        deferredTimerRef.current = window.setTimeout(() => {
          deferredTimerRef.current = null;
          void requestRefresh(reason, { immediate: true });
        }, delayMs);
        return inFlightPromiseRef.current ?? Promise.resolve();
      }

      return runRefresh(reason);
    },
    [clearDeferredTimer, queueRefresh, runRefresh],
  );

  const refreshNow = useCallback(() => requestRefresh("manual", { immediate: true, supersede: true }), [requestRefresh]);

  const invalidate = useCallback(
    (reason: LiveRefreshReason = "invalidate", requestOptions: RefreshRequestOptions = {}) => {
      if (!enabledRef.current) return;
      clearInvalidateTimer();

      const activeProfile = profileRef.current;
      const now = Date.now();
      const minGapMs = requestOptions.immediate ? 0 : Math.max(0, activeProfile.minGapMs - (now - lastStartMsRef.current));
      const delayMs = Math.max(minGapMs, requestOptions.immediate ? 0 : activeProfile.invalidateDebounceMs);

      invalidateTimerRef.current = window.setTimeout(() => {
        invalidateTimerRef.current = null;
        void requestRefresh(reason, { immediate: true, supersede: requestOptions.supersede });
      }, delayMs);
    },
    [clearInvalidateTimer, requestRefresh],
  );

  const markUpdated = useCallback(() => {
    setLastUpdatedAt(new Date());
  }, []);

  useEffect(() => {
    if (typeof document === "undefined") return;
    const onVisibilityChange = () => {
      setIsVisible(readVisibility());
    };

    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, []);

  useEffect(() => {
    if (!enabled) {
      clearCadenceTimer();
      clearDeferredTimer();
      clearInvalidateTimer();
      currentControllerRef.current?.abort();
      queuedReasonRef.current = null;
      queuedImmediateRef.current = false;
      return;
    }

    const intervalMs = (() => {
      if (!isVisible) return profile.hiddenMs;
      return realtimeStatus === "open" ? profile.reconcileMs : profile.fallbackMs;
    })();

    if (intervalMs === null) {
      clearCadenceTimer();
      return;
    }

    clearCadenceTimer();
    cadenceTimerRef.current = window.setTimeout(() => {
      cadenceTimerRef.current = null;
      void requestRefresh(realtimeStatus === "open" ? "reconcile" : "fallback");
    }, intervalMs);

    return clearCadenceTimer;
  }, [clearCadenceTimer, clearDeferredTimer, clearInvalidateTimer, enabled, isVisible, profile, realtimeStatus, requestRefresh]);

  useEffect(() => {
    if (!enabled) return;
    void requestRefresh(mountReasonRef.current, { immediate: options.immediate ?? true, supersede: true });
    mountReasonRef.current = "dependency";
  }, [enabled, options.immediate, requestRefresh]);

  useEffect(() => {
    if (!enabled) return;
    const prevStatus = prevRealtimeStatusRef.current;
    if (prevStatus !== realtimeStatus && realtimeStatus === "open" && profile.immediateRefreshOnReconnect) {
      invalidate("reconnect", { immediate: true, supersede: false });
    }
    prevRealtimeStatusRef.current = realtimeStatus;
  }, [enabled, invalidate, profile.immediateRefreshOnReconnect, realtimeStatus]);

  useEffect(() => {
    if (!enabled) return;
    const wasVisible = prevVisibleRef.current;
    if (wasVisible !== isVisible && isVisible && profile.immediateRefreshOnVisible) {
      invalidate("visible", { immediate: true, supersede: false });
    }
    prevVisibleRef.current = isVisible;
  }, [enabled, invalidate, isVisible, profile.immediateRefreshOnVisible]);

  useEffect(() => {
    const isFallbackPolling = enabled && realtimeStatus !== "open";
    if (isFallbackPolling && !prevFallbackPollingRef.current) {
      noteFallbackPollingActivation();
    }
    prevFallbackPollingRef.current = isFallbackPolling;
  }, [enabled, noteFallbackPollingActivation, realtimeStatus]);

  useEffect(() => {
    return () => {
      clearCadenceTimer();
      clearDeferredTimer();
      clearInvalidateTimer();
      currentControllerRef.current?.abort();
      queuedReasonRef.current = null;
      queuedImmediateRef.current = false;
    };
  }, [clearCadenceTimer, clearDeferredTimer, clearInvalidateTimer]);

  const state = useMemo<LiveRefreshState>(
    () => ({
      profile,
      realtimeStatus,
      isVisible,
      isRefreshing,
      isLive: enabled && realtimeStatus === "open",
      isFallbackPolling: enabled && realtimeStatus !== "open",
      isReconnecting: enabled && (realtimeStatus === "connecting" || realtimeStatus === "retrying"),
      lastUpdatedAt,
      lastStartedAt,
      lastReason,
    }),
    [enabled, isRefreshing, isVisible, lastReason, lastStartedAt, lastUpdatedAt, profile, realtimeStatus],
  );

  return useMemo(
    () => ({
      state,
      refreshNow,
      invalidate,
      markUpdated,
    }),
    [invalidate, markUpdated, refreshNow, state],
  );
}
