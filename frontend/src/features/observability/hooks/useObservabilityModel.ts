import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useAuth } from "@/features/auth/context";
import { getErrorMessage } from "@/shared/lib/errors";
import { isAbortError } from "@/shared/lib/http";
import { useLiveRefresh } from "@/shared/realtime";

import { getObservabilityStatus, getRangeQuery } from "../api";
import { collectRangeKeys, DEFAULT_RANGE_PRESET_ID, resolveRangePreset } from "../lib/panels";
import type { EnvelopeMap, ObservabilityStatus, QueryEnvelope } from "../types";

const RANGE_KEYS = collectRangeKeys();

type RangeWindow = {
  start: number;
  end: number;
  spanSeconds: number;
};

function computeWindow(presetId: string): RangeWindow {
  const preset = resolveRangePreset(presetId);
  const end = Math.floor(Date.now() / 1000);
  return { start: end - preset.seconds, end, spanSeconds: preset.seconds };
}

async function fetchEnvelope(key: string, window: RangeWindow, signal: AbortSignal): Promise<[string, QueryEnvelope]> {
  try {
    const env = await getRangeQuery(key, { start: window.start, end: window.end }, { force: true, signal });
    return [key, env];
  } catch (error) {
    if (isAbortError(error)) throw error;
    return [key, { available: false, error: getErrorMessage(error, "Query failed"), result: null }];
  }
}

export function useObservabilityModel() {
  const { user } = useAuth();
  const isAdmin = String(user?.role || "").toLowerCase() === "admin";

  const [rangePresetId, setRangePresetId] = useState<string>(DEFAULT_RANGE_PRESET_ID);
  const [status, setStatus] = useState<ObservabilityStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [envelopes, setEnvelopes] = useState<EnvelopeMap>({});
  const [spanSeconds, setSpanSeconds] = useState<number>(resolveRangePreset(DEFAULT_RANGE_PRESET_ID).seconds);
  const [hasLoaded, setHasLoaded] = useState(false);

  const rangeRef = useRef(rangePresetId);
  useEffect(() => {
    rangeRef.current = rangePresetId;
  }, [rangePresetId]);

  const refresh = useCallback(async ({ signal }: { signal: AbortSignal }) => {
    let next: ObservabilityStatus;
    try {
      next = await getObservabilityStatus({ force: true, signal });
    } catch (error) {
      if (isAbortError(error)) throw error;
      setStatusError(getErrorMessage(error, "Failed to reach observability API"));
      setHasLoaded(true);
      return;
    }

    setStatus(next);
    setStatusError(null);

    if (!next.available) {
      setEnvelopes({});
      setHasLoaded(true);
      return;
    }

    const window = computeWindow(rangeRef.current);
    const entries = await Promise.all(RANGE_KEYS.map((key) => fetchEnvelope(key, window, signal)));
    if (signal.aborted) return;

    const map: EnvelopeMap = {};
    for (const [key, env] of entries) map[key] = env;
    setEnvelopes(map);
    setSpanSeconds(window.spanSeconds);
    setHasLoaded(true);
  }, []);

  const live = useLiveRefresh({
    enabled: isAdmin,
    profile: "admin",
    refresh,
  });
  const { refreshNow } = live;

  const skipFirstRangeEffect = useRef(true);
  useEffect(() => {
    if (!isAdmin) return;
    if (skipFirstRangeEffect.current) {
      skipFirstRangeEffect.current = false;
      return;
    }
    refreshNow();
  }, [isAdmin, refreshNow, rangePresetId]);

  return useMemo(
    () => ({
      isAdmin,
      status,
      statusError,
      envelopes,
      rangePresetId,
      setRangePresetId,
      spanSeconds,
      live,
      initializing: isAdmin && !hasLoaded,
    }),
    [envelopes, hasLoaded, isAdmin, live, rangePresetId, spanSeconds, status, statusError]
  );
}

export type ObservabilityModel = ReturnType<typeof useObservabilityModel>;
