import { useEffect, useMemo, useRef } from "react";

import { usePortalRealtimeSubscription } from "@/shared/realtime/context";
import {
  type DashboardInvalidatePayload,
  type DashboardPage,
  type DashboardScope,
  type DashboardScopeValue,
  type PortalRealtimeEventType,
} from "@/shared/realtime/types";

export const DASHBOARD_PAGE_EVENT: Record<DashboardPage, PortalRealtimeEventType> = {
  overview: "ui.overview.invalidate",
  exposure_summary: "ui.exposure.invalidate",
  network_topology_summary: "ui.network_topology.invalidate",
  threat_map: "ui.threat_map.invalidate",
  vuln_summary: "ui.vulnerabilities.invalidate",
  vuln_posture: "ui.vulnerabilities.invalidate",
};

export const DASHBOARD_INVALIDATE_BURST_MS = 250;

export type DashboardInvalidateSignal = {
  page: DashboardPage;
  version: string;
  scope: DashboardScope;
};

export type DashboardInvalidateRouterOptions = {
  page: DashboardPage;
  onInvalidate: (signal: DashboardInvalidateSignal) => void;
  burstMs?: number;
  setTimeoutFn?: (callback: () => void, delayMs: number) => ReturnType<typeof setTimeout>;
  clearTimeoutFn?: (timer: ReturnType<typeof setTimeout>) => void;
};

export type DashboardInvalidateRouter = {
  accept: (payload: DashboardInvalidatePayload | null | undefined) => void;
  setScope: (scope: DashboardScope | null | undefined) => void;
  setCallback: (callback: (signal: DashboardInvalidateSignal) => void) => void;
  cancel: () => void;
};

function normalizeScopeValue(value: DashboardScopeValue | undefined): string | null {
  if (value === undefined || value === null) return null;
  return String(value);
}

export function scopeMatches(local: DashboardScope | null | undefined, incoming: DashboardScope | null | undefined): boolean {
  if (!local || !incoming) return true;
  for (const [key, incomingValue] of Object.entries(incoming)) {
    if (!(key in local)) continue;
    if (normalizeScopeValue(local[key]) !== normalizeScopeValue(incomingValue)) return false;
  }
  return true;
}

export function scopeIdentity(scope: DashboardScope | null | undefined): string {
  if (!scope) return "";
  return Object.keys(scope)
    .sort()
    .map((key) => `${key}=${normalizeScopeValue(scope[key]) ?? ""}`)
    .join("&");
}

export function createDashboardInvalidateRouter(options: DashboardInvalidateRouterOptions): DashboardInvalidateRouter {
  const burstMs = Math.max(0, options.burstMs ?? DASHBOARD_INVALIDATE_BURST_MS);
  const setTimer = options.setTimeoutFn ?? ((callback, delayMs) => setTimeout(callback, delayMs));
  const clearTimer = options.clearTimeoutFn ?? ((timer) => clearTimeout(timer));

  let callback = options.onInvalidate;
  let localScope: DashboardScope | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let pending: DashboardInvalidateSignal | null = null;
  const handledVersions = new Map<string, string>();

  const cancel = () => {
    if (timer === null) return;
    clearTimer(timer);
    timer = null;
    pending = null;
  };

  const flush = () => {
    timer = null;
    const signal = pending;
    pending = null;
    if (signal) callback(signal);
  };

  return {
    accept: (payload) => {
      if (!payload || payload.page !== options.page) return;
      const incomingScope = payload.scope_params ?? null;
      if (!scopeMatches(localScope, incomingScope)) return;

      const version = String(payload.version ?? "");
      const identity = scopeIdentity(incomingScope);
      if (version && handledVersions.get(identity) === version) return;
      if (version) handledVersions.set(identity, version);

      pending = { page: options.page, version, scope: incomingScope ?? {} };
      if (timer !== null) return;
      timer = setTimer(flush, burstMs);
    },
    setScope: (scope) => {
      const nextIdentity = scopeIdentity(scope);
      if (nextIdentity !== scopeIdentity(localScope)) {
        handledVersions.clear();
        cancel();
      }
      localScope = scope ?? null;
    },
    setCallback: (nextCallback) => {
      callback = nextCallback;
    },
    cancel,
  };
}

export type UseDashboardInvalidationOptions = {
  page: DashboardPage;
  scope?: DashboardScope | null;
  enabled?: boolean;
  onInvalidate: (signal: DashboardInvalidateSignal) => void;
};

export function useDashboardInvalidation({
  page,
  scope,
  enabled = true,
  onInvalidate,
}: UseDashboardInvalidationOptions): void {
  const identity = scopeIdentity(scope);
  const scopeRef = useRef<DashboardScope | null>(scope ?? null);
  const enabledRef = useRef(enabled);
  const router = useMemo(
    () => createDashboardInvalidateRouter({ page, onInvalidate: () => undefined }),
    [page],
  );

  useEffect(() => {
    scopeRef.current = scope ?? null;
    enabledRef.current = enabled;
  });

  useEffect(() => {
    router.setCallback(onInvalidate);
  }, [onInvalidate, router]);

  useEffect(() => {
    router.setScope(scopeRef.current);
  }, [identity, router]);

  useEffect(() => {
    if (enabled) return;
    router.cancel();
  }, [enabled, router]);

  useEffect(() => () => router.cancel(), [router]);

  usePortalRealtimeSubscription(DASHBOARD_PAGE_EVENT[page], (event) => {
    if (!enabledRef.current) return;
    router.accept(event.payload as DashboardInvalidatePayload);
  });
}
