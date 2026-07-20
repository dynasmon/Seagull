import { describe, expect, it } from "vitest";

import {
  DASHBOARD_PAGE_EVENT,
  createDashboardInvalidateRouter,
  scopeIdentity,
  scopeMatches,
  type DashboardInvalidateRouter,
  type DashboardInvalidateSignal,
} from "@/shared/realtime/dashboards";
import { DASHBOARD_INVALIDATE_PAGES, PORTAL_REALTIME_EVENT_MODE } from "@/shared/realtime/types";

type Harness = {
  router: DashboardInvalidateRouter;
  signals: DashboardInvalidateSignal[];
  advance: () => void;
};

function harness(page: (typeof DASHBOARD_INVALIDATE_PAGES)[number] = "overview"): Harness {
  const signals: DashboardInvalidateSignal[] = [];
  let pendingCallback: (() => void) | null = null;

  const router = createDashboardInvalidateRouter({
    page,
    onInvalidate: (signal) => signals.push(signal),
    burstMs: 250,
    setTimeoutFn: (callback) => {
      pendingCallback = callback;
      return 1 as unknown as ReturnType<typeof setTimeout>;
    },
    clearTimeoutFn: () => {
      pendingCallback = null;
    },
  });

  return {
    router,
    signals,
    advance: () => {
      const callback = pendingCallback;
      pendingCallback = null;
      callback?.();
    },
  };
}

describe("dashboard invalidation protocol", () => {
  it("maps every dashboard page to an invalidate-mode event", () => {
    for (const page of DASHBOARD_INVALIDATE_PAGES) {
      const eventType = DASHBOARD_PAGE_EVENT[page];
      expect(eventType).toBeTruthy();
      expect(PORTAL_REALTIME_EVENT_MODE[eventType]).toBe("invalidate");
    }
  });
});

describe("scopeMatches", () => {
  it("matches when no scope is declared on either side", () => {
    expect(scopeMatches(null, null)).toBe(true);
    expect(scopeMatches({ window_minutes: 60 }, null)).toBe(true);
    expect(scopeMatches(null, { window_minutes: 60 })).toBe(true);
  });

  it("rejects only on a shared key that differs", () => {
    expect(scopeMatches({ window_minutes: 60 }, { window_minutes: 1440 })).toBe(false);
    expect(scopeMatches({ window_minutes: 60 }, { window_minutes: 60, lite: true })).toBe(true);
    expect(scopeMatches({ window_minutes: 60, source: "both" }, { source: "alerts" })).toBe(false);
  });

  it("treats null and missing values as equivalent", () => {
    expect(scopeMatches({ agent_id: null }, { agent_id: null })).toBe(true);
    expect(scopeMatches({ agent_id: null }, { agent_id: "web-01" })).toBe(false);
  });

  it("builds a stable identity regardless of key order", () => {
    expect(scopeIdentity({ b: 2, a: 1 })).toBe(scopeIdentity({ a: 1, b: 2 }));
    expect(scopeIdentity(null)).toBe("");
  });
});

describe("createDashboardInvalidateRouter", () => {
  it("ignores payloads addressed to another page", () => {
    const { router, signals, advance } = harness("overview");

    router.accept({ page: "threat_map", version: "v1" });
    advance();

    expect(signals).toHaveLength(0);
  });

  it("ignores untagged invalidations so legacy subscribers stay in charge of them", () => {
    const { router, signals, advance } = harness("overview");

    router.accept({ version: "v1" });
    advance();

    expect(signals).toHaveLength(0);
  });

  it("skips invalidations for a scope the caller is not showing", () => {
    const { router, signals, advance } = harness("overview");
    router.setScope({ window_minutes: 60 });

    router.accept({ page: "overview", version: "v1", scope_params: { window_minutes: 1440 } });
    advance();

    expect(signals).toHaveLength(0);
  });

  it("collapses a burst of invalidations into a single refetch", () => {
    const { router, signals, advance } = harness("overview");
    router.setScope({ window_minutes: 60 });

    for (let i = 0; i < 10; i += 1) {
      router.accept({ page: "overview", version: `v${i}`, scope_params: { window_minutes: 60 } });
    }
    advance();

    expect(signals).toHaveLength(1);
    expect(signals[0]?.version).toBe("v9");
  });

  it("drops a repeated version for the same scope", () => {
    const { router, signals, advance } = harness("overview");
    router.setScope({ window_minutes: 60 });

    router.accept({ page: "overview", version: "v1", scope_params: { window_minutes: 60 } });
    advance();
    router.accept({ page: "overview", version: "v1", scope_params: { window_minutes: 60 } });
    advance();

    expect(signals).toHaveLength(1);
  });

  it("re-delivers a known version after the caller changes scope", () => {
    const { router, signals, advance } = harness("overview");
    router.setScope({ window_minutes: 60 });

    router.accept({ page: "overview", version: "v1", scope_params: { window_minutes: 60 } });
    advance();
    router.setScope({ window_minutes: 1440 });
    router.setScope({ window_minutes: 60 });
    router.accept({ page: "overview", version: "v1", scope_params: { window_minutes: 60 } });
    advance();

    expect(signals).toHaveLength(2);
  });

  it("cancels a pending refetch when torn down", () => {
    const { router, signals, advance } = harness("overview");

    router.accept({ page: "overview", version: "v1" });
    router.cancel();
    advance();

    expect(signals).toHaveLength(0);
  });
});
