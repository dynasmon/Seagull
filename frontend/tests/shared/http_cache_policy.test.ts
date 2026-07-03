import { describe, expect, it } from "vitest";

import { defaultGetCacheMs } from "@/shared/lib/http";

describe("defaultGetCacheMs", () => {
  it("keeps always-fresh endpoints uncached", () => {
    expect(defaultGetCacheMs("/api/auth/me")).toBe(0);
    expect(defaultGetCacheMs("/api/auth/refresh")).toBe(0);
    expect(defaultGetCacheMs("/api/ingest/storm/status")).toBe(0);
    expect(defaultGetCacheMs("/health")).toBe(0);
  });

  it("keeps live event feeds uncached", () => {
    expect(defaultGetCacheMs("/api/events/live/network")).toBe(0);
    expect(defaultGetCacheMs("/api/events/recent?limit=50")).toBe(0);
  });

  it("gives SWR-backed read models a small non-zero TTL", () => {
    expect(defaultGetCacheMs("/api/overview?window_minutes=60")).toBe(5000);
    expect(defaultGetCacheMs("/api/alerts/recent?limit=50")).toBe(3000);
    expect(defaultGetCacheMs("/api/events/network/summary?minutes=60")).toBe(5000);
    expect(defaultGetCacheMs("/api/events/ssh/summary?minutes=60")).toBe(5000);
    expect(defaultGetCacheMs("/api/exposure/summary")).toBe(10000);
    expect(defaultGetCacheMs("/api/exposure/paths?page_size=25")).toBe(10000);
    expect(defaultGetCacheMs("/api/network-topology/summary")).toBe(10000);
    expect(defaultGetCacheMs("/api/network-topology/graph?max_nodes=200")).toBe(10000);
    expect(defaultGetCacheMs("/api/vuln/summary?active_within_days=30")).toBe(10000);
    expect(defaultGetCacheMs("/api/vuln/posture?active_within_days=30")).toBe(10000);
  });

  it("keeps endpoints without a SWR read model uncached", () => {
    expect(defaultGetCacheMs("/api/agents")).toBe(0);
    expect(defaultGetCacheMs("/api/exposure/assets?page_size=50")).toBe(0);
    expect(defaultGetCacheMs("/api/vuln/summary-export")).toBe(0);
  });
});
