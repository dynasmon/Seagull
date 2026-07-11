import { describe, expect, it } from "vitest";

import { isRegressiveOverviewWindow } from "./live_realtime";
import type { OverviewSnapshot } from "./types";

function snap(windowEnd: string | null, streamIdle = false): OverviewSnapshot {
  return { meta: { window_end: windowEnd, stream_idle: streamIdle } } as unknown as OverviewSnapshot;
}

describe("isRegressiveOverviewWindow", () => {
  it("drops a clock-anchored payload whose window regressed", () => {
    expect(isRegressiveOverviewWindow(snap("2026-07-11T12:10:00Z"), snap("2026-07-11T12:09:00Z"))).toBe(true);
  });

  it("accepts equal or advancing windows", () => {
    expect(isRegressiveOverviewWindow(snap("2026-07-11T12:10:00Z"), snap("2026-07-11T12:10:00Z"))).toBe(false);
    expect(isRegressiveOverviewWindow(snap("2026-07-11T12:10:00Z"), snap("2026-07-11T12:11:00Z"))).toBe(false);
  });

  it("accepts an idle payload frozen at the last activity", () => {
    expect(isRegressiveOverviewWindow(snap("2026-07-11T12:10:00Z"), snap("2026-07-11T12:05:00Z", true))).toBe(false);
  });

  it("accepts when either window_end is missing or unparsable", () => {
    expect(isRegressiveOverviewWindow(null, snap("2026-07-11T12:05:00Z"))).toBe(false);
    expect(isRegressiveOverviewWindow(snap("2026-07-11T12:10:00Z"), snap(null))).toBe(false);
    expect(isRegressiveOverviewWindow(snap("junk"), snap("2026-07-11T12:05:00Z"))).toBe(false);
  });
});
