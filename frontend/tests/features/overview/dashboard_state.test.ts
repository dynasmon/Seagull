import { describe, expect, it } from "vitest";

import { timeSeriesHasSignal } from "@/features/overview/dashboard_state";

describe("overview dashboard state helpers", () => {
  it("treats zero-filled minute buckets as no signal", () => {
    expect(
      timeSeriesHasSignal([
        { t: "10:00", critical: 0, high: 0 },
        { t: "10:01", critical: 0, high: 0 },
      ]),
    ).toBe(false);
  });

  it("detects positive DDoS volume data", () => {
    expect(
      timeSeriesHasSignal([
        { t: "10:00", packets: 0, peak_pps: 0, peak_bps: 0 },
        { t: "10:01", packets: 379, peak_pps: 11, peak_bps: 1024 },
      ]),
    ).toBe(true);
  });
});
