import { describe, expect, it } from "vitest";

import { createTopologyInvalidationScheduler } from "@/features/network_topology/lib/realtime/realtime";

describe("network topology realtime invalidation scheduler", () => {
  it("debounces bursts and enforces a minimum refresh gap", () => {
    let now = 1000;
    let calls = 0;
    const canceled = new Set<number>();
    const scheduled: Array<{ callback: () => void; delay: number }> = [];
    const scheduler = createTopologyInvalidationScheduler(
      () => {
        calls += 1;
      },
      {
        debounceMs: 650,
        minGapMs: 5000,
        now: () => now,
        setTimeoutFn: (callback, delay) => {
          scheduled.push({ callback, delay });
          return scheduled.length - 1 as ReturnType<typeof setTimeout>;
        },
        clearTimeoutFn: (timer) => {
          canceled.add(timer as unknown as number);
        },
      },
    );

    scheduler.notify();
    scheduler.notify();

    expect(scheduled).toHaveLength(2);
    expect(canceled.has(0)).toBe(true);
    expect(scheduled[1].delay).toBe(650);

    scheduled[1].callback();
    expect(calls).toBe(1);

    now = 2000;
    scheduler.notify();
    expect(scheduled[2].delay).toBe(4000);
  });
});
