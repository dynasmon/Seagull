import { describe, expect, it, vi } from "vitest";

import {
  attemptRouteLoadRecovery,
  isRecoverableRouteLoadError,
  shouldAttemptRouteLoadRecovery,
} from "@/app/route_error_recovery";

class FakeStorage {
  private readonly data = new Map<string, string>();

  getItem(key: string): string | null {
    return this.data.has(key) ? (this.data.get(key) ?? null) : null;
  }

  setItem(key: string, value: string): void {
    this.data.set(key, value);
  }
}

describe("route error recovery", () => {
  it("detects common lazy-route chunk load failures", () => {
    expect(isRecoverableRouteLoadError(new Error("Failed to fetch dynamically imported module"))).toBe(true);
    expect(isRecoverableRouteLoadError({ name: "ChunkLoadError", message: "Loading chunk 7 failed." })).toBe(true);
    expect(isRecoverableRouteLoadError("Importing a module script failed.")).toBe(true);
    expect(isRecoverableRouteLoadError(new Error("Some other runtime error"))).toBe(false);
  });

  it("only allows one automatic reload per path inside the recovery window", () => {
    const storage = new FakeStorage();

    expect(shouldAttemptRouteLoadRecovery("/alerts/queue", { storage, nowMs: 1_000 })).toBe(true);
    expect(shouldAttemptRouteLoadRecovery("/alerts/queue", { storage, nowMs: 5_000 })).toBe(false);
    expect(shouldAttemptRouteLoadRecovery("/alerts/rules", { storage, nowMs: 5_000 })).toBe(true);
    expect(shouldAttemptRouteLoadRecovery("/alerts/queue", { storage, nowMs: 70_500 })).toBe(true);
  });

  it("executes reload callback only when recovery should proceed", () => {
    const storage = new FakeStorage();
    const reload = vi.fn();

    expect(attemptRouteLoadRecovery("/alerts/queue", { storage, nowMs: 10_000, reload })).toBe(true);
    expect(reload).toHaveBeenCalledTimes(1);

    expect(attemptRouteLoadRecovery("/alerts/queue", { storage, nowMs: 10_500, reload })).toBe(false);
    expect(reload).toHaveBeenCalledTimes(1);
  });
});
