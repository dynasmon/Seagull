import { describe, expect, it } from "vitest";

import {
  createInitialPollingState,
  pollingStateReducer,
  type PollingState,
} from "@/shared/hooks/usePolling";

type Payload = { total: number };

describe("pollingStateReducer", () => {
  it("starts unsettled with no data", () => {
    const state = createInitialPollingState<Payload>();

    expect(state).toEqual({ data: null, error: null, settled: false });
  });

  it("settles with data on success and clears previous errors", () => {
    const failed = pollingStateReducer(createInitialPollingState<Payload>(), {
      type: "failure",
      error: new Error("boom"),
    });

    const state = pollingStateReducer(failed, { type: "success", data: { total: 3 } });

    expect(state).toEqual({ data: { total: 3 }, error: null, settled: true });
  });

  it("keeps previous data when a refresh fails", () => {
    const loaded = pollingStateReducer(createInitialPollingState<Payload>(), {
      type: "success",
      data: { total: 3 },
    });
    const error = new Error("boom");

    const state = pollingStateReducer(loaded, { type: "failure", error });

    expect(state.data).toEqual({ total: 3 });
    expect(state.error).toBe(error);
    expect(state.settled).toBe(true);
  });

  it("keeps data and settled flag across path changes so the UI refreshes instead of reloading", () => {
    const loaded = pollingStateReducer(createInitialPollingState<Payload>(), {
      type: "success",
      data: { total: 3 },
    });

    const state = pollingStateReducer(loaded, { type: "path-changed" });

    expect(state).toBe(loaded);
  });

  it("clears a stale error when the path changes", () => {
    const failed = pollingStateReducer(createInitialPollingState<Payload>(), {
      type: "failure",
      error: new Error("boom"),
    });

    const state = pollingStateReducer(failed, { type: "path-changed" });

    expect(state.error).toBeNull();
    expect(state.settled).toBe(true);
  });

  it("resets to the initial state when polling is disabled", () => {
    const loaded = pollingStateReducer(createInitialPollingState<Payload>(), {
      type: "success",
      data: { total: 3 },
    });

    const state = pollingStateReducer(loaded, { type: "reset" });

    expect(state).toEqual(createInitialPollingState<Payload>());
  });

  it("returns the same reference for a no-op reset", () => {
    const initial: PollingState<Payload> = createInitialPollingState<Payload>();

    expect(pollingStateReducer(initial, { type: "reset" })).toBe(initial);
  });
});
