import { describe, expect, it, vi } from "vitest";

import { PortalRealtimeClient } from "@/shared/realtime/client";
import type { EventSourceLike } from "@/shared/realtime/client";
import type { StreamTokenOut } from "@/shared/realtime/api";

type MessageLikeEvent = MessageEvent<string> & { data: string };

class FakeEventSource implements EventSourceLike {
  public onopen: ((event: Event) => void) | null = null;
  public onerror: ((event: Event) => void) | null = null;
  public onmessage: ((event: MessageEvent<string>) => void) | null = null;

  public readonly listeners = new Map<string, Set<EventListener>>();
  public closed = false;

  constructor(public readonly url: string) {}

  addEventListener(type: string, listener: EventListener): void {
    let set = this.listeners.get(type);
    if (!set) {
      set = new Set<EventListener>();
      this.listeners.set(type, set);
    }
    set.add(listener);
  }

  removeEventListener(type: string, listener: EventListener): void {
    const set = this.listeners.get(type);
    if (!set) return;
    set.delete(listener);
    if (set.size === 0) {
      this.listeners.delete(type);
    }
  }

  close(): void {
    this.closed = true;
  }

  emitOpen(): void {
    this.onopen?.({} as Event);
  }

  emitError(): void {
    this.onerror?.({} as Event);
  }

  emitNamed(type: string, rawData: string): void {
    const event = { data: rawData } as MessageLikeEvent;
    const set = this.listeners.get(type);
    if (!set) return;
    for (const listener of Array.from(set)) {
      listener(event as unknown as Event);
    }
  }
}

function waitForTick(ms = 0): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function tokenOut(token: string): StreamTokenOut {
  return { stream_token: token, token_type: "stream", expires_in: 30 };
}

describe("PortalRealtimeClient", () => {
  it("bootstraps stream token and avoids duplicate parallel connections", async () => {
    const tokenProvider = vi.fn(async () => tokenOut("token-one"));
    const sources: FakeEventSource[] = [];
    const client = new PortalRealtimeClient({
      tokenProvider,
      eventSourceFactory: (url) => {
        const source = new FakeEventSource(url);
        sources.push(source);
        return source;
      },
      reconnectBaseMs: 1,
      reconnectMaxMs: 1,
    });

    client.start();
    client.start();
    await waitForTick(1);

    expect(tokenProvider).toHaveBeenCalledTimes(1);
    expect(sources).toHaveLength(1);
    expect(sources[0]?.url).toContain(`/api/realtime/portal?st=${encodeURIComponent("token-one")}`);

    client.stop();
  });

  it("dispatches incoming events to typed subscribers", async () => {
    const tokenProvider = vi.fn(async () => tokenOut("token-two"));
    const sources: FakeEventSource[] = [];
    const client = new PortalRealtimeClient({
      tokenProvider,
      eventSourceFactory: (url) => {
        const source = new FakeEventSource(url);
        sources.push(source);
        return source;
      },
      reconnectBaseMs: 1,
      reconnectMaxMs: 1,
    });

    const typedListener = vi.fn();
    const anyListener = vi.fn();
    client.subscribe("alert.created", typedListener);
    client.subscribeAll(anyListener);

    client.start();
    await waitForTick(1);
    sources[0]?.emitOpen();
    sources[0]?.emitNamed(
      "alert.created",
      JSON.stringify({
        version: 1,
        type: "alert.created",
        timestamp: "2026-04-09T12:00:00Z",
        payload: { alert_id: 42, severity: "high" },
      }),
    );

    expect(typedListener).toHaveBeenCalledTimes(1);
    expect(anyListener).toHaveBeenCalledTimes(1);
    expect(typedListener.mock.calls[0]?.[0]?.type).toBe("alert.created");
    expect(typedListener.mock.calls[0]?.[0]?.payload?.alert_id).toBe(42);

    client.stop();
  });

  it("reconnects by requesting a fresh stream token after source errors", async () => {
    const tokenProvider = vi
      .fn<() => Promise<StreamTokenOut>>()
      .mockResolvedValueOnce(tokenOut("token-a"))
      .mockResolvedValueOnce(tokenOut("token-b"));
    const sources: FakeEventSource[] = [];
    const client = new PortalRealtimeClient({
      tokenProvider,
      eventSourceFactory: (url) => {
        const source = new FakeEventSource(url);
        sources.push(source);
        return source;
      },
      reconnectBaseMs: 1,
      reconnectMaxMs: 1,
    });

    client.start();
    await waitForTick(2);
    expect(sources).toHaveLength(1);

    sources[0]?.emitError();
    await waitForTick(5);

    expect(tokenProvider).toHaveBeenCalledTimes(2);
    expect(sources).toHaveLength(2);
    expect(sources[1]?.url).toContain(`/api/realtime/portal?st=${encodeURIComponent("token-b")}`);

    client.stop();
  });

  it("cleans up listeners and source resources on stop", async () => {
    const tokenProvider = vi.fn(async () => tokenOut("token-cleanup"));
    const sources: FakeEventSource[] = [];
    const client = new PortalRealtimeClient({
      tokenProvider,
      eventSourceFactory: (url) => {
        const source = new FakeEventSource(url);
        sources.push(source);
        return source;
      },
      reconnectBaseMs: 1,
      reconnectMaxMs: 1,
    });

    const listener = vi.fn();
    const unsubscribe = client.subscribe("alert.updated", listener);

    client.start();
    await waitForTick(1);
    unsubscribe();
    client.stop();

    expect(sources[0]?.closed).toBe(true);

    sources[0]?.emitNamed(
      "alert.updated",
      JSON.stringify({
        version: 1,
        type: "alert.updated",
        timestamp: "2026-04-09T12:10:00Z",
        payload: { alert_id: 1, status: "closed" },
      }),
    );
    expect(listener).toHaveBeenCalledTimes(0);

    sources[0]?.emitError();
    await waitForTick(5);
    expect(tokenProvider).toHaveBeenCalledTimes(1);
  });
});
