import { describe, expect, it, vi } from "vitest";

import { PortalRealtimeClient } from "@/shared/realtime/client";
import type { EventSourceLike, WebSocketLike } from "@/shared/realtime/client";
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

class FakeWebSocket implements WebSocketLike {
  public onopen: ((event: Event) => void) | null = null;
  public onerror: ((event: Event) => void) | null = null;
  public onclose: ((event: CloseEvent) => void) | null = null;
  public onmessage: ((event: MessageEvent<string>) => void) | null = null;

  public closed = false;

  constructor(public readonly url: string) {}

  close(): void {
    this.closed = true;
  }

  emitOpen(): void {
    this.onopen?.({} as Event);
  }

  emitError(): void {
    this.onerror?.({} as Event);
  }

  emitClose(code = 1000, reason = ""): void {
    this.onclose?.({ code, reason } as CloseEvent);
  }

  emitMessage(rawData: string): void {
    this.onmessage?.({ data: rawData } as MessageLikeEvent);
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
      preferredTransport: "sse",
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
      preferredTransport: "sse",
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
      preferredTransport: "sse",
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

  it("reconnects using last processed cursor", async () => {
    const tokenProvider = vi
      .fn<() => Promise<StreamTokenOut>>()
      .mockResolvedValueOnce(tokenOut("token-a"))
      .mockResolvedValueOnce(tokenOut("token-b"));
    const sources: FakeEventSource[] = [];
    const client = new PortalRealtimeClient({
      tokenProvider,
      preferredTransport: "sse",
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
    sources[0]?.emitOpen();
    sources[0]?.emitNamed(
      "overview.patch",
      JSON.stringify({
        version: 2,
        topic: "overview",
        type: "overview.patch",
        cursor: "9",
        timestamp: "2026-04-09T12:00:00Z",
        scope: "portal:realtime",
        mode: "patch",
        payload: { events_5m_delta: 1 },
      }),
    );

    sources[0]?.emitError();
    await waitForTick(6);

    expect(sources).toHaveLength(2);
    expect(sources[1]?.url).toContain("cursor=9");
    client.stop();
  });

  it("schedules reconnect when event source creation throws", async () => {
    const tokenProvider = vi
      .fn<() => Promise<StreamTokenOut>>()
      .mockResolvedValueOnce(tokenOut("token-a"))
      .mockResolvedValueOnce(tokenOut("token-b"));
    const eventSourceFactory = vi
      .fn<(url: string) => EventSourceLike>()
      .mockImplementationOnce(() => {
        throw new Error("factory failed");
      })
      .mockImplementation((url) => new FakeEventSource(url));

    const client = new PortalRealtimeClient({
      tokenProvider,
      preferredTransport: "sse",
      eventSourceFactory,
      reconnectBaseMs: 1,
      reconnectMaxMs: 1,
    });

    client.start();
    await waitForTick(6);

    expect(tokenProvider).toHaveBeenCalledTimes(2);
    expect(eventSourceFactory).toHaveBeenCalledTimes(2);
    expect(client.status).toBe("retrying");

    client.stop();
  });

  it("ignores malformed payloads and mismatched named events", async () => {
    const tokenProvider = vi.fn(async () => tokenOut("token-ignore"));
    const sources: FakeEventSource[] = [];
    const client = new PortalRealtimeClient({
      tokenProvider,
      preferredTransport: "sse",
      eventSourceFactory: (url) => {
        const source = new FakeEventSource(url);
        sources.push(source);
        return source;
      },
      reconnectBaseMs: 1,
      reconnectMaxMs: 1,
    });

    const listener = vi.fn();
    client.subscribe("alert.created", listener);

    client.start();
    await waitForTick(1);
    sources[0]?.emitOpen();
    sources[0]?.emitNamed("alert.created", "not-json");
    sources[0]?.emitNamed(
      "alert.created",
      JSON.stringify({
        version: 1,
        type: "alert.updated",
        timestamp: "2026-04-09T12:00:00Z",
        payload: { alert_id: 3 },
      }),
    );

    expect(listener).toHaveBeenCalledTimes(0);
    client.stop();
  });

  it("ignores legacy websocket keepalive payloads without counting them as malformed", async () => {
    const tokenProvider = vi.fn(async () => tokenOut("token-keepalive"));
    const sockets: FakeWebSocket[] = [];
    const client = new PortalRealtimeClient({
      tokenProvider,
      preferredTransport: "ws",
      webSocketFactory: (url) => {
        const socket = new FakeWebSocket(url);
        sockets.push(socket);
        return socket;
      },
      reconnectBaseMs: 1,
      reconnectMaxMs: 1,
    });

    client.start();
    await waitForTick(2);
    sockets[0]?.emitOpen();
    sockets[0]?.emitMessage(
      JSON.stringify({
        kind: "keepalive",
        transport: "ws",
        timestamp: "2026-04-09T12:00:00Z",
      }),
    );

    expect(client.diagnostics.malformedEnvelopeCount).toBe(0);
    client.stop();
  });

  it("falls back from websocket to sse before open", async () => {
    const tokenProvider = vi.fn(async () => tokenOut("token-hybrid"));
    const sockets: FakeWebSocket[] = [];
    const sources: FakeEventSource[] = [];
    const client = new PortalRealtimeClient({
      tokenProvider,
      preferredTransport: "ws",
      webSocketFactory: (url) => {
        const socket = new FakeWebSocket(url);
        sockets.push(socket);
        return socket;
      },
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

    expect(sockets).toHaveLength(1);
    expect(sockets[0]?.url).toContain("/api/realtime/portal/ws?");

    sockets[0]?.emitError();
    await waitForTick(2);

    expect(sources).toHaveLength(1);
    expect(sources[0]?.url).toContain(`/api/realtime/portal?st=${encodeURIComponent("token-hybrid")}`);

    sources[0]?.emitOpen();
    expect(client.connection.transport).toBe("sse");
    expect(client.connection.isFallbackTransport).toBe(true);

    client.stop();
  });

  it("does not fall back to sse on explicit websocket auth closes before open", async () => {
    const tokenProvider = vi.fn(async () => tokenOut("token-auth-close"));
    const sockets: FakeWebSocket[] = [];
    const sources: FakeEventSource[] = [];
    const client = new PortalRealtimeClient({
      tokenProvider,
      webSocketFactory: (url) => {
        const socket = new FakeWebSocket(url);
        sockets.push(socket);
        return socket;
      },
      eventSourceFactory: (url) => {
        const source = new FakeEventSource(url);
        sources.push(source);
        return source;
      },
      reconnectBaseMs: 50,
      reconnectMaxMs: 50,
    });

    client.subscribe("ui.events.invalidate", vi.fn());
    client.start();
    await waitForTick(2);

    expect(sockets).toHaveLength(1);

    sockets[0]?.emitClose(1008, "Invalid stream token");
    await waitForTick(10);

    expect(sources).toHaveLength(0);
    expect(client.diagnostics.invalidTokenCount).toBeGreaterThanOrEqual(1);

    client.stop();
  });

  it("dispatches websocket messages and reuses cursor on reconnect", async () => {
    const tokenProvider = vi
      .fn<() => Promise<StreamTokenOut>>()
      .mockResolvedValueOnce(tokenOut("token-ws-a"))
      .mockResolvedValueOnce(tokenOut("token-ws-b"));
    const sockets: FakeWebSocket[] = [];
    const client = new PortalRealtimeClient({
      tokenProvider,
      preferredTransport: "ws",
      webSocketFactory: (url) => {
        const socket = new FakeWebSocket(url);
        sockets.push(socket);
        return socket;
      },
      reconnectBaseMs: 1,
      reconnectMaxMs: 1,
    });

    const listener = vi.fn();
    client.subscribe("overview.patch", listener);

    client.start();
    await waitForTick(2);
    sockets[0]?.emitOpen();
    sockets[0]?.emitMessage(
      JSON.stringify({
        version: 2,
        topic: "overview",
        type: "overview.patch",
        cursor: "11",
        timestamp: "2026-04-09T12:00:00Z",
        scope: "portal:realtime",
        mode: "patch",
        payload: { events_5m_delta: 3 },
      }),
    );

    expect(listener).toHaveBeenCalledTimes(1);
    expect(client.connection.transport).toBe("ws");

    sockets[0]?.emitClose(1006, "transport dropped");
    await waitForTick(6);

    expect(sockets).toHaveLength(2);
    expect(sockets[1]?.url).toContain("cursor=11");

    client.stop();
  });

  it("records diagnostics for replay recovery and explicit websocket auth failures", async () => {
    const tokenProvider = vi
      .fn<() => Promise<StreamTokenOut>>()
      .mockResolvedValueOnce(tokenOut("token-auth-a"))
      .mockResolvedValueOnce(tokenOut("token-auth-b"));
    const sockets: FakeWebSocket[] = [];
    const client = new PortalRealtimeClient({
      tokenProvider,
      webSocketFactory: (url) => {
        const socket = new FakeWebSocket(url);
        sockets.push(socket);
        return socket;
      },
      reconnectBaseMs: 1,
      reconnectMaxMs: 1,
    });

    client.subscribe("ui.events.invalidate", vi.fn());
    client.start();
    await waitForTick(2);
    sockets[0]?.emitOpen();
    sockets[0]?.emitMessage(
      JSON.stringify({
        version: 2,
        topic: "events",
        type: "ui.events.invalidate",
        cursor: "17",
        timestamp: "2026-04-09T12:00:00Z",
        scope: "portal:realtime",
        mode: "invalidate",
        payload: { reason: "replay_overflow" },
      }),
    );
    sockets[0]?.emitClose(1008, "Invalid stream token");
    await waitForTick(6);

    expect(client.diagnostics.replayOverflowCount).toBe(1);
    expect(client.diagnostics.invalidTokenCount).toBeGreaterThanOrEqual(1);
    expect(client.diagnostics.reconnectCount).toBeGreaterThanOrEqual(1);

    client.stop();
  });

  it("cleans up listeners and source resources on stop", async () => {
    const tokenProvider = vi.fn(async () => tokenOut("token-cleanup"));
    const sources: FakeEventSource[] = [];
    const client = new PortalRealtimeClient({
      tokenProvider,
      preferredTransport: "sse",
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
