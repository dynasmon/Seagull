import {
  buildPortalRealtimeSseUrl,
  buildPortalRealtimeWebSocketUrl,
  requestRealtimeStreamToken,
  type StreamTokenOut,
} from "@/shared/realtime/api";
import type { HttpError } from "@/shared/lib/http";
import {
  PORTAL_REALTIME_EVENT_MODE,
  PORTAL_REALTIME_EVENT_SCOPE,
  PORTAL_REALTIME_EVENT_TOPIC,
  PORTAL_REALTIME_EVENT_TYPES,
  PORTAL_REALTIME_TOPICS,
  type PortalRealtimeAnyEvent,
  type PortalRealtimeEnvelope,
  type PortalRealtimeEventType,
  type PortalRealtimeTopic,
  isPortalRealtimeEventType,
  isPortalRealtimeMode,
  isPortalRealtimeTopic,
} from "@/shared/realtime/types";

export type RealtimeConnectionStatus = "idle" | "connecting" | "open" | "retrying" | "stopped";
export type RealtimeTransportKind = "sse" | "ws";

export type PortalRealtimeEventListener<K extends PortalRealtimeEventType> = (event: PortalRealtimeEnvelope<K>) => void;
export type PortalRealtimeAnyListener = (event: PortalRealtimeAnyEvent) => void;
export type RealtimeStatusListener = (status: RealtimeConnectionStatus) => void;
export type RealtimeConnectionSnapshot = {
  status: RealtimeConnectionStatus;
  transport: RealtimeTransportKind | null;
  isFallbackTransport: boolean;
  isVisible: boolean;
};
export type RealtimeConnectionListener = (connection: RealtimeConnectionSnapshot) => void;
export type RealtimeDiagnosticsSnapshot = {
  reconnectCount: number;
  fallbackTransportCount: number;
  fallbackPollingActivations: number;
  tokenFailureCount: number;
  invalidTokenCount: number;
  unauthorizedTopicCount: number;
  redisUnavailableCount: number;
  cursorGapCount: number;
  replayOverflowCount: number;
  malformedEnvelopeCount: number;
  duplicateEventCount: number;
  lastFailureKind: string | null;
  lastFailureMessage: string | null;
  lastFailureAt: string | null;
  lastTransport: RealtimeTransportKind | null;
  lastCloseCode: number | null;
  lastReconnectDelayMs: number;
};
export type RealtimeDiagnosticsListener = (snapshot: RealtimeDiagnosticsSnapshot) => void;

export type EventSourceLike = {
  addEventListener: (type: string, listener: EventListener) => void;
  removeEventListener: (type: string, listener: EventListener) => void;
  close: () => void;
  onopen: ((event: Event) => void) | null;
  onerror: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent<string>) => void) | null;
};

export type WebSocketLike = {
  close: (code?: number, reason?: string) => void;
  onopen: ((event: Event) => void) | null;
  onerror: ((event: Event) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  onmessage: ((event: MessageEvent<string>) => void) | null;
};

export type PortalRealtimeClientOptions = {
  tokenProvider?: () => Promise<StreamTokenOut>;
  eventSourceFactory?: (url: string) => EventSourceLike;
  webSocketFactory?: (url: string) => WebSocketLike;
  reconnectBaseMs?: number;
  reconnectMaxMs?: number;
  baseTopics?: PortalRealtimeTopic[];
  hotTopics?: PortalRealtimeTopic[];
  preferredTransport?: "auto" | RealtimeTransportKind;
};

const DEFAULT_RECONNECT_BASE_MS = 1000;
const DEFAULT_RECONNECT_MAX_MS = 15000;
const DEFAULT_BASE_TOPICS: readonly PortalRealtimeTopic[] = ["agents"];
const DEFAULT_HOT_TOPICS: readonly PortalRealtimeTopic[] = ["investigations", "workflows", "events", "ddos"];
const RECENT_EVENT_KEY_LIMIT = 256;
const DEFAULT_DIAGNOSTICS: RealtimeDiagnosticsSnapshot = {
  reconnectCount: 0,
  fallbackTransportCount: 0,
  fallbackPollingActivations: 0,
  tokenFailureCount: 0,
  invalidTokenCount: 0,
  unauthorizedTopicCount: 0,
  redisUnavailableCount: 0,
  cursorGapCount: 0,
  replayOverflowCount: 0,
  malformedEnvelopeCount: 0,
  duplicateEventCount: 0,
  lastFailureKind: null,
  lastFailureMessage: null,
  lastFailureAt: null,
  lastTransport: null,
  lastCloseCode: null,
  lastReconnectDelayMs: 0,
};

function defaultEventSourceFactory(url: string): EventSourceLike {
  return new EventSource(url) as unknown as EventSourceLike;
}

function defaultWebSocketFactory(url: string): WebSocketLike {
  return new WebSocket(url) as unknown as WebSocketLike;
}

function readVisibility(): boolean {
  if (typeof document === "undefined") return true;
  return document.visibilityState !== "hidden";
}

function parseCursorValue(value: unknown): number {
  const text = String(value ?? "").trim();
  if (!/^[0-9]+$/.test(text)) return 0;
  const out = Number(text);
  if (!Number.isFinite(out) || out < 0) return 0;
  return Math.trunc(out);
}

function nowIso(): string {
  return new Date().toISOString();
}

function classifyHttpFailure(error: unknown): { kind: string; message: string } {
  const status = Number((error as Partial<HttpError> | null)?.status ?? 0);
  const message = error instanceof Error ? error.message : String(error ?? "Realtime bootstrap failed");
  if (status === 401) return { kind: "invalid_token", message };
  if (status === 403) return { kind: "unauthorized_topic", message };
  if (status === 503) return { kind: "redis_unavailable", message };
  return { kind: "token_failure", message };
}

function classifySocketClose(code: number, reason: string): { kind: string; message: string } {
  const normalizedReason = String(reason || "").trim().toLowerCase();
  if (code === 1008 && normalizedReason.includes("invalid")) {
    return { kind: "invalid_token", message: reason || "Invalid realtime token" };
  }
  if (code === 1008 && normalizedReason.includes("topic")) {
    return { kind: "unauthorized_topic", message: reason || "Unauthorized realtime topic" };
  }
  if (code === 1013 || normalizedReason.includes("unavailable")) {
    return { kind: "redis_unavailable", message: reason || "Realtime unavailable" };
  }
  return { kind: "transport_close", message: reason || `Socket closed (${code || 0})` };
}

function isLegacyWebSocketKeepalive(rawData: unknown): boolean {
  if (typeof rawData !== "string") return false;

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawData);
  } catch {
    return false;
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return false;

  const obj = parsed as Record<string, unknown>;
  return obj.kind === "keepalive" && obj.transport === "ws";
}

function isSemanticTransportFailure(kind: string | undefined): boolean {
  return kind === "invalid_token" || kind === "unauthorized_topic" || kind === "redis_unavailable";
}

export function decodePortalRealtimeEnvelope(rawData: unknown): PortalRealtimeAnyEvent | null {
  if (typeof rawData !== "string") return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawData);
  } catch {
    return null;
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;

  const obj = parsed as Record<string, unknown>;
  const rawType = obj.type;
  if (!isPortalRealtimeEventType(rawType)) return null;

  const version = Number(obj.version);
  const timestamp = String(obj.timestamp ?? "").trim();
  if (!Number.isFinite(version) || version < 1 || !timestamp) return null;

  const topic = isPortalRealtimeTopic(obj.topic) ? obj.topic : PORTAL_REALTIME_EVENT_TOPIC[rawType];
  const mode = isPortalRealtimeMode(obj.mode) ? obj.mode : PORTAL_REALTIME_EVENT_MODE[rawType];
  const scope = String(obj.scope ?? PORTAL_REALTIME_EVENT_SCOPE[rawType]).trim();
  if (!scope) return null;

  const cursorNum = parseCursorValue(obj.cursor);
  const cursor = String(cursorNum);

  const payload = obj.payload;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;

  return {
    version,
    topic,
    type: rawType,
    cursor,
    timestamp,
    scope,
    mode,
    payload,
  } as PortalRealtimeAnyEvent;
}

export class PortalRealtimeClient {
  private readonly tokenProvider: () => Promise<StreamTokenOut>;
  private readonly eventSourceFactory: (url: string) => EventSourceLike;
  private readonly webSocketFactory: (url: string) => WebSocketLike;
  private readonly reconnectBaseMs: number;
  private readonly reconnectMaxMs: number;
  private readonly baseTopics: readonly PortalRealtimeTopic[];
  private readonly hotTopics: readonly PortalRealtimeTopic[];
  private readonly preferredTransport: "auto" | RealtimeTransportKind;

  private source: EventSourceLike | null = null;
  private socket: WebSocketLike | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private connectInFlight: Promise<void> | null = null;
  private reconnectAttempt = 0;
  private running = false;
  private isVisible = readVisibility();

  private statusValue: RealtimeConnectionStatus = "idle";
  private transportValue: RealtimeTransportKind | null = null;
  private isFallbackTransportValue = false;
  private readonly statusListeners = new Set<RealtimeStatusListener>();
  private readonly connectionListeners = new Set<RealtimeConnectionListener>();
  private diagnosticsValue: RealtimeDiagnosticsSnapshot = { ...DEFAULT_DIAGNOSTICS };
  private readonly diagnosticsListeners = new Set<RealtimeDiagnosticsListener>();

  private readonly listenersByType = new Map<PortalRealtimeEventType, Set<PortalRealtimeAnyListener>>();
  private readonly anyListeners = new Set<PortalRealtimeAnyListener>();
  private readonly namedSourceListeners = new Map<string, EventListener>();
  private lastCursor = 0;
  private connectedTopicsCsv = "";
  private topicRebindTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly recentEventKeys = new Set<string>();
  private recentEventKeyOrder: string[] = [];
  private connectOrder: RealtimeTransportKind[] = [];
  private connectTransportIndex = 0;
  private transportOpened = false;
  private desiredTransport: RealtimeTransportKind | null = null;
  private currentStreamToken = "";

  constructor(options: PortalRealtimeClientOptions = {}) {
    this.tokenProvider = options.tokenProvider ?? requestRealtimeStreamToken;
    this.eventSourceFactory = options.eventSourceFactory ?? defaultEventSourceFactory;
    this.webSocketFactory = options.webSocketFactory ?? defaultWebSocketFactory;
    this.reconnectBaseMs = Math.max(1, Math.trunc(options.reconnectBaseMs ?? DEFAULT_RECONNECT_BASE_MS));
    this.reconnectMaxMs = Math.max(this.reconnectBaseMs, Math.trunc(options.reconnectMaxMs ?? DEFAULT_RECONNECT_MAX_MS));
    this.baseTopics = this.normalizeTopics(options.baseTopics ?? Array.from(DEFAULT_BASE_TOPICS));
    this.hotTopics = this.normalizeTopics(options.hotTopics ?? Array.from(DEFAULT_HOT_TOPICS));
    this.preferredTransport = options.preferredTransport ?? "auto";
  }

  get status(): RealtimeConnectionStatus {
    return this.statusValue;
  }

  get connection(): RealtimeConnectionSnapshot {
    return {
      status: this.statusValue,
      transport: this.transportValue,
      isFallbackTransport: this.isFallbackTransportValue,
      isVisible: this.isVisible,
    };
  }

  get diagnostics(): RealtimeDiagnosticsSnapshot {
    return this.diagnosticsValue;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.bindVisibilityListener();
    this.ensureConnected();
  }

  stop(): void {
    this.running = false;
    this.clearReconnectTimer();
    this.clearTopicRebindTimer();
    this.teardownTransport();
    this.reconnectAttempt = 0;
    this.connectedTopicsCsv = "";
    this.connectOrder = [];
    this.connectTransportIndex = 0;
    this.transportOpened = false;
    this.desiredTransport = null;
    this.currentStreamToken = "";
    this.clearRecentEventKeys();
    this.unbindVisibilityListener();
    this.setConnectionState({ status: "stopped", transport: null, isFallbackTransport: false });
  }

  subscribeStatus(listener: RealtimeStatusListener): () => void {
    this.statusListeners.add(listener);
    listener(this.statusValue);
    return () => {
      this.statusListeners.delete(listener);
    };
  }

  subscribeConnection(listener: RealtimeConnectionListener): () => void {
    this.connectionListeners.add(listener);
    listener(this.connection);
    return () => {
      this.connectionListeners.delete(listener);
    };
  }

  subscribeDiagnostics(listener: RealtimeDiagnosticsListener): () => void {
    this.diagnosticsListeners.add(listener);
    listener(this.diagnostics);
    return () => {
      this.diagnosticsListeners.delete(listener);
    };
  }

  noteFallbackPollingActivation(): void {
    this.updateDiagnostics((current) => ({
      ...current,
      fallbackPollingActivations: current.fallbackPollingActivations + 1,
    }));
  }

  subscribe<K extends PortalRealtimeEventType>(eventType: K, listener: PortalRealtimeEventListener<K>): () => void {
    let set = this.listenersByType.get(eventType);
    if (!set) {
      set = new Set<PortalRealtimeAnyListener>();
      this.listenersByType.set(eventType, set);
    }
    const wrapped = listener as unknown as PortalRealtimeAnyListener;
    set.add(wrapped);
    this.scheduleTopicRebind();
    return () => {
      const cur = this.listenersByType.get(eventType);
      if (!cur) return;
      cur.delete(wrapped);
      if (cur.size === 0) {
        this.listenersByType.delete(eventType);
      }
      this.scheduleTopicRebind();
    };
  }

  subscribeAll(listener: PortalRealtimeAnyListener): () => void {
    this.anyListeners.add(listener);
    this.scheduleTopicRebind();
    return () => {
      this.anyListeners.delete(listener);
      this.scheduleTopicRebind();
    };
  }

  private bindVisibilityListener(): void {
    if (typeof document === "undefined") return;
    document.addEventListener("visibilitychange", this.handleVisibilityChange);
  }

  private unbindVisibilityListener(): void {
    if (typeof document === "undefined") return;
    document.removeEventListener("visibilitychange", this.handleVisibilityChange);
  }

  private readonly handleVisibilityChange = (): void => {
    const nextVisible = readVisibility();
    if (nextVisible === this.isVisible) return;
    this.isVisible = nextVisible;
    this.emitConnectionState();
    this.scheduleTopicRebind();
  };

  private setConnectionState(next: {
    status?: RealtimeConnectionStatus;
    transport?: RealtimeTransportKind | null;
    isFallbackTransport?: boolean;
  }): void {
    let changed = false;
    if (next.status !== undefined && next.status !== this.statusValue) {
      this.statusValue = next.status;
      changed = true;
      for (const listener of Array.from(this.statusListeners)) {
        listener(this.statusValue);
      }
    }
    if (next.transport !== undefined && next.transport !== this.transportValue) {
      this.transportValue = next.transport;
      changed = true;
    }
    if (
      next.isFallbackTransport !== undefined &&
      next.isFallbackTransport !== this.isFallbackTransportValue
    ) {
      this.isFallbackTransportValue = next.isFallbackTransport;
      changed = true;
    }
    if (changed) {
      this.emitConnectionState();
    }
  }

  private emitConnectionState(): void {
    const snapshot = this.connection;
    for (const listener of Array.from(this.connectionListeners)) {
      listener(snapshot);
    }
  }

  private emitDiagnostics(): void {
    const snapshot = this.diagnostics;
    for (const listener of Array.from(this.diagnosticsListeners)) {
      listener(snapshot);
    }
  }

  private updateDiagnostics(
    updater: (current: RealtimeDiagnosticsSnapshot) => RealtimeDiagnosticsSnapshot,
  ): void {
    this.diagnosticsValue = updater(this.diagnosticsValue);
    this.emitDiagnostics();
  }

  private recordFailure(
    kind: string,
    message: string,
    opts: {
      transport?: RealtimeTransportKind | null;
      closeCode?: number | null;
    } = {},
  ): void {
    this.updateDiagnostics((current) => {
      const next: RealtimeDiagnosticsSnapshot = {
        ...current,
        lastFailureKind: kind,
        lastFailureMessage: message,
        lastFailureAt: nowIso(),
        lastTransport: opts.transport ?? current.lastTransport ?? null,
        lastCloseCode: opts.closeCode ?? current.lastCloseCode ?? null,
      };
      if (kind === "token_failure") next.tokenFailureCount += 1;
      if (kind === "invalid_token") next.invalidTokenCount += 1;
      if (kind === "unauthorized_topic") next.unauthorizedTopicCount += 1;
      if (kind === "redis_unavailable") next.redisUnavailableCount += 1;
      if (kind === "cursor_gap") next.cursorGapCount += 1;
      if (kind === "replay_overflow") next.replayOverflowCount += 1;
      return next;
    });
  }

  private ensureConnected(): void {
    if (!this.running || this.activeTransportHandle() || this.connectInFlight) return;
    this.setConnectionState({
      status: this.reconnectAttempt > 0 ? "retrying" : "connecting",
      transport: null,
      isFallbackTransport: false,
    });

    this.connectInFlight = this.openConnection().finally(() => {
      this.connectInFlight = null;
    });
  }

  private async openConnection(): Promise<void> {
    let tokenOut: StreamTokenOut;
    try {
      tokenOut = await this.tokenProvider();
    } catch (error) {
      const failure = classifyHttpFailure(error);
      this.recordFailure(failure.kind, failure.message, { transport: this.transportValue });
      this.scheduleReconnect();
      return;
    }

    if (!this.running) return;

    const streamToken = String(tokenOut?.stream_token || "").trim();
    if (!streamToken) {
      this.recordFailure("token_failure", "Realtime token endpoint returned an empty token", {
        transport: this.transportValue,
      });
      this.scheduleReconnect();
      return;
    }

    const requestedTopics = this.computeRequestedTopics();
    if (requestedTopics.length === 0) {
      this.setConnectionState({ status: "idle", transport: null, isFallbackTransport: false });
      return;
    }

    this.connectOrder = this.computeTransportOrder(requestedTopics);
    this.connectTransportIndex = 0;
    this.transportOpened = false;
    this.desiredTransport = this.connectOrder[0] ?? null;
    this.connectedTopicsCsv = requestedTopics.join(",");
    this.currentStreamToken = streamToken;
    this.clearRecentEventKeys();
    this.tryOpenTransport(streamToken, requestedTopics, this.lastCursor);
  }

  private tryOpenTransport(streamToken: string, topics: PortalRealtimeTopic[], resumeCursor: number): void {
    const transport = this.connectOrder[this.connectTransportIndex];
    if (!transport) {
      this.scheduleReconnect();
      return;
    }

    this.setConnectionState({
      transport,
      isFallbackTransport: this.connectTransportIndex > 0,
    });
    if (this.connectTransportIndex > 0) {
      this.updateDiagnostics((current) => ({
        ...current,
        fallbackTransportCount: current.fallbackTransportCount + 1,
      }));
    }

    try {
      if (transport === "ws") {
        const socket = this.webSocketFactory(
          buildPortalRealtimeWebSocketUrl({
            streamToken,
            topics,
            cursor: resumeCursor > 0 ? resumeCursor : null,
          }),
        );
        this.attachSocket(socket, transport);
        this.socket = socket;
      } else {
        const source = this.eventSourceFactory(
          buildPortalRealtimeSseUrl({
            streamToken,
            topics,
            cursor: resumeCursor > 0 ? resumeCursor : null,
          }),
        );
        this.attachSource(source, transport);
        this.source = source;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Realtime transport bootstrap failed";
      this.recordFailure("transport_open_failed", message, { transport });
      this.handleTransportFailure(transport, { kind: "transport_open_failed", message });
    }
  }

  private attachSource(source: EventSourceLike, transport: RealtimeTransportKind): void {
    source.onopen = () => {
      if (source !== this.source) return;
      this.handleTransportOpen(transport);
    };
    source.onerror = () => {
      if (source !== this.source) return;
      this.handleTransportFailure(transport, { kind: "transport_error", message: "SSE connection failed" });
    };
    source.onmessage = (event) => {
      this.handleIncomingData("message", event.data);
    };

    this.namedSourceListeners.clear();
    for (const eventType of PORTAL_REALTIME_EVENT_TYPES) {
      const listener: EventListener = (event) => {
        const data = (event as MessageEvent<string>).data;
        this.handleIncomingData(eventType, data);
      };
      this.namedSourceListeners.set(eventType, listener);
      source.addEventListener(eventType, listener);
    }
  }

  private attachSocket(socket: WebSocketLike, transport: RealtimeTransportKind): void {
    socket.onopen = () => {
      if (socket !== this.socket) return;
      this.handleTransportOpen(transport);
    };
    socket.onerror = () => {
      if (socket !== this.socket) return;
      this.handleTransportFailure(transport, { kind: "transport_error", message: "WebSocket transport error" });
    };
    socket.onclose = (event) => {
      if (socket !== this.socket) return;
      const failure = classifySocketClose(event.code, event.reason);
      this.handleTransportFailure(transport, {
        kind: failure.kind,
        message: failure.message,
        closeCode: event.code,
      });
    };
    socket.onmessage = (event) => {
      this.handleIncomingData("message", event.data);
    };
  }

  private handleTransportOpen(transport: RealtimeTransportKind): void {
    if (transport !== this.transportValue) {
      this.setConnectionState({ transport });
    }
    this.transportOpened = true;
    this.reconnectAttempt = 0;
    this.setConnectionState({ status: "open", isFallbackTransport: this.connectTransportIndex > 0 });
  }

  private handleTransportFailure(
    transport: RealtimeTransportKind,
    meta: { kind?: string; message?: string; closeCode?: number } = {},
  ): void {
    if (transport !== this.transportValue) return;
    if (meta.kind) {
      this.recordFailure(meta.kind, meta.message || "Realtime transport failure", {
        transport,
        closeCode: meta.closeCode ?? null,
      });
    }

    const canFallback =
      !this.transportOpened &&
      this.connectTransportIndex + 1 < this.connectOrder.length &&
      !isSemanticTransportFailure(meta.kind);
    this.teardownTransport();

    if (canFallback) {
      this.connectTransportIndex += 1;
      const requestedTopics = this.computeRequestedTopics();
      if (requestedTopics.length === 0) {
        this.setConnectionState({ status: "idle", transport: null, isFallbackTransport: false });
        return;
      }
      this.tryOpenTransport(this.currentStreamToken, requestedTopics, this.lastCursor);
      return;
    }

    this.scheduleReconnect();
  }

  private teardownTransport(): void {
    const source = this.source;
    if (source) {
      for (const [eventType, listener] of this.namedSourceListeners.entries()) {
        source.removeEventListener(eventType, listener);
      }
      this.namedSourceListeners.clear();
      source.onopen = null;
      source.onerror = null;
      source.onmessage = null;
      source.close();
      this.source = null;
    }

    const socket = this.socket;
    if (socket) {
      socket.onopen = null;
      socket.onerror = null;
      socket.onclose = null;
      socket.onmessage = null;
      socket.close();
      this.socket = null;
    }

    this.transportOpened = false;
    this.setConnectionState({ transport: null, isFallbackTransport: false });
  }

  private activeTransportHandle(): EventSourceLike | WebSocketLike | null {
    return this.socket ?? this.source;
  }

  private scheduleReconnect(): void {
    if (!this.running) return;
    if (this.reconnectTimer) return;

    this.setConnectionState({ status: "retrying", transport: null, isFallbackTransport: false });
    const delayMs = this.nextReconnectDelayMs();
    this.updateDiagnostics((current) => ({
      ...current,
      reconnectCount: current.reconnectCount + 1,
      lastReconnectDelayMs: delayMs,
    }));
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.ensureConnected();
    }, delayMs);
  }

  private clearReconnectTimer(): void {
    if (!this.reconnectTimer) return;
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
  }

  private clearTopicRebindTimer(): void {
    if (!this.topicRebindTimer) return;
    clearTimeout(this.topicRebindTimer);
    this.topicRebindTimer = null;
  }

  private scheduleTopicRebind(): void {
    if (!this.running) return;
    if (this.topicRebindTimer) return;
    this.topicRebindTimer = setTimeout(() => {
      this.topicRebindTimer = null;
      this.applyTopicRebind();
    }, 120);
  }

  private applyTopicRebind(): void {
    if (!this.running) return;
    const nextTopics = this.computeRequestedTopics();
    const nextCsv = nextTopics.join(",");
    const nextDesiredTransport = nextTopics.length > 0 ? this.computeTransportOrder(nextTopics)[0] ?? null : null;
    if (nextCsv === this.connectedTopicsCsv && nextDesiredTransport === this.desiredTransport) return;

    this.clearReconnectTimer();
    this.teardownTransport();
    this.connectedTopicsCsv = "";
    this.desiredTransport = null;
    this.currentStreamToken = "";
    if (nextTopics.length === 0) {
      this.setConnectionState({ status: "idle", transport: null, isFallbackTransport: false });
      return;
    }
    this.ensureConnected();
  }

  private normalizeTopics(raw: readonly string[]): PortalRealtimeTopic[] {
    const out: PortalRealtimeTopic[] = [];
    for (const topic of raw) {
      if (!isPortalRealtimeTopic(topic)) continue;
      if (out.includes(topic)) continue;
      out.push(topic);
    }
    return out;
  }

  private computeRequestedTopics(): PortalRealtimeTopic[] {
    const topics = new Set<PortalRealtimeTopic>(this.baseTopics);

    if (this.anyListeners.size > 0) {
      for (const topic of PORTAL_REALTIME_TOPICS) topics.add(topic);
      return Array.from(topics);
    }

    for (const eventType of this.listenersByType.keys()) {
      const topic = PORTAL_REALTIME_EVENT_TOPIC[eventType];
      if (isPortalRealtimeTopic(topic)) {
        topics.add(topic);
      }
    }
    return Array.from(topics);
  }

  private computeTransportOrder(topics: readonly PortalRealtimeTopic[]): RealtimeTransportKind[] {
    if (this.preferredTransport === "sse") return ["sse"];
    if (this.preferredTransport === "ws") return ["ws", "sse"];
    if (!this.isVisible) return ["sse"];

    const wantsHotTransport = topics.some((topic) => this.hotTopics.includes(topic));
    return wantsHotTransport ? ["ws", "sse"] : ["sse"];
  }

  private nextReconnectDelayMs(): number {
    const exponent = Math.min(this.reconnectAttempt, 5);
    const baseDelayMs = Math.min(this.reconnectMaxMs, this.reconnectBaseMs * 2 ** exponent);
    const jitteredDelayMs = Math.round(baseDelayMs * (0.85 + Math.random() * 0.3));
    const delayMs = Math.max(this.reconnectBaseMs, Math.min(this.reconnectMaxMs, jitteredDelayMs));
    this.reconnectAttempt += 1;
    return delayMs;
  }

  private clearRecentEventKeys(): void {
    this.recentEventKeys.clear();
    this.recentEventKeyOrder = [];
  }

  private rememberEventKey(key: string): boolean {
    if (!key) return false;
    if (this.recentEventKeys.has(key)) return true;
    this.recentEventKeys.add(key);
    this.recentEventKeyOrder.push(key);
    if (this.recentEventKeyOrder.length > RECENT_EVENT_KEY_LIMIT) {
      const stale = this.recentEventKeyOrder.shift();
      if (stale) this.recentEventKeys.delete(stale);
    }
    return false;
  }

  private buildEventKey(event: PortalRealtimeAnyEvent): string {
    const cursor = parseCursorValue(event.cursor);
    if (cursor > 0) {
      return `cursor:${cursor}:${event.type}`;
    }
    return JSON.stringify({
      type: event.type,
      topic: event.topic,
      scope: event.scope,
      timestamp: event.timestamp,
      payload: event.payload,
    });
  }

  private handleIncomingData(eventType: string, data: unknown): void {
    const envelope = decodePortalRealtimeEnvelope(data);
    if (!envelope) {
      if (isLegacyWebSocketKeepalive(data)) return;
      this.updateDiagnostics((current) => ({
        ...current,
        malformedEnvelopeCount: current.malformedEnvelopeCount + 1,
      }));
      return;
    }
    if (eventType !== "message" && envelope.type !== eventType) return;
    const eventKey = this.buildEventKey(envelope);
    if (this.rememberEventKey(eventKey)) {
      this.updateDiagnostics((current) => ({
        ...current,
        duplicateEventCount: current.duplicateEventCount + 1,
      }));
      return;
    }
    const cursor = parseCursorValue(envelope.cursor);
    if (cursor > this.lastCursor) this.lastCursor = cursor;
    const reason = String((envelope.payload as Record<string, unknown> | null)?.reason ?? "").trim().toLowerCase();
    if (reason === "cursor_gap" || reason === "replay_overflow") {
      this.recordFailure(reason, `Realtime requested reconciliation: ${reason}`, {
        transport: this.transportValue,
      });
    }
    this.dispatch(envelope);
  }

  private dispatch(event: PortalRealtimeAnyEvent): void {
    const typedListeners = this.listenersByType.get(event.type);
    if (typedListeners) {
      for (const listener of Array.from(typedListeners)) {
        listener(event);
      }
    }
    for (const listener of Array.from(this.anyListeners)) {
      listener(event);
    }
  }
}

export function createPortalRealtimeClient(options: PortalRealtimeClientOptions = {}): PortalRealtimeClient {
  return new PortalRealtimeClient(options);
}
