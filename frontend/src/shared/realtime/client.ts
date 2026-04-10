import { requestRealtimeStreamToken, type StreamTokenOut } from "@/shared/realtime/api";
import {
  PORTAL_REALTIME_EVENT_MODE,
  PORTAL_REALTIME_EVENT_SCOPE,
  PORTAL_REALTIME_EVENT_TOPIC,
  PORTAL_REALTIME_TOPICS,
  PORTAL_REALTIME_EVENT_TYPES,
  type PortalRealtimeAnyEvent,
  type PortalRealtimeEnvelope,
  type PortalRealtimeEventType,
  isPortalRealtimeMode,
  isPortalRealtimeEventType,
  isPortalRealtimeTopic,
} from "@/shared/realtime/types";

export type RealtimeConnectionStatus = "idle" | "connecting" | "open" | "retrying" | "stopped";

export type PortalRealtimeEventListener<K extends PortalRealtimeEventType> = (event: PortalRealtimeEnvelope<K>) => void;
export type PortalRealtimeAnyListener = (event: PortalRealtimeAnyEvent) => void;
export type RealtimeStatusListener = (status: RealtimeConnectionStatus) => void;

export type EventSourceLike = {
  addEventListener: (type: string, listener: EventListener) => void;
  removeEventListener: (type: string, listener: EventListener) => void;
  close: () => void;
  onopen: ((event: Event) => void) | null;
  onerror: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent<string>) => void) | null;
};

export type PortalRealtimeClientOptions = {
  tokenProvider?: () => Promise<StreamTokenOut>;
  eventSourceFactory?: (url: string) => EventSourceLike;
  reconnectBaseMs?: number;
  reconnectMaxMs?: number;
};

const DEFAULT_RECONNECT_BASE_MS = 1000;
const DEFAULT_RECONNECT_MAX_MS = 15000;

function defaultEventSourceFactory(url: string): EventSourceLike {
  return new EventSource(url) as unknown as EventSourceLike;
}

function parseCursorValue(value: unknown): number {
  const text = String(value ?? "").trim();
  if (!/^[0-9]+$/.test(text)) return 0;
  const out = Number(text);
  if (!Number.isFinite(out) || out < 0) return 0;
  return Math.trunc(out);
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
  private readonly reconnectBaseMs: number;
  private readonly reconnectMaxMs: number;

  private source: EventSourceLike | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private connectInFlight: Promise<void> | null = null;
  private reconnectAttempt = 0;
  private running = false;

  private statusValue: RealtimeConnectionStatus = "idle";
  private readonly statusListeners = new Set<RealtimeStatusListener>();

  private readonly listenersByType = new Map<PortalRealtimeEventType, Set<PortalRealtimeAnyListener>>();
  private readonly anyListeners = new Set<PortalRealtimeAnyListener>();
  private readonly namedSourceListeners = new Map<string, EventListener>();
  private lastCursor = 0;

  constructor(options: PortalRealtimeClientOptions = {}) {
    this.tokenProvider = options.tokenProvider ?? requestRealtimeStreamToken;
    this.eventSourceFactory = options.eventSourceFactory ?? defaultEventSourceFactory;
    this.reconnectBaseMs = Math.max(1, Math.trunc(options.reconnectBaseMs ?? DEFAULT_RECONNECT_BASE_MS));
    this.reconnectMaxMs = Math.max(this.reconnectBaseMs, Math.trunc(options.reconnectMaxMs ?? DEFAULT_RECONNECT_MAX_MS));
  }

  get status(): RealtimeConnectionStatus {
    return this.statusValue;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.ensureConnected();
  }

  stop(): void {
    this.running = false;
    this.clearReconnectTimer();
    this.teardownSource();
    this.reconnectAttempt = 0;
    this.setStatus("stopped");
  }

  subscribeStatus(listener: RealtimeStatusListener): () => void {
    this.statusListeners.add(listener);
    listener(this.statusValue);
    return () => {
      this.statusListeners.delete(listener);
    };
  }

  subscribe<K extends PortalRealtimeEventType>(eventType: K, listener: PortalRealtimeEventListener<K>): () => void {
    let set = this.listenersByType.get(eventType);
    if (!set) {
      set = new Set<PortalRealtimeAnyListener>();
      this.listenersByType.set(eventType, set);
    }
    const wrapped = listener as unknown as PortalRealtimeAnyListener;
    set.add(wrapped);
    return () => {
      const cur = this.listenersByType.get(eventType);
      if (!cur) return;
      cur.delete(wrapped);
      if (cur.size === 0) {
        this.listenersByType.delete(eventType);
      }
    };
  }

  subscribeAll(listener: PortalRealtimeAnyListener): () => void {
    this.anyListeners.add(listener);
    return () => {
      this.anyListeners.delete(listener);
    };
  }

  private setStatus(next: RealtimeConnectionStatus): void {
    if (this.statusValue === next) return;
    this.statusValue = next;
    for (const listener of Array.from(this.statusListeners)) {
      listener(next);
    }
  }

  private ensureConnected(): void {
    if (!this.running || this.source || this.connectInFlight) return;
    this.setStatus(this.reconnectAttempt > 0 ? "retrying" : "connecting");

    this.connectInFlight = this.openConnection().finally(() => {
      this.connectInFlight = null;
    });
  }

  private async openConnection(): Promise<void> {
    let tokenOut: StreamTokenOut;
    try {
      tokenOut = await this.tokenProvider();
    } catch {
      this.scheduleReconnect();
      return;
    }

    if (!this.running) return;

    const streamToken = String(tokenOut?.stream_token || "").trim();
    if (!streamToken) {
      this.scheduleReconnect();
      return;
    }

    try {
      const params = new URLSearchParams();
      params.set("st", streamToken);
      params.set("topics", PORTAL_REALTIME_TOPICS.join(","));
      if (this.lastCursor > 0) {
        params.set("cursor", String(this.lastCursor));
      }
      const url = `/api/realtime/portal?${params.toString()}`;
      const source = this.eventSourceFactory(url);
      this.attachSource(source);
      this.source = source;
    } catch {
      this.scheduleReconnect();
    }
  }

  private attachSource(source: EventSourceLike): void {
    source.onopen = () => {
      if (source !== this.source) return;
      this.reconnectAttempt = 0;
      this.setStatus("open");
    };
    source.onerror = () => {
      if (source !== this.source) return;
      this.teardownSource();
      this.scheduleReconnect();
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

  private teardownSource(): void {
    const source = this.source;
    if (!source) return;

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

  private scheduleReconnect(): void {
    if (!this.running) return;
    if (this.reconnectTimer) return;

    this.setStatus("retrying");
    const delayMs = this.nextReconnectDelayMs();
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

  private nextReconnectDelayMs(): number {
    const exponent = Math.min(this.reconnectAttempt, 5);
    const delayMs = Math.min(this.reconnectMaxMs, this.reconnectBaseMs * 2 ** exponent);
    this.reconnectAttempt += 1;
    return delayMs;
  }

  private handleIncomingData(eventType: string, data: unknown): void {
    const envelope = decodePortalRealtimeEnvelope(data);
    if (!envelope) return;
    if (eventType !== "message" && envelope.type !== eventType) return;
    const cursor = parseCursorValue(envelope.cursor);
    if (cursor > 0 && cursor <= this.lastCursor) return;
    if (cursor > this.lastCursor) this.lastCursor = cursor;
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
