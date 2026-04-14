import { apiPost } from "@/shared/lib/http";
import type { PortalRealtimeTopic } from "@/shared/realtime/types";

export type StreamTokenOut = {
  stream_token: string;
  token_type: "stream";
  expires_in: number;
};

export type PortalRealtimeStreamRequest = {
  streamToken: string;
  topics: readonly PortalRealtimeTopic[];
  cursor?: string | number | null;
};

export function requestRealtimeStreamToken(): Promise<StreamTokenOut> {
  return apiPost<StreamTokenOut>("/api/realtime/token");
}

function buildPortalRealtimeQuery(request: PortalRealtimeStreamRequest): string {
  const params = new URLSearchParams();
  params.set("st", request.streamToken);
  if (request.topics.length > 0) {
    params.set("topics", request.topics.join(","));
  }
  const cursor = String(request.cursor ?? "").trim();
  if (cursor) {
    params.set("cursor", cursor);
  }
  return params.toString();
}

export function buildPortalRealtimeSseUrl(request: PortalRealtimeStreamRequest): string {
  return `/api/realtime/portal?${buildPortalRealtimeQuery(request)}`;
}

export function buildPortalRealtimeWebSocketUrl(request: PortalRealtimeStreamRequest): string {
  const path = `/api/realtime/portal/ws?${buildPortalRealtimeQuery(request)}`;
  if (typeof window === "undefined") {
    return path;
  }
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}${path}`;
}
