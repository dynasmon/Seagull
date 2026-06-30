import { apiGet, getAccessToken } from "@/shared/lib/http";
import type { ApiGetOptions } from "@/shared/lib/http";

import type { NetEvent } from "../../types";
import type { ProtocolIntelIndicatorKind, ProtocolIntelSummaryResponse } from "./types";

export type ProtocolIntelSummaryParams = {
  since_minutes?: number;
  limit?: number;
  agent_id?: string;
  widen_if_empty?: boolean;
};

function buildSummaryQuery(params?: ProtocolIntelSummaryParams): URLSearchParams {
  const q = new URLSearchParams();
  q.set("since_minutes", String(params?.since_minutes ?? 60 * 12));
  q.set("limit", String(params?.limit ?? 25));
  if (params?.widen_if_empty) q.set("widen_if_empty", "true");
  const agent = (params?.agent_id ?? "").trim();
  if (agent) q.set("agent_id", agent);
  return q;
}

export function getProtocolIntelSummary(params?: ProtocolIntelSummaryParams, opts?: ApiGetOptions) {
  const q = buildSummaryQuery(params);
  return apiGet<ProtocolIntelSummaryResponse>(`/api/events/network/summary?${q.toString()}`, opts);
}

export type ProtocolIntelStreamHandlers = {
  onOverview: (overview: Partial<ProtocolIntelSummaryResponse>) => void;
  onFacet: (name: keyof ProtocolIntelSummaryResponse, items: unknown[]) => void;
};

export async function streamProtocolIntelSummary(
  params: ProtocolIntelSummaryParams,
  handlers: ProtocolIntelStreamHandlers,
  opts?: { signal?: AbortSignal }
): Promise<void> {
  const q = buildSummaryQuery(params);
  const token = getAccessToken();
  const res = await fetch(`/api/events/network/summary/stream?${q.toString()}`, {
    method: "GET",
    headers: {
      Accept: "text/event-stream",
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    credentials: "include",
    signal: opts?.signal
  });
  if (!res.ok || !res.body) {
    const err = new Error(`stream failed: ${res.status}`) as Error & { status?: number };
    err.status = res.status;
    throw err;
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let sep = buffer.indexOf("\n\n");
    while (sep >= 0) {
      const frame = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      sep = buffer.indexOf("\n\n");

      const eventLine = frame.split("\n").find((l) => l.startsWith("event:"));
      const dataLine = frame.split("\n").find((l) => l.startsWith("data:"));
      if (!eventLine || !dataLine) continue;
      const event = eventLine.slice("event:".length).trim();
      let payload: any;
      try {
        payload = JSON.parse(dataLine.slice("data:".length).trim());
      } catch {
        continue;
      }
      if (event === "overview") handlers.onOverview(payload as Partial<ProtocolIntelSummaryResponse>);
      else if (event === "facet") handlers.onFacet(payload.name as keyof ProtocolIntelSummaryResponse, payload.items ?? []);
      else if (event === "done") return;
    }
  }
}

export function getProtocolIntelSamples(params: {
  kind: ProtocolIntelIndicatorKind;
  value: string;
  since_minutes?: number;
  limit?: number;
  agent_id?: string;
}) {
  const q = new URLSearchParams();
  q.set("kind", params.kind);
  q.set("value", params.value);
  q.set("since_minutes", String(params.since_minutes ?? 60 * 12));
  q.set("limit", String(params.limit ?? 50));

  const agent = (params.agent_id ?? "").trim();
  if (agent) q.set("agent_id", agent);

  return apiGet<NetEvent[]>(`/api/events/network/samples?${q.toString()}`);
}
