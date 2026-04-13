import { describe, expect, it } from "vitest";

import type { NetEvent, QueryProvenanceMeta } from "@/features/events/types";
import { buildCombinedQueryMeta, DDOS_EVENT_TYPES, mergeEventsByRecency } from "@/features/events/views/ddos/live_data";

function makeEvent(input: Partial<NetEvent>): NetEvent {
  return {
    id: 1,
    agent_id: "agent-1",
    event_type: "dos_attack",
    schema_version: 1,
    timestamp: "2026-04-12T10:00:00Z",
    extra: {},
    ...input,
  };
}

describe("ddos live data helpers", () => {
  it("merges live and historical events without duplicating the same event", () => {
    const live = [
      makeEvent({ id: 11, timestamp: "2026-04-12T10:02:00Z" }),
      makeEvent({ id: 10, timestamp: "2026-04-12T10:01:00Z" }),
    ];
    const history = [
      makeEvent({ id: 10, timestamp: "2026-04-12T10:01:00Z" }),
      makeEvent({ id: 9, timestamp: "2026-04-12T10:00:00Z" }),
    ];

    const merged = mergeEventsByRecency(live, history);

    expect(merged.map((row) => row.id)).toEqual([11, 10, 9]);
  });

  it("annotates deep dive queries as recent_feed-first when the live head is active", () => {
    const historyMeta: QueryProvenanceMeta = {
      source: "clickhouse",
      fallback_chain: ["clickhouse", "postgres"],
      degraded_reason: "clickhouse_fallback:stale",
      source_freshness_seconds: 12,
      query_latency_ms: 55,
      cache_hit: false,
      approximate: false,
      query_window_start: "2026-04-12T09:00:00Z",
      query_window_end: "2026-04-12T10:00:00Z",
    };

    const meta = buildCombinedQueryMeta({
      liveSourceActive: true,
      historyMeta,
    });

    expect(meta?.source).toBe("recent_feed");
    expect(meta?.fallback_chain).toEqual(["recent_feed", "clickhouse", "postgres"]);
    expect(meta?.degraded_reason).toBe("clickhouse_fallback:stale");
  });

  it("keeps the supported DDoS event types explicit", () => {
    expect(DDOS_EVENT_TYPES).toEqual(["dos_attack", "ddos_telemetry"]);
  });
});
