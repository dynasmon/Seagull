import type { NetEvent, QueryProvenanceMeta } from "../../types";

export const DDOS_EVENT_TYPES = ["dos_attack", "ddos_telemetry"] as const;

export function mergeEventsByRecency(primary: NetEvent[], secondary: NetEvent[]): NetEvent[] {
  const merged = new Map<string, NetEvent>();
  for (const row of [...primary, ...secondary]) {
    const key = `${String(row.timestamp || "")}|${Number(row.id) || 0}`;
    if (!row.timestamp || merged.has(key)) continue;
    merged.set(key, row);
  }
  return Array.from(merged.values()).sort((a, b) => {
    const tsDiff = new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    if (tsDiff !== 0) return tsDiff;
    return (Number(b.id) || 0) - (Number(a.id) || 0);
  });
}

export function buildCombinedQueryMeta(args: {
  liveSourceActive: boolean;
  historyMeta: QueryProvenanceMeta | null;
  degradedReason?: string | null;
}): QueryProvenanceMeta | null {
  const historyMeta = args.historyMeta;
  if (!args.liveSourceActive && !historyMeta) return null;

  if (!args.liveSourceActive) {
    if (historyMeta) return historyMeta;
    return {
      source: "recent_feed",
      fallback_chain: ["recent_feed"],
      degraded_reason: args.degradedReason ?? null,
      source_freshness_seconds: 0,
      query_latency_ms: null,
      cache_hit: false,
      approximate: false,
      query_window_start: null,
      query_window_end: null,
    };
  }

  const fallbackChain = [
    "recent_feed",
    ...(historyMeta?.fallback_chain || []),
    ...(historyMeta?.source ? [historyMeta.source] : []),
  ].filter((value, index, array) => array.indexOf(value) === index);

  return {
    source: "recent_feed",
    fallback_chain: fallbackChain,
    degraded_reason: args.degradedReason ?? historyMeta?.degraded_reason ?? null,
    source_freshness_seconds: 0,
    query_latency_ms: historyMeta?.query_latency_ms ?? null,
    cache_hit: Boolean(historyMeta?.cache_hit),
    approximate: Boolean(historyMeta?.approximate),
    query_window_start: historyMeta?.query_window_start ?? null,
    query_window_end: historyMeta?.query_window_end ?? null,
  };
}
