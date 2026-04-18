import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { useAgentsCatalog } from "@/app/providers";
import { DataPaginationFooter, DataQueryStateBanner, DataStatsStrip, DataViewToolbar } from "@/shared/components/DataView";
import EmptyState from "@/shared/components/EmptyState";
import { useUrlQueryState } from "@/shared/hooks/useUrlQueryState";
import { getErrorMessage } from "@/shared/lib/errors";
import { clampInt } from "@/shared/lib/filters";
import { getIntParam, getStringParam, setOptionalParam } from "@/shared/lib/urlParams";
import { useLiveRefresh, usePortalRealtime, usePortalRealtimeSubscription } from "@/shared/realtime";

import { getDdosLiveSnapshot, huntEvents } from "../../api";
import EventDrawer from "../../components/EventDrawer";
import { compactRowToEvent, describeLiveSurface, mergeLiveEvents } from "../../live";
import { isDdosEvent } from "../../lib/ddos";
import type { NetEvent, QueryProvenanceMeta } from "../../types";
import EventsStreamPage from "../stream/page";

import DdosDeepDive from "./DdosDeepDive";

type DdosPanel = "stream" | "deep";

type DdosQueryState = {
  panel: DdosPanel;
  agent_id: string;
  since_minutes: number;
  limit: number;
  event_id: number | null;
};

const DEFAULTS: DdosQueryState = {
  panel: "stream",
  agent_id: "",
  since_minutes: 60 * 12,
  limit: 200,
  event_id: null,
};

function parsePanel(raw: string | null): DdosPanel {
  return raw === "deep" ? "deep" : "stream";
}

export default function DdosEventsPage() {
  const navigate = useNavigate();
  const { agents } = useAgentsCatalog();
  const { connection } = usePortalRealtime();

  const [query, setQuery] = useUrlQueryState<DdosQueryState>({
    parse: (sp) => ({
      panel: parsePanel(sp.get("panel")),
      agent_id: getStringParam(sp, "agent_id", ""),
      since_minutes: getIntParam(sp, "since_minutes", { min: 1, max: 60 * 24 * 30, fallback: DEFAULTS.since_minutes }),
      limit: getIntParam(sp, "limit", { min: 25, max: 500, fallback: DEFAULTS.limit }),
      event_id: clampInt(sp.get("event_id"), 0, Number.MAX_SAFE_INTEGER, 0) || null,
    }),
    serialize: (state) => {
      const sp = new URLSearchParams();
      setOptionalParam(sp, "panel", state.panel === "stream" ? null : state.panel);
      setOptionalParam(sp, "agent_id", state.agent_id || null);
      setOptionalParam(sp, "since_minutes", state.since_minutes === DEFAULTS.since_minutes ? null : state.since_minutes);
      setOptionalParam(sp, "limit", state.limit === DEFAULTS.limit ? null : state.limit);
      setOptionalParam(sp, "event_id", state.event_id);
      return sp;
    },
    replace: true,
  });

  const [events, setEvents] = useState<NetEvent[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadMoreError, setLoadMoreError] = useState<string | null>(null);
  const [queryMeta, setQueryMeta] = useState<QueryProvenanceMeta | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const [liveSummary, setLiveSummary] = useState<Record<string, any>>({});
  const [pressure, setPressure] = useState<Record<string, any>>({});

  const reqSeq = useRef(0);
  const didBootRef = useRef(false);

  const agentNameById = useMemo(() => {
    const map: Record<string, string> = {};
    for (const a of agents || []) {
      if (!a?.agent_id) continue;
      map[a.agent_id] = a.display_name || a.agent_id;
    }
    return map;
  }, [agents]);

  const load = useCallback(async () => {
    if (query.panel !== "deep") return;
    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);

    try {
      const payload = await getDdosLiveSnapshot({
        limit: query.limit,
        since_minutes: query.since_minutes,
        agent_id: query.agent_id || undefined,
      });
      if (reqSeq.current !== mySeq) return;

      const rows = Array.isArray(payload?.items) ? payload.items.filter((row) => isDdosEvent(row)) : [];
      setEvents(rows);
      setNextCursor(payload?.next_cursor ?? null);
      setHasMore(Boolean(payload?.has_more));
      setQueryMeta(payload?.meta ?? null);
      setLiveSummary(payload?.live_summary ?? {});
      setPressure(payload?.pressure ?? {});
      setLoadMoreError(null);
      setLastUpdatedAt(Date.now());

      setQuery((prev) => {
        if (prev.event_id && rows.some((row) => row.id === prev.event_id && isDdosEvent(row))) return prev;
        const firstDdos = rows.find((row) => isDdosEvent(row)) || null;
        return { ...prev, event_id: firstDdos?.id ?? null };
      });
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(getErrorMessage(e, "Failed to load DDoS events"));
      setEvents([]);
      setNextCursor(null);
      setHasMore(false);
      setLiveSummary({});
      setPressure({});
    } finally {
      if (reqSeq.current !== mySeq) return;
      setLoading(false);
    }
  }, [query.agent_id, query.limit, query.panel, query.since_minutes, setQuery]);

  const loadMore = useCallback(async () => {
    if (query.panel !== "deep") return;
    const cursor = nextCursor;
    if (!cursor || loading || loadingMore) return;

    setLoadingMore(true);
    setLoadMoreError(null);

    try {
      const payload = await huntEvents({
        page_size: query.limit,
        since_minutes: query.since_minutes,
        agent_id: query.agent_id || undefined,
        cursor,
      });

      const incoming = Array.isArray(payload?.items) ? payload.items : [];
      setEvents((prev) => {
        const seen = new Set(prev.map((e) => `${e.id}|${e.timestamp}`));
        const merged = prev.slice();
        for (const item of incoming) {
          const key = `${item.id}|${item.timestamp}`;
          if (seen.has(key)) continue;
          seen.add(key);
          merged.push(item);
        }
        return merged;
      });

      setNextCursor(payload?.next_cursor ?? null);
      setHasMore(Boolean(payload?.has_more));
      setQueryMeta((prev) => payload?.meta ?? prev);
      setLastUpdatedAt(Date.now());
    } catch (e: any) {
      setLoadMoreError(getErrorMessage(e, "Failed to load older DDoS events"));
    } finally {
      setLoadingMore(false);
    }
  }, [loading, loadingMore, nextCursor, query.agent_id, query.limit, query.panel, query.since_minutes]);

  const live = useLiveRefresh({
    enabled: query.panel === "deep",
    profile: "hot-operational",
    refresh: load,
  });

  useEffect(() => {
    if (query.panel !== "deep") return;
    if (!didBootRef.current) {
      didBootRef.current = true;
      return;
    }
    void load();
  }, [load, query.agent_id, query.limit, query.panel, query.since_minutes]);

  usePortalRealtimeSubscription("ui.events.invalidate", (event) => {
    if (query.panel !== "deep") return;
    if (connection.status === "open" && connection.transport === "ws") return;
    const eventAgentId = String(event.payload?.agent_id || "").trim();
    if (query.agent_id && eventAgentId && eventAgentId !== query.agent_id) return;
    const domains = Array.isArray(event.payload?.domains) ? event.payload.domains.map((value) => String(value)) : [];
    if (domains.length > 0 && !domains.includes("ddos")) return;
    live.invalidate();
  });

  usePortalRealtimeSubscription("ui.ddos.live.patch", (event) => {
    if (query.panel !== "deep") return;
    const payloadAgentId = String(event.payload?.agent_id || "").trim();
    if (query.agent_id && payloadAgentId && payloadAgentId !== query.agent_id) return;

    const incoming = Array.isArray(event.payload?.events)
      ? event.payload.events.map((row) => compactRowToEvent(row)).filter((row): row is NetEvent => row !== null && isDdosEvent(row))
      : [];

    if (incoming.length > 0) {
      setEvents((prev) => mergeLiveEvents(incoming, prev, Math.max(query.limit * 4, 500)));
      setLastUpdatedAt(Date.now());
      live.markUpdated();
    }

    if (event.payload?.live_summary && typeof event.payload.live_summary === "object") {
      setLiveSummary((prev) => ({ ...prev, ...event.payload.live_summary }));
    }
    if (event.payload?.pressure && typeof event.payload.pressure === "object") {
      setPressure((prev) => ({ ...prev, ...event.payload.pressure }));
    }
    if (event.payload?.requires_reconcile) {
      live.invalidate("invalidate");
    }
  });

  usePortalRealtimeSubscription("ui.ddos.live.invalidate", () => {
    if (query.panel !== "deep") return;
    live.invalidate("invalidate");
  });

  usePortalRealtimeSubscription("ui.overview.storm.patch", (event) => {
    if (query.panel !== "deep") return;
    setPressure((prev) => ({
      ...prev,
      active: Boolean(event.payload?.active),
      protection_active: Boolean(event.payload?.protection_active ?? event.payload?.active),
      phase: event.payload?.phase ?? prev.phase,
      reason: event.payload?.reason ?? prev.reason,
      backlog_events: event.payload?.backlog_events ?? prev.backlog_events,
      backlog_messages: event.payload?.backlog_messages ?? prev.backlog_messages,
    }));
  });

  const ddosEvents = useMemo(() => {
    return events.filter((e) => isDdosEvent(e));
  }, [events]);

  const selectedEvent = useMemo(() => {
    if (!query.event_id) return null;
    return ddosEvents.find((e) => e.id === query.event_id) || null;
  }, [ddosEvents, query.event_id]);

  useEffect(() => {
    if (query.panel !== "deep") return;
    if (!query.event_id) {
      if (!ddosEvents[0]) return;
      setQuery((prev) => (prev.event_id === ddosEvents[0].id ? prev : { ...prev, event_id: ddosEvents[0].id }));
      return;
    }
    if (ddosEvents.some((row) => row.id === query.event_id)) return;
    setQuery((prev) => ({ ...prev, event_id: ddosEvents[0]?.id ?? null }));
  }, [ddosEvents, query.event_id, query.panel, setQuery]);

  const topTarget = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of ddosEvents) {
      const key = `${e.dst_ip || "-"}:${e.dst_port ?? "-"}/${e.proto || "-"}`;
      counts.set(key, (counts.get(key) || 0) + 1);
    }
    let best = "-";
    let bestN = 0;
    for (const [k, n] of counts.entries()) {
      if (n > bestN) {
        best = k;
        bestN = n;
      }
    }
    return best;
  }, [ddosEvents]);

  const topAgent = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of ddosEvents) {
      counts.set(e.agent_id, (counts.get(e.agent_id) || 0) + 1);
    }
    let winner = "-";
    let winnerN = 0;
    for (const [id, n] of counts.entries()) {
      if (n > winnerN) {
        winner = id;
        winnerN = n;
      }
    }
    return winner === "-" ? "-" : (agentNameById[winner] || winner);
  }, [agentNameById, ddosEvents]);

  const liveSurface = useMemo(
    () =>
      describeLiveSurface(connection, {
        degraded: Boolean(queryMeta?.degraded_reason) || Boolean(pressure?.active),
        fallbackPolling: live.state.isFallbackPolling,
      }),
    [connection, live.state.isFallbackPolling, pressure?.active, queryMeta?.degraded_reason],
  );

  const rightToolbar =
    query.panel === "deep" ? (
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={query.agent_id}
          onChange={(e) => setQuery((prev) => ({ ...prev, agent_id: e.target.value, event_id: null }))}
          className="ui-select h-8 min-w-[180px] text-xs"
          aria-label="Agent scope"
        >
          <option value="">All agents</option>
          {(agents || []).map((a) => (
            <option key={a.agent_id} value={a.agent_id}>
              {a.display_name || a.agent_id}
            </option>
          ))}
        </select>

        <select
          value={String(query.since_minutes)}
          onChange={(e) => setQuery((prev) => ({ ...prev, since_minutes: clampInt(e.target.value, 1, 60 * 24 * 30, prev.since_minutes), event_id: null }))}
          className="ui-select h-8 text-xs"
          aria-label="Lookback window"
        >
          <option value={60}>1h</option>
          <option value={6 * 60}>6h</option>
          <option value={12 * 60}>12h</option>
          <option value={24 * 60}>24h</option>
          <option value={3 * 24 * 60}>3d</option>
          <option value={7 * 24 * 60}>7d</option>
        </select>

        <select
          value={String(query.limit)}
          onChange={(e) => setQuery((prev) => ({ ...prev, limit: clampInt(e.target.value, 25, 500, prev.limit), event_id: null }))}
          className="ui-select h-8 text-xs"
          aria-label="Batch size"
        >
          <option value={100}>100</option>
          <option value={200}>200</option>
          <option value={300}>300</option>
          <option value={500}>500</option>
        </select>

        <button type="button" onClick={() => void load()} className="ui-btn-secondary h-8 px-3 text-xs">
          Refresh
        </button>
      </div>
    ) : null;

  if (query.panel === "stream") {
    return (
      <div className="space-y-4">
        <DataViewToolbar
          left={
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setQuery((prev) => ({ ...prev, panel: "stream" }))}
                className="ui-btn-secondary h-8 px-3 text-xs"
              >
                Stream
              </button>
              <button
                type="button"
                onClick={() => setQuery((prev) => ({ ...prev, panel: "deep" }))}
                className="ui-btn h-8 px-3 text-xs"
              >
                Deep Dive
              </button>
            </div>
          }
        />

        <EventsStreamPage forcedScope="ddos" moduleTitle="DDoS Event Stream" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <DataViewToolbar
        left={
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setQuery((prev) => ({ ...prev, panel: "stream" }))}
              className="ui-btn h-8 px-3 text-xs"
            >
              Stream
            </button>
            <button
              type="button"
              onClick={() => setQuery((prev) => ({ ...prev, panel: "deep" }))}
              className="ui-btn-secondary h-8 px-3 text-xs"
            >
              Deep Dive
            </button>
          </div>
        }
        right={rightToolbar}
      />

      <DataStatsStrip
        stats={[
          { label: "DDoS events", value: ddosEvents.length },
          { label: "Top target", value: topTarget },
          { label: "Top agent", value: topAgent },
          { label: "Peak PPS", value: Number(liveSummary.ddos_peak_pps || 0).toFixed(0) },
          { label: "Peak BPS", value: Number(liveSummary.ddos_peak_bps || 0).toFixed(0) },
          { label: "Phase", value: String(pressure.phase || "ok") },
          { label: "Live status", value: liveSurface.label, hint: `${liveSurface.transport ?? "poll"}${lastUpdatedAt ? ` · ${new Date(lastUpdatedAt).toLocaleTimeString()}` : ""}` },
          { label: "Scope", value: query.agent_id || "all agents", hint: `Lookback ${query.since_minutes}m` },
          { label: "Batch size", value: query.limit },
        ]}
      />

      {queryMeta ? (
        <DataQueryStateBanner
          tone={queryMeta.degraded_reason || liveSurface.tone === "warning" ? "warning" : "neutral"}
          message={`source ${queryMeta.source}${typeof queryMeta.source_freshness_seconds === "number" ? ` · ${queryMeta.source_freshness_seconds}s` : ""}${queryMeta.cache_hit ? " · cache" : ""}${queryMeta.degraded_reason ? ` · degraded (${queryMeta.degraded_reason})` : ""} · ${liveSurface.label}${connection.transport ? ` (${connection.transport})` : ""}${pressure?.phase ? ` · phase ${pressure.phase}` : ""}`}
          right={queryMeta.query_latency_ms != null ? `${Math.round(queryMeta.query_latency_ms)}ms` : undefined}
        />
      ) : null}

      {loading && ddosEvents.length === 0 ? <EmptyState title="Loading DDoS telemetry" description="Fetching deep-dive event window..." /> : null}
      {error && ddosEvents.length === 0 ? <EmptyState title="Unable to load DDoS telemetry" description={error} /> : null}
      {!loading && !error && ddosEvents.length === 0 ? <EmptyState title="No DDoS detections" description="No DDoS-classified events in the selected scope." /> : null}

      {ddosEvents.length > 0 ? (
        <>
          <DdosDeepDive
            events={ddosEvents}
            selectedId={query.event_id}
            onSelect={(e) => setQuery((prev) => ({ ...prev, event_id: e.id }))}
          />

          <DataPaginationFooter
            totalCount={ddosEvents.length}
            pageSize={query.limit}
            onPageSizeChange={(next) => setQuery((prev) => ({ ...prev, limit: clampInt(next, 25, 500, prev.limit), event_id: null }))}
            pageSizeOptions={[100, 200, 300, 500]}
            hasMore={hasMore}
            loadingMore={loadingMore}
            onLoadMore={() => loadMore()}
            loadMoreLabel="Load older"
            error={loadMoreError}
            onRetry={loadMoreError ? () => loadMore() : undefined}
          />
        </>
      ) : null}

      <EventDrawer
        open={Boolean(query.event_id)}
        event={selectedEvent}
        agentNameById={agentNameById}
        onClose={() => setQuery((prev) => ({ ...prev, event_id: null }))}
        onApplyAgent={(agentId) => setQuery((prev) => ({ ...prev, agent_id: agentId }))}
        onApplyType={() => undefined}
        onApplySearch={(q) => {
          navigate(`/events/ddos?panel=stream&search=${encodeURIComponent(q)}`);
        }}
      />
    </div>
  );
}
