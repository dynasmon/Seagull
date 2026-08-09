import { useCallback, useEffect, useMemo, useRef, useState, type RefObject } from "react";
import { EuiFacetButton, EuiFacetGroup } from "@elastic/eui";

import { Button } from "@/shared/components/Button";
import {
  DataPaginationFooter,
  DataQueryStateBanner,
  DataStatsStrip,
  DataTableSkeleton,
} from "@/shared/components/DataView";
import EmptyState from "@/shared/components/EmptyState";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { ToggleSwitch } from "@/shared/components/ToggleSwitch";
import { useDataTablePreferences } from "@/shared/hooks/useDataTablePreferences";
import { usePersistentState } from "@/shared/hooks/usePersistentState";
import { useUrlQueryState } from "@/shared/hooks/useUrlQueryState";
import { getErrorMessage } from "@/shared/lib/errors";
import { clampInt, normalizeFilterText, normalizeSearchText } from "@/shared/lib/filters";
import { getIntParam, getStringParam, setOptionalParam } from "@/shared/lib/urlParams";
import { useLiveRefresh, usePortalRealtime, usePortalRealtimeSubscription } from "@/shared/realtime";

import { useAgentsCatalog } from "@/app/providers";
import { agentScopeLabel } from "@/features/agents/lib/identity";

import { getEventStreamSnapshot, huntEvents } from "../../api";
import EventDrawer from "../../components/EventDrawer";
import EventExplorer from "../../components/EventExplorer";
import EventsFilters from "../../components/EventsFilters";
import EventsTable from "../../components/EventsTable";
import { compactRowToEvent, describeLiveSurface, matchesEventStreamFilters, mergeLiveEvents } from "../../live";
import { buildTopCounts } from "../../lib/aggregates";
import { isDdosEvent } from "../../lib/ddos";
import type { NetEvent, QueryProvenanceMeta } from "../../types";

type ViewCfg = {
  agent_id: string;
  event_type: string;
  search: string;
  window_minutes: number;
  limit: number;
  event_id: number | null;
};

type DisplayCfg = {
  auto_refresh: boolean;
  refresh_ms: number;
  show_extra: boolean;
};

type EventsStreamPageProps = {
  forcedEventType?: string;
  forcedScope?: "ddos";
  moduleTitle?: string;
};

const DEFAULTS: ViewCfg = {
  agent_id: "",
  event_type: "",
  search: "",
  window_minutes: 60,
  limit: 200,
  event_id: null,
};

const INSIGHTS_OPEN_KEY = "nw_events_stream_insights_v1";
const INSIGHTS_PANEL_HEIGHT = 168;
const STREAM_MIN_HEIGHT = 380;
const STREAM_BOTTOM_GUTTER = 16;

const DEFAULT_DISPLAY: DisplayCfg = {
  auto_refresh: true,
  refresh_ms: 15000,
  show_extra: true,
};

function sanitizeDisplay(raw: unknown): DisplayCfg {
  const parsed = (raw || {}) as Partial<DisplayCfg>;
  return {
    auto_refresh: Boolean(parsed.auto_refresh),
    refresh_ms: clampInt(parsed.refresh_ms, 2000, 300000, DEFAULT_DISPLAY.refresh_ms),
    show_extra: typeof parsed.show_extra === "boolean" ? parsed.show_extra : DEFAULT_DISPLAY.show_extra,
  };
}

function fmtTimeAgo(ms: number) {
  if (!Number.isFinite(ms) || ms <= 0) return "";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  return `${h}h ago`;
}

function fmtSource(meta: QueryProvenanceMeta | null) {
  if (!meta) return "source: -";
  const fresh = typeof meta.source_freshness_seconds === "number" ? `${meta.source_freshness_seconds}s` : "-";
  const degraded = meta.degraded_reason ? `degraded (${meta.degraded_reason})` : "ok";
  return `source: ${meta.source} · freshness: ${fresh} · ${degraded}`;
}

function normalizeView(input: ViewCfg, pinnedEventType: string, ddosScope = false): ViewCfg {
  const out: ViewCfg = {
    ...input,
    agent_id: normalizeFilterText(input.agent_id),
    event_type: ddosScope ? "" : (pinnedEventType || normalizeFilterText(input.event_type)),
    search: normalizeSearchText(input.search),
    window_minutes: clampInt(input.window_minutes, 1, 1440, DEFAULTS.window_minutes),
    limit: clampInt(input.limit, 10, 500, DEFAULTS.limit),
    event_id: input.event_id && input.event_id > 0 ? Math.trunc(input.event_id) : null,
  };
  if (!ddosScope && pinnedEventType) out.event_type = pinnedEventType;
  return out;
}

function sortRows(rows: NetEvent[], sortKey: string, direction: "asc" | "desc"): NetEvent[] {
  const multiplier = direction === "asc" ? 1 : -1;
  const sorted = rows.slice();

  sorted.sort((a, b) => {
    let left: string | number = "";
    let right: string | number = "";

    if (sortKey === "timestamp") {
      left = Date.parse(a.timestamp || "") || 0;
      right = Date.parse(b.timestamp || "") || 0;
    } else if (sortKey === "agent_id") {
      left = a.agent_id || "";
      right = b.agent_id || "";
    } else if (sortKey === "event_type") {
      left = a.event_type || "";
      right = b.event_type || "";
    } else if (sortKey === "src_ip") {
      left = a.src_ip || "";
      right = b.src_ip || "";
    } else if (sortKey === "dst_ip") {
      left = a.dst_ip || "";
      right = b.dst_ip || "";
    } else {
      left = a.id;
      right = b.id;
    }

    if (typeof left === "number" && typeof right === "number") {
      if (left === right) return (a.id - b.id) * multiplier;
      return (left - right) * multiplier;
    }

    const cmp = String(left).localeCompare(String(right));
    if (cmp === 0) return (a.id - b.id) * multiplier;
    return cmp * multiplier;
  });

  return sorted;
}

function TopList({
  items,
  onPick,
}: {
  items: Array<{ key: string; count: number }>;
  onPick: (key: string) => void;
}) {
  if (items.length === 0) {
    return <div className="text-[12px] text-muted-foreground">-</div>;
  }
  return (
    <EuiFacetGroup layout="vertical" gutterSize="none">
      {items.map((r) => (
        <EuiFacetButton key={r.key} quantity={r.count} onClick={() => onPick(r.key)} title="Click to search">
          <span className="truncate font-mono text-[12px]">{r.key}</span>
        </EuiFacetButton>
      ))}
    </EuiFacetGroup>
  );
}

function DisplayToggle({
  label,
  checked,
  onChange,
  hint,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  hint?: string;
}) {
  return (
    <span className="inline-flex items-center" title={hint}>
      <ToggleSwitch label={label} checked={checked} onChange={(e) => onChange(e.target.checked)} />
    </span>
  );
}

function findScrollParent(el: HTMLElement | null): HTMLElement | null {
  let node = el?.parentElement ?? null;
  while (node) {
    const overflowY = window.getComputedStyle(node).overflowY;
    if (overflowY === "auto" || overflowY === "scroll") return node;
    node = node.parentElement;
  }
  return null;
}

function useViewportFillHeight(ref: RefObject<HTMLElement>, minHeight: number) {
  const [height, setHeight] = useState(minHeight);

  const measure = useCallback(() => {
    const el = ref.current;
    if (!el) return;

    const rect = el.getBoundingClientRect();
    const scroller = findScrollParent(el);
    if (!scroller) {
      setHeight(Math.max(minHeight, Math.round(window.innerHeight - rect.top - STREAM_BOTTOM_GUTTER)));
      return;
    }

    const scrollerRect = scroller.getBoundingClientRect();
    const visibleHeight = Math.min(scrollerRect.bottom, window.innerHeight) - Math.max(scrollerRect.top, 0);
    const offset = rect.top - scrollerRect.top + scroller.scrollTop;
    setHeight(Math.max(minHeight, Math.round(visibleHeight - offset - STREAM_BOTTOM_GUTTER)));
  }, [minHeight, ref]);

  useEffect(measure);

  useEffect(() => {
    const el = ref.current;
    if (!el) return undefined;

    const scroller = findScrollParent(el);
    const observer = new ResizeObserver(measure);
    if (el.parentElement) observer.observe(el.parentElement);
    if (scroller) observer.observe(scroller);
    window.addEventListener("resize", measure);

    return () => {
      observer.disconnect();
      window.removeEventListener("resize", measure);
    };
  }, [measure, ref]);

  return height;
}

export default function EventsPage({ forcedEventType, forcedScope, moduleTitle }: EventsStreamPageProps = {}) {
  const { agents } = useAgentsCatalog();
  const { connection } = usePortalRealtime();
  const ddosScope = forcedScope === "ddos";
  const pinnedEventType = ddosScope ? "" : normalizeFilterText(forcedEventType);

  const tablePrefs = useDataTablePreferences({
    storageKey: `nw_events_stream_table_${pinnedEventType || "all"}_v2`,
    defaultPageSize: DEFAULTS.limit,
    minPageSize: 10,
    maxPageSize: 500,
    defaultCompact: false,
    defaultSort: { key: "timestamp", direction: "desc" },
  });

  const [display, setDisplay] = usePersistentState<DisplayCfg>(
    `nw_events_stream_display_${pinnedEventType || "all"}_v2`,
    DEFAULT_DISPLAY,
    sanitizeDisplay
  );

  const [insightsOpen, setInsightsOpen] = usePersistentState<boolean>(
    INSIGHTS_OPEN_KEY,
    false,
    (raw) => raw === true
  );

  const streamRef = useRef<HTMLDivElement>(null);
  const streamHeight = useViewportFillHeight(streamRef, STREAM_MIN_HEIGHT);

  const parseQuery = useCallback(
    (sp: URLSearchParams): ViewCfg => {
      const view = normalizeView(
        {
          agent_id: getStringParam(sp, "agent_id", ""),
          event_type: pinnedEventType || getStringParam(sp, "event_type", ""),
          search: sp.get("search") ?? "",
          window_minutes: getIntParam(sp, "window_minutes", { min: 1, max: 1440, fallback: DEFAULTS.window_minutes }),
          limit: getIntParam(sp, "limit", { min: 10, max: 500, fallback: tablePrefs.pageSize }),
          event_id: clampInt(sp.get("event_id"), 0, Number.MAX_SAFE_INTEGER, 0) || null,
        },
        pinnedEventType,
        ddosScope
      );
      return view;
    },
    [ddosScope, pinnedEventType, tablePrefs.pageSize]
  );

  const serializeQuery = useCallback(
    (view: ViewCfg): URLSearchParams => {
      const normalized = normalizeView(view, pinnedEventType, ddosScope);
      const sp = new URLSearchParams();
      setOptionalParam(sp, "agent_id", normalized.agent_id || null);
      setOptionalParam(sp, "event_type", ddosScope ? null : (normalized.event_type || null));
      setOptionalParam(sp, "search", normalized.search || null);

      if (normalized.window_minutes !== DEFAULTS.window_minutes) {
        setOptionalParam(sp, "window_minutes", normalized.window_minutes);
      }
      if (normalized.limit !== DEFAULTS.limit) {
        setOptionalParam(sp, "limit", normalized.limit);
      }
      setOptionalParam(sp, "event_id", normalized.event_id);
      return sp;
    },
    [ddosScope, pinnedEventType]
  );

  const [view, setView] = useUrlQueryState<ViewCfg>({ parse: parseQuery, serialize: serializeQuery, replace: true });

  useEffect(() => {
    if (tablePrefs.pageSize === view.limit) return;
    tablePrefs.setPageSize(view.limit);
  }, [tablePrefs, view.limit]);

  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadMoreError, setLoadMoreError] = useState<string | null>(null);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [queryMeta, setQueryMeta] = useState<QueryProvenanceMeta | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);

  const eventsRef = useRef<NetEvent[]>([]);
  useEffect(() => {
    eventsRef.current = events;
  }, [events]);

  const viewRef = useRef(view);
  useEffect(() => {
    viewRef.current = view;
  }, [view]);

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

  const agentOptions = useMemo(() => {
    return (agents || []).map((a) => ({ agent_id: a.agent_id, display_name: a.display_name || a.agent_id }));
  }, [agents]);

  const load = useCallback(async () => {
    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);

    const snapshot = viewRef.current;

    try {
      const payload = await getEventStreamSnapshot({
        limit: snapshot.limit,
        agent_id: snapshot.agent_id || undefined,
        event_type: ddosScope ? undefined : (snapshot.event_type || undefined),
        since_minutes: snapshot.window_minutes,
        search: snapshot.search.trim() || undefined,
      });
      if (reqSeq.current !== mySeq) return;

      const rows = Array.isArray(payload?.items) ? payload.items : [];
      setEvents(rows);
      setNextCursor(payload?.next_cursor ?? null);
      setHasMore(Boolean(payload?.has_more));
      setQueryMeta(payload?.meta ?? null);
      setLoadMoreError(null);
      setLastUpdatedAt(Date.now());
      setSelectedId((prev) => {
        if (snapshot.event_id) return snapshot.event_id;
        if (prev === null) return rows[0]?.id ?? null;
        return rows.some((e) => e.id === prev) ? prev : rows[0]?.id ?? null;
      });
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(getErrorMessage(e, "Failed to load events"));
      if (eventsRef.current.length === 0) {
        setEvents([]);
        setSelectedId(null);
        setNextCursor(null);
        setHasMore(false);
        setQueryMeta(null);
      }
    } finally {
      if (reqSeq.current !== mySeq) return;
      setLoading(false);
    }
  }, [ddosScope]);

  const loadMore = useCallback(async () => {
    const cursor = nextCursor;
    if (!cursor || loadingMore || loading) return;
    setLoadingMore(true);
    setLoadMoreError(null);

    const snapshot = viewRef.current;

    try {
      const payload = await huntEvents({
        page_size: snapshot.limit,
        cursor,
        agent_id: snapshot.agent_id || undefined,
        event_type: ddosScope ? undefined : (snapshot.event_type || undefined),
        since_minutes: snapshot.window_minutes,
        search: snapshot.search.trim() || undefined,
      });

      const incoming = Array.isArray(payload?.items) ? payload.items : [];
      setEvents((prev) => {
        const seen = new Set(prev.map((e) => `${e.timestamp}|${e.id}`));
        const merged = prev.slice();
        for (const row of incoming) {
          const key = `${row.timestamp}|${row.id}`;
          if (seen.has(key)) continue;
          seen.add(key);
          merged.push(row);
        }
        return merged;
      });
      setNextCursor(payload?.next_cursor ?? null);
      setHasMore(Boolean(payload?.has_more));
      setQueryMeta(payload?.meta ?? null);
    } catch (e: any) {
      setLoadMoreError(getErrorMessage(e, "Failed to load older events"));
    } finally {
      setLoadingMore(false);
    }
  }, [ddosScope, loading, loadingMore, nextCursor]);

  const live = useLiveRefresh({
    enabled: display.auto_refresh,
    profile: ddosScope ? "hot-operational" : "operational",
    refresh: load,
  });

  useEffect(() => {
    if (!didBootRef.current) {
      didBootRef.current = true;
      if (display.auto_refresh) return;
    }
    void load();
  }, [display.auto_refresh, load, view.agent_id, view.event_type, view.search, view.window_minutes, view.limit]);

  usePortalRealtimeSubscription("ui.events.invalidate", (event) => {
    if (connection.status === "open" && connection.transport === "ws" && !view.search.trim()) return;
    const eventAgentId = String(event.payload?.agent_id || "").trim();
    if (view.agent_id && eventAgentId && eventAgentId !== view.agent_id) return;
    const domains = Array.isArray(event.payload?.domains) ? event.payload.domains.map((value) => String(value)) : [];
    if (ddosScope && domains.length > 0 && !domains.includes("ddos")) return;
    live.invalidate();
  });

  usePortalRealtimeSubscription("ui.events.stream.append", (event) => {
    if (!display.auto_refresh) return;
    const payloadAgentId = String(event.payload?.agent_id || "").trim();
    if (view.agent_id && payloadAgentId && payloadAgentId !== view.agent_id) return;

    const incoming = Array.isArray(event.payload?.events)
      ? event.payload.events.map((row) => compactRowToEvent(row)).filter((row): row is NetEvent => Boolean(row))
      : [];
    if (incoming.length === 0) {
      if (event.payload?.requires_reconcile) live.invalidate("invalidate");
      return;
    }

    const matching = incoming.filter((row) =>
      matchesEventStreamFilters(
        row,
        {
          agent_id: view.agent_id,
          event_type: view.event_type,
          search: view.search,
          window_minutes: view.window_minutes,
        },
        {
          ddosScope,
          pinnedEventType,
        },
      ),
    );

    if (matching.length > 0) {
      setEvents((prev) => mergeLiveEvents(matching, prev));
      setLastUpdatedAt(Date.now());
      live.markUpdated();
    }

    if (event.payload?.requires_reconcile || view.search.trim()) {
      live.invalidate("invalidate");
    }
  });

  const drawerId = view.event_id;

  const drawerEvent = useMemo(() => {
    if (drawerId === null) return null;
    return events.find((e) => e.id === drawerId) || null;
  }, [events, drawerId]);

  useEffect(() => {
    if (!drawerId || !drawerEvent) return;
    setSelectedId(drawerId);
  }, [drawerEvent, drawerId]);

  const typeCounts = useMemo(() => {
    const m = new Map<string, number>();
    const scopeRows = ddosScope ? events.filter((row) => isDdosEvent(row)) : events;
    for (const e of scopeRows) {
      const k = (e.event_type || "").trim();
      if (!k) continue;
      m.set(k, (m.get(k) || 0) + 1);
    }
    return Array.from(m.entries())
      .map(([key, count]) => ({ key, count }))
      .sort((a, b) => (b.count !== a.count ? b.count - a.count : a.key.localeCompare(b.key)));
  }, [ddosScope, events]);

  const scopedEvents = useMemo(() => {
    return ddosScope ? events.filter((e) => isDdosEvent(e)) : events;
  }, [ddosScope, events]);

  const sortedEvents = useMemo(() => {
    const sortKey = tablePrefs.sort?.key || "timestamp";
    const sortDirection = tablePrefs.sort?.direction || "desc";
    return sortRows(scopedEvents, sortKey, sortDirection);
  }, [scopedEvents, tablePrefs.sort]);

  const topSrc = useMemo(() => buildTopCounts(sortedEvents.map((e) => e.src_ip ?? null), 10), [sortedEvents]);
  const topDst = useMemo(() => buildTopCounts(sortedEvents.map((e) => e.dst_ip ?? null), 10), [sortedEvents]);
  const uniqAgents = useMemo(() => new Set(sortedEvents.map((e) => e.agent_id)).size, [sortedEvents]);

  const patchView = useCallback(
    (next: Partial<ViewCfg>) => {
      setView((prev) => normalizeView({ ...prev, ...next }, pinnedEventType, ddosScope));
    },
    [ddosScope, pinnedEventType, setView]
  );

  const patchDisplay = useCallback(
    (next: Partial<DisplayCfg>) => {
      setDisplay((prev) => sanitizeDisplay({ ...prev, ...next }));
    },
    [setDisplay]
  );

  const isInitialLoading = loading && events.length === 0;
  const isRefreshing = loading && events.length > 0;

  const filtersValue = useMemo(
    () => ({
      agent_id: view.agent_id || null,
      event_type: ddosScope ? null : (view.event_type || null),
      search: view.search,
      window_minutes: view.window_minutes,
      limit: view.limit
    }),
    [ddosScope, view.agent_id, view.event_type, view.limit, view.search, view.window_minutes]
  );

  const onFiltersChange = useCallback(
    (next: { agent_id?: string | null; event_type?: string | null; search?: string | null; window_minutes?: number | null; limit?: number | null }) => {
      const nextLimit = clampInt(next.limit, 10, 500, tablePrefs.pageSize);
      tablePrefs.setPageSize(nextLimit);
      patchView({
        agent_id: (next.agent_id ?? "") || "",
        event_type: ddosScope ? "" : (pinnedEventType || ((next.event_type ?? "") || "")),
        search: next.search ?? "",
        window_minutes: next.window_minutes ?? DEFAULTS.window_minutes,
        limit: nextLimit,
        event_id: view.event_id,
      });
    },
    [ddosScope, patchView, pinnedEventType, tablePrefs, view.event_id]
  );

  const headerRight = useMemo(() => {
    if (isInitialLoading) return "Loading...";
    if (error) return "Error";
    const shown = sortedEvents.length;
    const suffix = ` (${shown})`;
    const ago = lastUpdatedAt ? fmtTimeAgo(Date.now() - lastUpdatedAt) : "";
    const src = queryMeta ? ` · ${queryMeta.source}` : "";
    return `Events${suffix}${src}${ago ? ` · updated ${ago}` : ""}${isRefreshing ? " · refreshing" : ""}`;
  }, [error, isInitialLoading, isRefreshing, lastUpdatedAt, queryMeta, sortedEvents.length]);

  const viewActions = (
    <div className="flex flex-wrap items-center gap-2">
      <Button
        variant={insightsOpen ? "secondary" : "subtle"}
        size="md"
        onClick={() => setInsightsOpen((prev) => !prev)}
        title="Toggle the type/source/destination breakdown above the stream"
      >
        {insightsOpen ? "Hide insights" : "Show insights"}
      </Button>

      <Button variant="subtle" size="md" onClick={() => void load()} title="Refresh now">
        Refresh
      </Button>

      <Button
        variant="subtle"
        size="md"
        onClick={() => {
          setSelectedId(null);
          setEvents([]);
          setNextCursor(null);
          setHasMore(false);
          setQueryMeta(null);
          setError(null);
          setLoadMoreError(null);
          setLastUpdatedAt(null);
          tablePrefs.setPageSize(DEFAULTS.limit);
          tablePrefs.setCompact(false);
          tablePrefs.setSort({ key: "timestamp", direction: "desc" });
          patchDisplay(DEFAULT_DISPLAY);
          setView(normalizeView({ ...DEFAULTS, event_type: pinnedEventType || "" }, pinnedEventType, ddosScope));
        }}
        title="Reset filters and table preferences"
      >
        Reset
      </Button>
    </div>
  );

  const liveSurface = useMemo(
    () =>
      describeLiveSurface(connection, {
        degraded: Boolean(queryMeta?.degraded_reason),
        fallbackPolling: live.state.isFallbackPolling,
      }),
    [connection, live.state.isFallbackPolling, queryMeta?.degraded_reason],
  );

  return (
    <div className="flex min-w-0 flex-col gap-3">
      <Panel padded={false} className="min-w-0">
        <EventsFilters
          agents={agentOptions}
          busy={isInitialLoading}
          value={filtersValue}
          lockEventType={pinnedEventType || null}
          hideEventType={ddosScope}
          onChange={onFiltersChange}
        />

        <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 border-t border-border/60 px-3 py-2">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
            <DisplayToggle
              label="Details column"
              checked={display.show_extra}
              onChange={(v) => patchDisplay({ show_extra: v })}
              hint="Adds a compact details column (rule/user/pps/entropy)."
            />
            <DisplayToggle
              label="Compact rows"
              checked={tablePrefs.compact}
              onChange={(v) => tablePrefs.setCompact(v)}
              hint="Tighter table spacing for high-volume streams."
            />
            <DisplayToggle
              label="Auto refresh"
              checked={display.auto_refresh}
              onChange={(v) => patchDisplay({ auto_refresh: v })}
              hint={display.auto_refresh ? "Uses the shared operational live cadence." : "Manual refresh only."}
            />
            <span className="font-mono text-[10.5px] text-muted-foreground">
              {display.auto_refresh
                ? `${Math.round(live.state.profile.fallbackMs / 1000)}s shared fallback`
                : "manual refresh only"}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2">
              <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                Sort
              </span>
              <span className="w-[188px]">
                <SelectInput
                  value={`${tablePrefs.sort?.key || "timestamp"}:${tablePrefs.sort?.direction || "desc"}`}
                  onChange={(e) => {
                    const [key, direction] = e.target.value.split(":");
                    tablePrefs.setSort({ key, direction: direction === "asc" ? "asc" : "desc" });
                  }}
                  className="font-mono text-[11.5px]"
                  title="Sort visible rows"
                >
                  <option value="timestamp:desc">Time (newest first)</option>
                  <option value="timestamp:asc">Time (oldest first)</option>
                  <option value="event_type:asc">Type (A-Z)</option>
                  <option value="agent_id:asc">Agent (A-Z)</option>
                  <option value="src_ip:asc">Source IP (A-Z)</option>
                </SelectInput>
              </span>
            </label>

            {viewActions}
          </div>
        </div>
      </Panel>

      <DataStatsStrip
        stats={[
          {
            label: "Visible events",
            value: sortedEvents.length,
            hint: `limit ${view.limit}${hasMore ? " · older events available" : ""}`,
          },
          {
            label: "Agents in scope",
            value: uniqAgents,
            hint: agentScopeLabel(agents, view.agent_id),
          },
          {
            label: "Event types",
            value: typeCounts.length,
            hint: typeCounts[0] ? `${typeCounts[0].key} leads with ${typeCounts[0].count}` : "No data",
          },
          {
            label: "Live status",
            value: liveSurface.label,
            tone: liveSurface.tone === "muted" ? "default" : liveSurface.tone,
            hint: `${liveSurface.transport ?? "poll"}${
              lastUpdatedAt ? ` · updated ${fmtTimeAgo(Date.now() - lastUpdatedAt) || "just now"}` : ""
            }`,
          },
        ]}
      />

      {insightsOpen ? (
        <div className="grid min-w-0 gap-3 lg:grid-cols-3">
          <Panel
            title="Event types"
            actions={
              <span className="font-mono text-[10px] text-muted-foreground">
                {ddosScope
                  ? "locked: DDoS scope"
                  : pinnedEventType
                  ? `locked: ${pinnedEventType}`
                  : view.event_type || "all types"}
              </span>
            }
            compact
            scrollY
            style={{ height: INSIGHTS_PANEL_HEIGHT }}
          >
            {pinnedEventType || ddosScope ? (
              <div className="text-[12px] text-muted-foreground">
                {ddosScope
                  ? "Type filtering is locked to preserve the DDoS semantic scope."
                  : "Type filtering is locked for this module."}
              </div>
            ) : (
              <EventExplorer
                types={typeCounts}
                activeType={view.event_type || null}
                onSelectType={(t) => patchView({ event_type: t || "" })}
                onClearType={() => patchView({ event_type: "" })}
              />
            )}
          </Panel>

          <Panel
            title="Top sources"
            actions={
              <span className="font-mono text-[10px] text-muted-foreground">
                {topSrc.length ? "click to search" : "no data"}
              </span>
            }
            compact
            scrollY
            style={{ height: INSIGHTS_PANEL_HEIGHT }}
          >
            <TopList items={topSrc.slice(0, 8)} onPick={(key) => patchView({ search: key })} />
          </Panel>

          <Panel
            title="Top destinations"
            actions={
              <span className="font-mono text-[10px] text-muted-foreground">
                {topDst.length ? "click to search" : "no data"}
              </span>
            }
            compact
            scrollY
            style={{ height: INSIGHTS_PANEL_HEIGHT }}
          >
            <TopList items={topDst.slice(0, 8)} onPick={(key) => patchView({ search: key })} />
          </Panel>
        </div>
      ) : null}

      <div ref={streamRef} className="min-w-0" style={{ height: streamHeight }}>
        <Panel
          title={moduleTitle || "Event stream"}
          actions={<span className="font-mono text-[10px] text-muted-foreground">{headerRight}</span>}
          className="h-full min-w-0"
          bodyClassName="flex min-h-0 min-w-0 flex-col p-0"
        >
          {queryMeta ? (
            <div className="border-b border-border/60 px-3 py-2">
              <DataQueryStateBanner
                tone={queryMeta.degraded_reason || liveSurface.tone === "warning" ? "warning" : "neutral"}
                message={`${fmtSource(queryMeta)}${queryMeta.cache_hit ? " · cache" : ""} · ${liveSurface.label}${connection.transport ? ` (${connection.transport})` : ""}`}
                right={queryMeta.query_latency_ms != null ? `latency ${Math.round(queryMeta.query_latency_ms)}ms` : undefined}
              />
            </div>
          ) : null}

          {isInitialLoading ? (
            <div className="p-3">
              <DataTableSkeleton rows={10} columns={display.show_extra ? 7 : 6} />
            </div>
          ) : null}

          {!isInitialLoading && error && events.length === 0 ? (
            <div className="flex flex-1 flex-col items-center justify-center gap-3 p-4">
              <DataQueryStateBanner tone="danger" message={error} />
              <EmptyState
                title="Events unavailable"
                description={
                  <Button variant="subtle" size="md" onClick={() => load()}>
                    Retry
                  </Button>
                }
              />
            </div>
          ) : null}

          {!isInitialLoading && !error && sortedEvents.length === 0 ? (
            <div className="flex flex-1 items-center justify-center p-4">
              <EmptyState
                title="No events"
                description={
                  ddosScope
                    ? "No DDoS-classified events matched the current scope/filters."
                    : view.agent_id
                    ? "No telemetry events matched the current scope/filters."
                    : "No telemetry events matched the current filters across all agents."
                }
              />
            </div>
          ) : null}

          {!isInitialLoading && (!error || events.length > 0) && sortedEvents.length > 0 ? (
            <div className="relative flex min-h-0 min-w-0 flex-1 flex-col">
              <div className="min-h-0 flex-1 overflow-auto">
                <EventsTable
                  rows={sortedEvents}
                  selectedId={selectedId}
                  compact={tablePrefs.compact}
                  showExtra={display.show_extra}
                  sort={tablePrefs.sort}
                  onSortChange={(next) => tablePrefs.setSort(next)}
                  onSelect={(e) => {
                    setSelectedId(e.id);
                    setView((prev) => ({ ...prev, event_id: e.id }));
                  }}
                />
              </div>

              {isRefreshing ? (
                <div className="absolute right-3 top-3 inline-flex items-center gap-2 rounded-md border border-border bg-card/90 px-2.5 py-1.5 text-[10.5px] font-semibold uppercase tracking-[0.08em] text-muted-foreground backdrop-blur">
                  <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-border/70 border-t-primary" />
                  Refreshing
                </div>
              ) : null}

              <div className="border-t border-border/60 px-3 py-2">
                <DataPaginationFooter
                  totalCount={sortedEvents.length}
                  pageSize={view.limit}
                  onPageSizeChange={(next) => {
                    const limit = clampInt(next, 10, 500, DEFAULTS.limit);
                    tablePrefs.setPageSize(limit);
                    patchView({ limit });
                  }}
                  pageSizeOptions={[25, 50, 100, 200, 300, 500]}
                  hasMore={hasMore}
                  loadingMore={loadingMore}
                  onLoadMore={() => loadMore()}
                  loadMoreLabel="Load older"
                  error={loadMoreError}
                  onRetry={loadMoreError ? () => loadMore() : undefined}
                />
              </div>
            </div>
          ) : null}
        </Panel>
      </div>
      <EventDrawer
        open={drawerId !== null}
        event={drawerEvent}
        agentNameById={agentNameById}
        onClose={() => setView((prev) => ({ ...prev, event_id: null }))}
        onApplyAgent={(agentId) => patchView({ agent_id: agentId, event_id: drawerId })}
        onApplyType={(type) => patchView({ event_type: type, event_id: drawerId })}
        onApplySearch={(q) => patchView({ search: q, event_id: drawerId })}
      />
    </div>
  );
}
