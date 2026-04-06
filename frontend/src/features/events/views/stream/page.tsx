import type { CSSProperties, ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import AsyncState from "@/shared/components/AsyncState";
import { cx } from "@/shared/lib/cx";
import { getErrorMessage } from "@/shared/lib/errors";
import { clampInt, normalizeFilterText, normalizeSearchText } from "@/shared/lib/filters";

import { useAgentsCatalog } from "@/app/providers";

import { huntEvents } from "../../api";
import EventDrawer from "../../components/EventDrawer";
import EventExplorer from "../../components/EventExplorer";
import EventsFilters from "../../components/EventsFilters";
import EventsTable from "../../components/EventsTable";
import { buildTopCounts } from "../../lib/aggregates";
import type { NetEvent, QueryProvenanceMeta } from "../../types";

type ViewCfg = {
  agent_id: string; // empty = all agents
  event_type: string; // empty = all types
  search: string;
  window_minutes: number;
  limit: number;
  auto_refresh: boolean;
  refresh_ms: number;
  compact_rows: boolean;
  show_extra: boolean;
};

const LS_KEY = "nw_events_view_v1";

const DEFAULTS: ViewCfg = {
  agent_id: "",
  event_type: "",
  search: "",
  window_minutes: 60,
  limit: 200,
  auto_refresh: false,
  refresh_ms: 15000,
  compact_rows: false,
  show_extra: true
};

function safeLoadView(): ViewCfg {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw) as Partial<ViewCfg>;
    const merged: ViewCfg = {
      ...DEFAULTS,
      ...parsed,
      window_minutes: clampInt(parsed.window_minutes, 1, 1440, DEFAULTS.window_minutes),
      limit: clampInt(parsed.limit, 10, 500, DEFAULTS.limit),
      refresh_ms: clampInt(parsed.refresh_ms, 2000, 300000, DEFAULTS.refresh_ms),
      agent_id: normalizeFilterText(parsed.agent_id),
      event_type: normalizeFilterText(parsed.event_type),
      search: normalizeSearchText(parsed.search),
      auto_refresh: Boolean(parsed.auto_refresh),
      compact_rows: Boolean(parsed.compact_rows),
      show_extra: Boolean(parsed.show_extra)
    };
    return merged;
  } catch {
    return DEFAULTS;
  }
}

function persistView(v: ViewCfg) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(v));
  } catch {
    // no-op
  }
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

function Panel(props: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  style?: CSSProperties;
  scrollY?: boolean;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <div className={cx("rounded-xl border border-border/60 bg-background/70 backdrop-blur-md flex flex-col min-h-0", props.className)}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-border/60 bg-muted/10">
        <div className="text-sm font-semibold tracking-tight truncate">{props.title}</div>
        {props.right ? <div className="text-xs text-muted-foreground truncate">{props.right}</div> : null}
      </div>

      <div
        className={cx("p-4 min-h-0 grow", props.scrollY && "overflow-y-auto", props.bodyClassName)}
        style={props.style}
      >
        {props.children}
      </div>
    </div>
  );
}

function SmallToggle({
  label,
  checked,
  onChange,
  hint
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  hint?: string;
}) {
  return (
    <label className="flex items-start gap-3 rounded-lg border border-border/60 bg-background/40 px-3 py-2">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-1"
      />
      <div className="min-w-0">
        <div className="text-[12px] font-mono text-foreground">{label}</div>
        {hint ? <div className="mt-1 text-[11px] text-muted-foreground">{hint}</div> : null}
      </div>
    </label>
  );
}

export default function EventsPage() {
  const { agents } = useAgentsCatalog();
  const [searchParams, setSearchParams] = useSearchParams();

  const [view, setView] = useState<ViewCfg>(() => safeLoadView());
  const viewRef = useRef(view);
  useEffect(() => {
    viewRef.current = view;
    persistView(view);
  }, [view]);

  const [drawerId, setDrawerId] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [queryMeta, setQueryMeta] = useState<QueryProvenanceMeta | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);

  // Keep the last known events around for "soft" refresh errors (no flicker).
  const eventsRef = useRef<NetEvent[]>([]);
  useEffect(() => {
    eventsRef.current = events;
  }, [events]);

  const viewSnapshotRef = useRef<ViewCfg>(view);
  useEffect(() => {
    viewSnapshotRef.current = view;
  }, [view]);

  const reqSeq = useRef(0);
  const didInitFromUrl = useRef(false);

  // One-time: hydrate state from URL.
  useEffect(() => {
    if (didInitFromUrl.current) return;
    didInitFromUrl.current = true;

    const agent_id = (searchParams.get("agent_id") ?? "").trim();
    const event_type = (searchParams.get("event_type") ?? "").trim();
    const search = searchParams.get("search") ?? "";
    const window_minutes = clampInt(searchParams.get("window_minutes"), 1, 1440, viewRef.current.window_minutes);
    const limit = clampInt(searchParams.get("limit"), 10, 500, viewRef.current.limit);
    const eventId = clampInt(searchParams.get("event_id"), 0, Number.MAX_SAFE_INTEGER, 0);

    setView((prev) => ({
      ...prev,
      agent_id,
      event_type,
      search,
      window_minutes,
      limit
    }));

    if (eventId > 0) setDrawerId(eventId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep URL in sync with the view (shareable state + deep-link drawer).
  useEffect(() => {
    const sp = new URLSearchParams();

    if (view.agent_id) sp.set("agent_id", view.agent_id);
    if (view.event_type) sp.set("event_type", view.event_type);
    if (view.search) sp.set("search", view.search);

    if (view.window_minutes !== DEFAULTS.window_minutes) sp.set("window_minutes", String(view.window_minutes));
    if (view.limit !== DEFAULTS.limit) sp.set("limit", String(view.limit));

    if (drawerId !== null) sp.set("event_id", String(drawerId));

    if (sp.toString() !== searchParams.toString()) {
      setSearchParams(sp, { replace: true });
    }
  }, [view.agent_id, view.event_type, view.search, view.window_minutes, view.limit, drawerId, searchParams, setSearchParams]);

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

    const agent_id = viewRef.current.agent_id ? viewRef.current.agent_id : undefined;
    const event_type = viewRef.current.event_type ? viewRef.current.event_type : undefined;
    const search = (viewRef.current.search || "").trim() || undefined;
    const since_minutes = viewRef.current.window_minutes;
    const page_size = viewRef.current.limit;

    try {
      const payload = await huntEvents({
        page_size,
        agent_id,
        event_type,
        since_minutes,
        search,
      });
      if (reqSeq.current !== mySeq) return;

      const rows = Array.isArray(payload?.items) ? payload.items : [];
      setEvents(rows);
      setNextCursor(payload?.next_cursor ?? null);
      setHasMore(Boolean(payload?.has_more));
      setQueryMeta(payload?.meta ?? null);
      setLastUpdatedAt(Date.now());
      setSelectedId((prev) => {
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
  }, []);

  const loadMore = useCallback(async () => {
    const cursor = nextCursor;
    if (!cursor || loadingMore || loading) return;
    setLoadingMore(true);
    setError(null);

    const v = viewSnapshotRef.current;
    const agent_id = v.agent_id ? v.agent_id : undefined;
    const event_type = v.event_type ? v.event_type : undefined;
    const search = (v.search || "").trim() || undefined;

    try {
      const payload = await huntEvents({
        page_size: v.limit,
        cursor,
        agent_id,
        event_type,
        since_minutes: v.window_minutes,
        search,
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
      setError(getErrorMessage(e, "Failed to load older events"));
    } finally {
      setLoadingMore(false);
    }
  }, [nextCursor, loadingMore, loading]);

  useEffect(() => {
    const t = window.setTimeout(() => load(), 180);
    return () => window.clearTimeout(t);
  }, [load, view.agent_id, view.event_type, view.search, view.window_minutes, view.limit]);

  useEffect(() => {
    if (!view.auto_refresh) return;
    const t = window.setInterval(() => {
      load();
    }, view.refresh_ms);
    return () => window.clearInterval(t);
  }, [view.auto_refresh, view.refresh_ms, load]);

  const visible = events;

  const drawerEvent = useMemo(() => {
    if (drawerId === null) return null;
    return events.find((e) => e.id === drawerId) || null;
  }, [events, drawerId]);

  // If we opened the page with ?event_id=..., try to highlight it.
  useEffect(() => {
    if (drawerId === null) return;
    if (!drawerEvent) return;
    setSelectedId(drawerId);
  }, [drawerId, drawerEvent]);

  const typeCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of events) {
      const k = (e.event_type || "").trim();
      if (!k) continue;
      m.set(k, (m.get(k) || 0) + 1);
    }
    return Array.from(m.entries())
      .map(([key, count]) => ({ key, count }))
      .sort((a, b) => (b.count !== a.count ? b.count - a.count : a.key.localeCompare(b.key)));
  }, [events]);

  const topSrc = useMemo(() => buildTopCounts(visible.map((e) => e.src_ip ?? null), 10), [visible]);
  const topDst = useMemo(() => buildTopCounts(visible.map((e) => e.dst_ip ?? null), 10), [visible]);
  const uniqAgents = useMemo(() => new Set(visible.map((e) => e.agent_id)).size, [visible]);

  const patch = useCallback((next: Partial<ViewCfg>) => {
    setView((prev) => {
      const merged: ViewCfg = {
        ...prev,
        ...next
      };
      merged.agent_id = normalizeFilterText(merged.agent_id);
      merged.event_type = normalizeFilterText(merged.event_type);
      merged.search = normalizeSearchText(merged.search);
      merged.window_minutes = clampInt(merged.window_minutes, 1, 1440, DEFAULTS.window_minutes);
      merged.limit = clampInt(merged.limit, 10, 500, DEFAULTS.limit);
      merged.refresh_ms = clampInt(merged.refresh_ms, 2000, 300000, DEFAULTS.refresh_ms);
      return merged;
    });
  }, []);

  const isInitialLoading = loading && events.length === 0;
  const isRefreshing = loading && events.length > 0;

  // Keep stable props so the native <select> doesn't get reset mid-selection.
  const filtersValue = useMemo(
    () => ({
      agent_id: view.agent_id || null,
      event_type: view.event_type || null,
      search: view.search,
      window_minutes: view.window_minutes,
      limit: view.limit
    }),
    [view.agent_id, view.event_type, view.search, view.window_minutes, view.limit]
  );

  const onFiltersChange = useCallback(
    (next: { agent_id?: string | null; event_type?: string | null; search?: string | null; window_minutes?: number | null; limit?: number | null }) => {
      patch({
        agent_id: (next.agent_id ?? "") || "",
        event_type: (next.event_type ?? "") || "",
        search: next.search ?? "",
        window_minutes: next.window_minutes ?? DEFAULTS.window_minutes,
        limit: next.limit ?? DEFAULTS.limit
      });
    },
    [patch]
  );

  const headerRight = useMemo(() => {
    if (isInitialLoading) return "Loading…";
    if (error) return "Error";
    const shown = visible.length;
    const suffix = ` (${shown})`;
    const ago = lastUpdatedAt ? fmtTimeAgo(Date.now() - lastUpdatedAt) : "";
    const src = queryMeta ? ` · ${queryMeta.source}` : "";
    return `Events${suffix}${src}${ago ? ` · updated ${ago}` : ""}${isRefreshing ? " · refreshing" : ""}`;
  }, [isInitialLoading, isRefreshing, error, visible.length, lastUpdatedAt, queryMeta]);

  const toolbarRight = (
    <div className="flex items-center gap-2">
      <button
        type="button"
        onClick={() => load()}
        className={cx(
          "rounded-md border border-border/60 bg-background/40",
          "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
          "hover:bg-muted/15 hover:text-foreground",
          "focus:outline-none focus:ring-2 focus:ring-primary/30"
        )}
      >
        Refresh
      </button>

      <button
        type="button"
        onClick={() => {
          setDrawerId(null);
          setSelectedId(null);
          setEvents([]);
          setNextCursor(null);
          setHasMore(false);
          setQueryMeta(null);
          setError(null);
          setLastUpdatedAt(null);
          setView(DEFAULTS);
        }}
        className={cx(
          "rounded-md border border-border/60 bg-background/40",
          "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
          "hover:bg-muted/15 hover:text-foreground",
          "focus:outline-none focus:ring-2 focus:ring-primary/30"
        )}
        title="Reset filters and view options"
      >
        Reset
      </button>
    </div>
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-semibold tracking-tight">Event Stream</div>
        {toolbarRight}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[380px_1fr] gap-4 min-h-0">
        {/* Left: filters + explorer */}
        <div className="space-y-4 min-h-0">
          <Panel
            title="Filters"
            right={view.agent_id ? `Agent: ${agentNameById[view.agent_id] || view.agent_id}` : "All agents"}
          >
            <EventsFilters
              agents={agentOptions}
              busy={isInitialLoading}
              value={filtersValue}
              onChange={onFiltersChange}
            />

            <div className="mt-4 flex items-center justify-between gap-2">
              <div className="text-[11px] text-muted-foreground">Filters apply immediately.</div>
              <button
                type="button"
                onClick={() => load()}
                className={cx(
                  "rounded-md border border-border/60 bg-background/40",
                  "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                  "hover:bg-muted/15 hover:text-foreground",
                  "focus:outline-none focus:ring-2 focus:ring-primary/30"
                )}
              >
                Apply
              </button>
            </div>
          </Panel>

          <Panel title="Display" right={`${uniqAgents} agents`}>
            <div className="space-y-3">
              <SmallToggle
                label="Show details column"
                checked={view.show_extra}
                onChange={(v) => patch({ show_extra: v })}
                hint="Adds a compact ‘Details’ column (rule/user/pps/entropy…)."
              />
              <SmallToggle
                label="Compact rows"
                checked={view.compact_rows}
                onChange={(v) => patch({ compact_rows: v })}
                hint="Tighter table spacing for very high event volume."
              />
              <SmallToggle
                label="Auto refresh"
                checked={view.auto_refresh}
                onChange={(v) => patch({ auto_refresh: v })}
                hint="Polls the backend with your current scope/window."
              />

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
                    Refresh
                  </div>
                  <select
                    value={String(view.refresh_ms)}
                    onChange={(e) => patch({ refresh_ms: clampInt(e.target.value, 2000, 300000, DEFAULTS.refresh_ms) })}
                    className={cx(
                      "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                      "text-[11px] font-mono text-foreground outline-none",
                      "focus:ring-2 focus:ring-primary/30"
                    )}
                    disabled={!view.auto_refresh}
                    title="Auto-refresh interval"
                  >
                    <option value="5000">5s</option>
                    <option value="10000">10s</option>
                    <option value="15000">15s</option>
                    <option value="30000">30s</option>
                    <option value="60000">60s</option>
                  </select>
                </div>
                <div>
                  <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
                    Showing
                  </div>
                  <div className="mt-2 text-[12px] font-mono text-muted-foreground">
                    {visible.length} events
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    {view.search ? "Server search is active" : "No server search"}
                  </div>
                </div>
              </div>
            </div>
          </Panel>

          <Panel title="Explorer" right={view.event_type ? `Type: ${view.event_type}` : "All types"} scrollY style={{ maxHeight: 360 }}>
            <EventExplorer
              types={typeCounts}
              activeType={view.event_type || null}
              onSelectType={(t) => patch({ event_type: t || "" })}
              onClearType={() => patch({ event_type: "" })}
            />
          </Panel>

          <Panel title="Top sources" right={topSrc.length ? "" : "No data"}>
            <div className="space-y-2">
              {topSrc.slice(0, 6).map((r) => (
                <button
                  key={r.key}
                  type="button"
                  onClick={() => patch({ search: r.key })}
                  className={cx(
                    "w-full text-left rounded-md border border-border/60 bg-background/40 px-3 py-2",
                    "hover:bg-muted/10 focus:outline-none focus:ring-2 focus:ring-primary/30"
                  )}
                  title="Click to search"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="truncate text-[12px] font-mono text-foreground">{r.key}</div>
                    <div className="shrink-0 text-[12px] font-mono text-muted-foreground">{r.count}</div>
                  </div>
                </button>
              ))}
              {topSrc.length === 0 ? <div className="text-[12px] text-muted-foreground">-</div> : null}
            </div>
          </Panel>

          <Panel title="Top destinations" right={topDst.length ? "" : "No data"}>
            <div className="space-y-2">
              {topDst.slice(0, 6).map((r) => (
                <button
                  key={r.key}
                  type="button"
                  onClick={() => patch({ search: r.key })}
                  className={cx(
                    "w-full text-left rounded-md border border-border/60 bg-background/40 px-3 py-2",
                    "hover:bg-muted/10 focus:outline-none focus:ring-2 focus:ring-primary/30"
                  )}
                  title="Click to search"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="truncate text-[12px] font-mono text-foreground">{r.key}</div>
                    <div className="shrink-0 text-[12px] font-mono text-muted-foreground">{r.count}</div>
                  </div>
                </button>
              ))}
              {topDst.length === 0 ? <div className="text-[12px] text-muted-foreground">-</div> : null}
            </div>
          </Panel>
        </div>

        {/* Right: stream */}
        <Panel
          title="Event stream"
          right={headerRight}
          className="min-h-[620px]"
          scrollY
          bodyClassName="p-0"
          style={{ height: "calc(100vh - 260px)" }}
        >
          {queryMeta ? (
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 px-3 py-2 text-[11px]">
              <div className={cx("font-mono text-muted-foreground", queryMeta.degraded_reason ? "text-amber-300" : "text-muted-foreground")}>
                {fmtSource(queryMeta)}
                {queryMeta.cache_hit ? " · cache" : ""}
              </div>
              {queryMeta.query_latency_ms != null ? (
                <div className="font-mono text-muted-foreground">latency {Math.round(queryMeta.query_latency_ms)}ms</div>
              ) : null}
            </div>
          ) : null}

          {isInitialLoading || (error && events.length === 0) || visible.length === 0 ? (
            <AsyncState
              loading={isInitialLoading}
              error={error && events.length === 0 ? error : null}
              empty={!isInitialLoading && !error && visible.length === 0}
              loadingLabel="Loading events..."
              errorTitle="Events error"
              emptyTitle="No events"
              emptyDescription={
                view.agent_id
                  ? "No telemetry events matched the current scope/filters."
                  : "No telemetry events matched the current filters across all agents."
              }
              onRetry={() => load()}
            />
          ) : (
            <div className="relative">
              <EventsTable
                rows={visible}
                selectedId={selectedId}
                compact={view.compact_rows}
                showExtra={view.show_extra}
                agentNameById={agentNameById}
                onSelect={(e) => setSelectedId(e.id)}
                onEdit={(e) => {
                  setSelectedId(e.id);
                  setDrawerId(e.id);
                }}
              />

              {isRefreshing ? (
                <div className="absolute right-3 top-3 rounded-md border border-border/60 bg-background/70 px-3 py-2 text-[11px] font-mono text-muted-foreground backdrop-blur">
                  <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-muted-foreground/40 border-t-muted-foreground mr-2 align-[-2px]" />
                  Refreshing…
                </div>
              ) : null}

              {hasMore ? (
                <div className="flex items-center justify-center border-t border-border/60 px-3 py-3">
                  <button
                    type="button"
                    onClick={loadMore}
                    disabled={loadingMore}
                    className={cx(
                      "rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest",
                      "text-muted-foreground hover:bg-muted/15 hover:text-foreground",
                      "focus:outline-none focus:ring-2 focus:ring-primary/30",
                      loadingMore && "opacity-70 cursor-not-allowed"
                    )}
                  >
                    {loadingMore ? "Loading…" : "Load older"}
                  </button>
                </div>
              ) : null}
            </div>
          )}
        </Panel>
      </div>

      {/* Drawer */}
      <EventDrawer
        open={drawerId !== null}
        event={drawerEvent}
        agentNameById={agentNameById}
        onClose={() => setDrawerId(null)}
        onApplyAgent={(agentId) => patch({ agent_id: agentId })}
        onApplyType={(type) => patch({ event_type: type })}
        onApplySearch={(q) => patch({ search: q })}
      />
    </div>
  );
}
