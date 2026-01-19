import type { CSSProperties, ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";

import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";

import { getAgents, getRecentEvents } from "./api";
import EventsFilters from "./components/EventsFilters";
import EventsTable from "./components/EventsTable";
import { SimpleTimeSeries } from "../overview/components/Charts";
import type { Agent, EventsViewConfig, NetEvent } from "./types";

const STORAGE_KEY = "nw_events_view_v1";

const DEFAULT_CONFIG: EventsViewConfig = {
  agent_id: "",
  event_type: "",
  window_minutes: 60,
  limit: 500,
  search: "",
  auto_refresh: true,
  refresh_ms: 5000,
  compact_rows: true,
  show_extra: true
};

// Grafana-like fixed panel heights.
const H_PANEL_SM = 240;
const H_PANEL_STREAM = 420;
const H_PANEL_DETAILS = 420;

function readConfig(): EventsViewConfig {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_CONFIG;
    const parsed = JSON.parse(raw) as Partial<EventsViewConfig>;
    return {
      ...DEFAULT_CONFIG,
      ...parsed,
      window_minutes: Number(parsed.window_minutes ?? DEFAULT_CONFIG.window_minutes),
      limit: Number(parsed.limit ?? DEFAULT_CONFIG.limit),
      refresh_ms: Number(parsed.refresh_ms ?? DEFAULT_CONFIG.refresh_ms)
    };
  } catch {
    return DEFAULT_CONFIG;
  }
}

function writeConfig(c: EventsViewConfig) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(c));
  } catch {
    // no-op
  }
}

function fmtHHMM(d: Date) {
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit" });
}

function StatTile({
  label,
  value,
  hint,
  tone = "default"
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "default" | "good" | "warn";
}) {
  const valueClass =
    tone === "warn" ? "text-red-500" : tone === "good" ? "text-green-500" : "text-foreground";

  return (
    <div className="border border-border/60 bg-background/80 backdrop-blur-md px-4 py-3">
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1 font-mono">
        {label}
      </div>
      <div className={cx("text-3xl font-bold font-mono tracking-tight leading-none", valueClass)}>
        {value}
      </div>
      {hint && <div className="text-[10px] text-muted-foreground font-mono opacity-70 mt-1">{hint}</div>}
    </div>
  );
}

function Panel({
  title,
  right,
  children,
  scrollY = false,
  className = "",
  style
}: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  scrollY?: boolean;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <div
      className={cx("border border-border/60 bg-background/70 backdrop-blur-sm flex flex-col", className)}
      style={style}
    >
      <div className="flex items-center justify-between border-b border-border/60 bg-muted/10 px-3 py-2 shrink-0">
        <h3 className="text-xs font-bold uppercase tracking-widest font-mono text-primary/90">
          {title}
        </h3>
        {right && (
          <div className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">
            {right}
          </div>
        )}
      </div>
      <div className={cx("p-3 flex-1 min-h-0", scrollY ? "overflow-y-auto" : "overflow-hidden")}>
        {children}
      </div>
    </div>
  );
}

function normalizeDetails(raw: any): Record<string, any> {
  if (!raw) return {};
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw);
    } catch {
      return {};
    }
  }
  if (typeof raw === "object") return raw as Record<string, any>;
  return {};
}

function buildTopCounts(values: Array<string | null | undefined>, limit = 10) {
  const m = new Map<string, number>();
  for (const v of values) {
    if (!v) continue;
    m.set(v, (m.get(v) || 0) + 1);
  }
  return [...m.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([k, count]) => ({ key: k, count }));
}

function buildRateSeries(events: NetEvent[], windowMinutes: number) {
  const now = Date.now();
  const start = now - windowMinutes * 60_000;
  const buckets = new Map<number, number>();

  for (const e of events) {
    const t = new Date(e.timestamp).getTime();
    if (!Number.isFinite(t)) continue;
    if (t < start) continue;
    const minute = Math.floor(t / 60_000) * 60_000;
    buckets.set(minute, (buckets.get(minute) || 0) + 1);
  }

  const points: Array<{ t: string; events: number }> = [];
  for (let t = Math.floor(start / 60_000) * 60_000; t <= now; t += 60_000) {
    const n = buckets.get(t) || 0;
    points.push({ t: fmtHHMM(new Date(t)), events: n });
  }
  return points;
}

function matchesSearch(e: NetEvent, query: string) {
  const q = query.trim().toLowerCase();
  if (!q) return true;

  const hay = [
    e.agent_id,
    e.event_type,
    e.src_ip || "",
    e.dst_ip || "",
    e.proto || "",
    e.src_port ? String(e.src_port) : "",
    e.dst_port ? String(e.dst_port) : "",
    typeof e.bytes === "number" ? String(e.bytes) : "",
    JSON.stringify(e.extra || {})
  ]
    .join(" ")
    .toLowerCase();

  return hay.includes(q);
}

function EventDetails({ event }: { event: NetEvent | null }) {
  if (!event) {
    return (
      <EmptyState
        title="Select an event"
        hint="Click an event row to inspect fields and metadata."
      />
    );
  }

  const extra = normalizeDetails(event.extra);
  const src = event.src_ip ? `${event.src_ip}${event.src_port ? `:${event.src_port}` : ""}` : "-";
  const dst = event.dst_ip ? `${event.dst_ip}${event.dst_port ? `:${event.dst_port}` : ""}` : "-";

  return (
    <div className="space-y-4">
      <div className="grid gap-3">
        <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">
          Summary
        </div>
        <div className="border border-border/60 bg-background/40 p-3">
          <div className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
            {event.event_type}
          </div>
          <div className="mt-1 text-sm">
            <span className="font-mono">{src}</span> → <span className="font-mono">{dst}</span>
            {event.proto ? <span className="text-muted-foreground"> ({event.proto})</span> : null}
          </div>
          <div className="mt-2 text-[11px] text-muted-foreground font-mono">
            agent={event.agent_id} · schema={event.schema_version} · id={event.id}
          </div>
        </div>
      </div>

      <div>
        <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground mb-2">
          Extra
        </div>
        <pre className="border border-border/60 bg-background/40 p-3 text-[11px] leading-relaxed overflow-auto">
          {JSON.stringify(extra, null, 2)}
        </pre>
      </div>
    </div>
  );
}

export default function EventsPage() {
  const [config, setConfig] = useState<EventsViewConfig>(() => readConfig());
  const [agents, setAgents] = useState<Agent[]>([]);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [selected, setSelected] = useState<NetEvent | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);

  const inFlight = useRef(false);

  useEffect(() => {
    writeConfig(config);
  }, [config]);

  useEffect(() => {
    let alive = true;
    getAgents()
      .then((rows) => {
        if (!alive) return;
        setAgents(rows);
      })
      .catch(() => {
        // optional
      });

    return () => {
      alive = false;
    };
  }, []);

  const refresh = async () => {
    if (inFlight.current) return;
    inFlight.current = true;

    try {
      const rows = await getRecentEvents({
        limit: config.limit,
        agent_id: config.agent_id || undefined,
        event_type: config.event_type || undefined
      });

      setEvents(rows);
      setError(null);
      setLastUpdatedAt(new Date());

      if (selected) {
        const still = rows.find((r) => r.id === selected.id) || null;
        setSelected(still);
      }
    } catch (e: any) {
      setError(e?.message || "Failed to load events");
    } finally {
      setIsLoading(false);
      inFlight.current = false;
    }
  };

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config.agent_id, config.event_type, config.limit]);

  useEffect(() => {
    if (!config.auto_refresh) return;
    const t = window.setInterval(() => refresh(), config.refresh_ms);
    return () => window.clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config.auto_refresh, config.refresh_ms, config.agent_id, config.event_type, config.limit]);

  const derived = useMemo(() => {
    const now = Date.now();
    const windowMs = config.window_minutes * 60_000;

    const windowed = events.filter((e) => {
      const t = new Date(e.timestamp).getTime();
      if (!Number.isFinite(t)) return false;
      return now - t <= windowMs;
    });

    const filtered = windowed.filter((e) => matchesSearch(e, config.search));

    const uniqueSrc = new Set(filtered.map((e) => e.src_ip || "").filter(Boolean)).size;
    const uniqueDst = new Set(filtered.map((e) => e.dst_ip || "").filter(Boolean)).size;

    const topTypes = buildTopCounts(filtered.map((e) => e.event_type), 6);
    const topSrc = buildTopCounts(filtered.map((e) => e.src_ip), 8);
    const topDst = buildTopCounts(filtered.map((e) => e.dst_ip), 8);

    const dstToSrcSet = new Map<string, Set<string>>();
    for (const e of filtered) {
      if (!e.dst_ip || !e.src_ip) continue;
      const k = e.dst_ip;
      const s = dstToSrcSet.get(k) || new Set<string>();
      s.add(e.src_ip);
      dstToSrcSet.set(k, s);
    }

    let maxUniqueSrcForDst = 0;
    let maxDst = "";
    for (const [dst, s] of dstToSrcSet.entries()) {
      if (s.size > maxUniqueSrcForDst) {
        maxUniqueSrcForDst = s.size;
        maxDst = dst;
      }
    }

    return {
      filtered,
      uniqueSrc,
      uniqueDst,
      topTypes,
      topSrc,
      topDst,
      maxUniqueSrcForDst,
      maxDst,
      rateSeries: buildRateSeries(filtered, config.window_minutes)
    };
  }, [events, config.window_minutes, config.search]);

  const eventTypes = useMemo(() => {
    const s = new Set<string>();
    for (const e of events) s.add(e.event_type);
    return [...s].sort((a, b) => a.localeCompare(b));
  }, [events]);

  const rightHeader = useMemo(() => {
    const stamp = lastUpdatedAt
      ? `${fmtHHMM(lastUpdatedAt)}${config.auto_refresh ? " · live" : ""}`
      : "";
    return stamp || (isLoading ? "loading" : "");
  }, [lastUpdatedAt, config.auto_refresh, isLoading]);

  return (
    <div className="space-y-6">
      <div>
        <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">
          Telemetry
        </div>
        <h1 className="text-xl font-semibold">Events</h1>
        <p className="text-sm text-muted-foreground">
          Live event stream with configurable filters. Use this view to understand what is happening
          on the wire and inside your agents.
        </p>
        {error && <div className="mt-2 text-sm text-red-400 font-mono">{error}</div>}
      </div>

      <Panel title="Controls" right={rightHeader} style={{ height: "auto" }}>
        <EventsFilters
          agents={agents}
          eventTypes={eventTypes}
          config={config}
          isLoading={isLoading}
          onChange={(next) => setConfig(next)}
          onRefresh={() => refresh()}
        />
      </Panel>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label={`Events (${config.window_minutes}m)`}
          value={derived.filtered.length}
          hint={config.search.trim() ? "search-filtered" : "window-filtered"}
        />
        <StatTile label="Unique sources" value={derived.uniqueSrc} />
        <StatTile label="Unique destinations" value={derived.uniqueDst} />
        <StatTile
          label="Hot destination"
          value={derived.maxDst || "-"}
          hint={derived.maxDst ? `${derived.maxUniqueSrcForDst} unique src` : ""}
          tone={derived.maxUniqueSrcForDst >= 25 ? "warn" : "default"}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-12">
        <div className="lg:col-span-8 space-y-4">
          <Panel
            title="Event rate"
            right={`${config.window_minutes}m window`}
            style={{ height: H_PANEL_SM }}
          >
            {derived.rateSeries.length ? (
              <SimpleTimeSeries
                data={derived.rateSeries as any}
                seriesKeys={["events"]}
                height={H_PANEL_SM - 56}
              />
            ) : (
              <EmptyState title="No data" hint="No events in the selected window." />
            )}
          </Panel>

          <Panel title="Event stream" right={`${derived.filtered.length} rows`} style={{ height: H_PANEL_STREAM }}>
            <div className="h-full">
              <EventsTable
                rows={derived.filtered}
                selectedId={selected ? selected.id : null}
                compact={config.compact_rows}
                showExtra={config.show_extra}
                onSelect={(e) => setSelected(e)}
              />
            </div>
          </Panel>
        </div>

        <div className="lg:col-span-4 space-y-4">
          <Panel title="Top signals" right="by count" scrollY style={{ height: H_PANEL_SM }}>
            <div className="space-y-4">
              <div>
                <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground mb-2">
                  Event types
                </div>
                <div className="grid gap-2">
                  {derived.topTypes.length ? (
                    derived.topTypes.map((t) => (
                      <button
                        key={t.key}
                        type="button"
                        onClick={() => setConfig({ ...config, event_type: t.key })}
                        className="flex items-center justify-between border border-border/60 bg-background/40 px-3 py-2 hover:bg-primary/5"
                      >
                        <span className="text-[11px] font-mono">{t.key}</span>
                        <span className="text-[11px] font-mono text-muted-foreground">{t.count}</span>
                      </button>
                    ))
                  ) : (
                    <div className="text-sm text-muted-foreground">No events</div>
                  )}
                </div>
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground mb-2">
                    Top sources
                  </div>
                  <div className="space-y-1">
                    {derived.topSrc.slice(0, 5).map((r) => (
                      <div key={r.key} className="flex items-center justify-between text-[11px] font-mono">
                        <span className="truncate">{r.key}</span>
                        <span className="text-muted-foreground">{r.count}</span>
                      </div>
                    ))}
                    {!derived.topSrc.length && <div className="text-sm text-muted-foreground">-</div>}
                  </div>
                </div>

                <div>
                  <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground mb-2">
                    Top destinations
                  </div>
                  <div className="space-y-1">
                    {derived.topDst.slice(0, 5).map((r) => (
                      <div key={r.key} className="flex items-center justify-between text-[11px] font-mono">
                        <span className="truncate">{r.key}</span>
                        <span className="text-muted-foreground">{r.count}</span>
                      </div>
                    ))}
                    {!derived.topDst.length && <div className="text-sm text-muted-foreground">-</div>}
                  </div>
                </div>
              </div>
            </div>
          </Panel>

          <Panel title="Event details" right={selected ? `id=${selected.id}` : ""} scrollY style={{ height: H_PANEL_DETAILS }}>
            <EventDetails event={selected} />
          </Panel>
        </div>
      </div>
    </div>
  );
}
