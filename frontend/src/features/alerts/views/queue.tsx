import type { CSSProperties, ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { Badge } from "@/shared/components/Badge";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";

import { getAlertsPage, runAllRules } from "../api";
import SeverityFilter from "../components/SeverityFilter";
import type { Alert } from "../types";

type Density = "comfortable" | "compact";

type ViewCfg = {
  // Backend filters (reduce payload)
  severity: string; // "all" | critical | high | ...
  rule_id: string; // exact match (optional)

  // Local-only
  search: string;

  // Pagination
  page_size: number;
  infinite_scroll: boolean;

  // UI
  wrap_json: boolean;
  density: Density;
};

const LS_KEY = "nw_alerts_queue_view_v1";

const DEFAULTS: ViewCfg = {
  severity: "all",
  rule_id: "",
  search: "",
  page_size: 200,
  infinite_scroll: false,
  wrap_json: true,
  density: "comfortable"
};

function clampInt(v: any, min: number, max: number, fallback: number) {
  const n = Number.parseInt(String(v ?? ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function safeLoadView(): ViewCfg {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw) as Partial<ViewCfg>;
    const merged: ViewCfg = {
      ...DEFAULTS,
      ...parsed,
      severity: String(parsed.severity ?? DEFAULTS.severity),
      rule_id: String(parsed.rule_id ?? "").trim(),
      search: String(parsed.search ?? ""),
      page_size: clampInt(parsed.page_size, 10, 200, DEFAULTS.page_size),
      infinite_scroll: Boolean(parsed.infinite_scroll),
      wrap_json: Boolean(parsed.wrap_json),
      density: (parsed.density === "compact" ? "compact" : "comfortable")
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

function Panel(props: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  style?: CSSProperties;
  scrollY?: boolean;
  className?: string;
  bodyClassName?: string;
  bodyRef?: React.Ref<HTMLDivElement>;
}) {
  return (
    <div className={cx("rounded-xl border border-border/60 bg-background/70 backdrop-blur-md flex flex-col min-h-0", props.className)}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-border/60 bg-muted/10">
        <div className="text-sm font-semibold tracking-tight truncate">{props.title}</div>
        {props.right ? <div className="text-xs text-muted-foreground truncate">{props.right}</div> : null}
      </div>

      <div
        ref={props.bodyRef}
        className={cx("p-4 min-h-0 grow", props.scrollY && "overflow-y-auto", props.bodyClassName)}
        style={props.style}
      >
        {props.children}
      </div>
    </div>
  );
}

function safeJson(v: any) {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function fmtTs(ts: string) {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

function sevVariant(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
}

function mergeUniqueById(newer: Alert[], older: Alert[]) {
  const out: Alert[] = [];
  const seen = new Set<number>();

  for (const a of newer) {
    if (!a || typeof a.id !== "number") continue;
    if (seen.has(a.id)) continue;
    seen.add(a.id);
    out.push(a);
  }
  for (const a of older) {
    if (!a || typeof a.id !== "number") continue;
    if (seen.has(a.id)) continue;
    seen.add(a.id);
    out.push(a);
  }
  return out;
}

function AlertsQueueTable(props: {
  rows: Alert[];
  selectedId: number | null;
  onEdit: (a: Alert) => void;
  density?: Density;
}) {
  const dense = props.density === "compact";

  return (
    <div className="w-full overflow-auto">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
          <tr className="border-b border-border/60 text-muted-foreground">
            <th className="text-left font-medium px-3 py-2 w-[180px]">Time</th>
            <th className="text-left font-medium px-3 py-2 w-[120px]">Severity</th>
            <th className="text-left font-medium px-3 py-2 w-[260px]">Rule</th>
            <th className="text-left font-medium px-3 py-2 w-[180px]">Source</th>
            <th className="text-left font-medium px-3 py-2 w-[220px]">Destination</th>
            <th className="text-left font-medium px-3 py-2">Description</th>
            <th className="text-right font-medium px-3 py-2 w-[120px]">Actions</th>
          </tr>
        </thead>

        <tbody>
          {props.rows.map((a) => {
            const selected = props.selectedId !== null && a.id === props.selectedId;
            return (
              <tr key={a.id} className={cx("border-b border-border/40 hover:bg-muted/30", selected && "bg-muted/40")}>
                <td className={cx("px-3 font-mono text-[12px] text-muted-foreground", dense ? "py-1.5" : "py-2")}>
                  {fmtTs(a.created_at)}
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <Badge variant={sevVariant(String(a.severity || "unknown"))}>{String(a.severity || "unknown")}</Badge>
                </td>

                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>{a.rule_id}</td>

                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>
                  {a.src_ip || <span className="text-muted-foreground">-</span>}
                </td>

                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>
                  {a.dst_ip ? <span>{a.dst_ip}</span> : <span className="text-muted-foreground">-</span>}
                  {typeof a.dst_port === "number" ? <span className="text-muted-foreground">:{a.dst_port}</span> : null}
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <div className="text-[12px] text-muted-foreground line-clamp-2">{a.description || ""}</div>
                </td>

                <td className={cx("px-3 text-right", dense ? "py-1.5" : "py-2")}>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      props.onEdit(a);
                    }}
                    className={cx(
                      "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                      "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                      "hover:bg-muted/15 hover:text-foreground",
                      "focus:outline-none focus:ring-2 focus:ring-primary/30"
                    )}
                    title="Open drawer"
                  >
                    Edit
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function AlertsQueuePage() {
  const nav = useNavigate();

  const [view, setView] = useState<ViewCfg>(() => safeLoadView());
  const viewRef = useRef(view);
  useEffect(() => {
    viewRef.current = view;
    persistView(view);
  }, [view]);

  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const [selected, setSelected] = useState<Alert | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const [copied, setCopied] = useState(false);

  // Keep last known alerts around so we can "soft refresh" without flicker.
  const alertsRef = useRef<Alert[]>([]);
  useEffect(() => {
    alertsRef.current = alerts;
  }, [alerts]);

  const reqSeq = useRef(0);
  const moreSeq = useRef(0);
  const nextCursorRef = useRef<string | null>(null);
  const hasMoreRef = useRef(false);
  useEffect(() => {
    nextCursorRef.current = nextCursor;
    hasMoreRef.current = hasMore;
  }, [nextCursor, hasMore]);

  const panelBodyRef = useRef<HTMLDivElement | null>(null);
  const loadMoreSentinelRef = useRef<HTMLDivElement | null>(null);

  const patch = useCallback((next: Partial<ViewCfg>) => {
    setView((prev) => {
      const merged: ViewCfg = { ...prev, ...next };
      merged.severity = String(merged.severity || "all");
      merged.rule_id = String(merged.rule_id || "").trim();
      merged.search = String(merged.search || "");
      merged.page_size = clampInt(merged.page_size, 10, 200, DEFAULTS.page_size);
      merged.infinite_scroll = Boolean(merged.infinite_scroll);
      merged.wrap_json = Boolean(merged.wrap_json);
      merged.density = merged.density === "compact" ? "compact" : "comfortable";
      return merged;
    });
  }, []);

  const loadHead = useCallback(async (mode: "reset" | "merge" = "reset") => {
    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);

    const severity = viewRef.current.severity;
    const rule_id = viewRef.current.rule_id;
    const page_size = viewRef.current.page_size;

    try {
      const page = await getAlertsPage({
        page_size,
        severity: severity && severity !== "all" ? severity : undefined,
        rule_id: rule_id ? rule_id : undefined
      });
      if (reqSeq.current !== mySeq) return;

      setLastRefresh(new Date());

      if (mode === "reset" || alertsRef.current.length === 0) {
        setAlerts(page.items);
        setNextCursor(page.next_cursor);
        setHasMore(Boolean(page.has_more));

        setSelected((prev) => {
          if (!prev) return null;
          const still = page.items.find((x) => x.id === prev.id);
          return still || null;
        });

        if (drawerOpen && selected) {
          const still = page.items.find((x) => x.id === selected.id);
          if (!still) setDrawerOpen(false);
        }
      } else {
        setAlerts((prev) => mergeUniqueById(page.items, prev));
        setHasMore((prev) => prev || Boolean(page.has_more));
        setNextCursor((prev) => (prev ? prev : page.next_cursor));
      }
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(e?.message || "Failed to load alerts");
      if (alertsRef.current.length === 0) {
        setAlerts([]);
        setNextCursor(null);
        setHasMore(false);
        setSelected(null);
        setDrawerOpen(false);
      }
    } finally {
      if (reqSeq.current !== mySeq) return;
      setLoading(false);
    }
  }, [drawerOpen, selected]);

  const loadMore = useCallback(async () => {
    const cursor = nextCursorRef.current;
    if (!hasMoreRef.current || !cursor) return;
    if (loadingMore) return;

    const mySeq = ++moreSeq.current;
    setLoadingMore(true);
    setError(null);

    const severity = viewRef.current.severity;
    const rule_id = viewRef.current.rule_id;
    const page_size = viewRef.current.page_size;

    try {
      const page = await getAlertsPage({
        page_size,
        cursor,
        severity: severity && severity !== "all" ? severity : undefined,
        rule_id: rule_id ? rule_id : undefined
      });
      if (moreSeq.current !== mySeq) return;

      setAlerts((prev) => mergeUniqueById(prev, page.items));
      setNextCursor(page.next_cursor);
      setHasMore(Boolean(page.has_more));
      setLastRefresh((prev) => prev ?? new Date());
    } catch (e: any) {
      if (moreSeq.current !== mySeq) return;
      setError(e?.message || "Failed to load more alerts");
    } finally {
      if (moreSeq.current !== mySeq) return;
      setLoadingMore(false);
    }
  }, [loadingMore]);

  // Initial load
  useEffect(() => {
    loadHead("reset");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Hard reset when backend scope changes.
  useEffect(() => {
    setAlerts([]);
    setNextCursor(null);
    setHasMore(false);
    setSelected(null);
    setDrawerOpen(false);
    setError(null);
    setLastRefresh(null);
    loadHead("reset");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view.severity, view.rule_id, view.page_size]);

  // Optional infinite scroll for older pages.
  useEffect(() => {
    if (!view.infinite_scroll) return;
    const root = panelBodyRef.current;
    const target = loadMoreSentinelRef.current;
    if (!root || !target) return;

    const obs = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          loadMore();
        }
      },
      { root, rootMargin: "320px 0px" }
    );

    obs.observe(target);
    return () => obs.disconnect();
  }, [view.infinite_scroll, loadMore]);

  const filtered = useMemo(() => {
    const qq = (view.search || "").trim().toLowerCase();
    if (!qq) return alerts;

    return (alerts || []).filter((a) => {
      const hay = [
        a.rule_id,
        a.src_ip,
        a.dst_ip,
        a.description,
        a.mitre_tactic,
        a.mitre_technique_id,
        a.mitre_technique
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(qq);
    });
  }, [alerts, view.search]);

  const headerRight = useMemo(() => {
    if (loading && alerts.length === 0) return "Loading…";
    const base = `${filtered.length} alerts`;
    if (!lastRefresh) return base;
    const hh = String(lastRefresh.getHours()).padStart(2, "0");
    const mm = String(lastRefresh.getMinutes()).padStart(2, "0");
    const ss = String(lastRefresh.getSeconds()).padStart(2, "0");
    return `${base} · refreshed ${hh}:${mm}:${ss}`;
  }, [filtered.length, lastRefresh, loading, alerts.length]);

  const detailsJson = useMemo(() => {
    if (!selected) return "";
    return safeJson({
      id: selected.id,
      severity: selected.severity,
      rule_id: selected.rule_id,
      src_ip: selected.src_ip,
      dst_ip: selected.dst_ip,
      dst_port: selected.dst_port,
      confidence: selected.confidence,
      mitre_tactic: selected.mitre_tactic,
      mitre_technique_id: selected.mitre_technique_id,
      mitre_technique: selected.mitre_technique,
      created_at: selected.created_at,
      description: selected.description,
      details: selected.details
    });
  }, [selected]);

  async function copyDetailsJson() {
    if (!detailsJson) return;
    try {
      await navigator.clipboard.writeText(detailsJson);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      // ignore
    }
  }

  function openDrawerFor(a: Alert) {
    setSelected(a);
    setDrawerOpen(true);
  }

  function openRuleEditor() {
    if (!selected?.rule_id) return;
    nav(`/alerts/rules?rule_id=${encodeURIComponent(selected.rule_id)}`);
  }

  async function handleRunAll() {
    setRunning(true);
    setError(null);
    try {
      await runAllRules();
      await loadHead("merge");
    } catch (e: any) {
      setError(e?.message || "Failed to run rules");
    } finally {
      setRunning(false);
    }
  }

  const panelHeightClass = "h-[560px] xl:h-[calc(100vh-270px)]";
  const isInitialLoading = loading && alerts.length === 0;

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <h2 className="text-lg font-semibold">Alert queue</h2>
          <div className="text-xs text-muted-foreground">
            Inspect alerts generated by rules. Use the <span className="text-foreground">Rules</span> tab to tune detection.
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            value={view.search}
            onChange={(e) => patch({ search: e.target.value })}
            placeholder="Search rule, IP, description…"
            className={cx(
              "h-9 min-w-[220px] flex-1 rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none",
              "focus:ring-1 focus:ring-primary/40"
            )}
          />

          <SeverityFilter value={view.severity} onChange={(v) => patch({ severity: v })} />

          <input
            value={view.rule_id}
            onChange={(e) => patch({ rule_id: e.target.value })}
            placeholder="Rule ID (exact, backend)"
            className={cx(
              "h-9 w-[220px] rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none",
              "focus:ring-1 focus:ring-primary/40"
            )}
            title="Exact rule_id filter (server-side)"
          />

          <select
            value={String(view.page_size)}
            onChange={(e) => patch({ page_size: Number(e.target.value) })}
            className="h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none focus:ring-1 focus:ring-primary/40"
            title="Page size"
          >
            <option value="50">50 / page</option>
            <option value="100">100 / page</option>
            <option value="200">200 / page</option>
          </select>

          <button
            onClick={() => patch({ density: view.density === "comfortable" ? "compact" : "comfortable" })}
            className={cx("h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm", "hover:bg-muted/30")}
            title="Toggle row density"
          >
            {view.density === "compact" ? "Compact" : "Comfort"}
          </button>

          <button
            onClick={() => patch({ infinite_scroll: !view.infinite_scroll })}
            className={cx(
              "h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm",
              view.infinite_scroll ? "text-foreground" : "text-muted-foreground",
              "hover:bg-muted/30"
            )}
            title="Auto-load older pages when you scroll"
          >
            {view.infinite_scroll ? "Infinite" : "Manual"}
          </button>

          <button
            onClick={() => loadHead("merge")}
            disabled={loading}
            className={cx("h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm", "hover:bg-muted/30 disabled:opacity-60")}
            title="Refresh (keeps loaded pages)"
          >
            Refresh
          </button>

          <button
            onClick={handleRunAll}
            disabled={running}
            className={cx("h-9 rounded-md bg-primary px-3 text-sm font-medium text-primary-foreground", "hover:opacity-95 disabled:opacity-60")}
            title="Run all rules now"
          >
            {running ? "Running…" : "Run rules"}
          </button>
        </div>
      </div>

      {error ? (
        <div className="rounded-xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
      ) : null}

      <Panel
        title="Queue"
        right={headerRight}
        scrollY
        className={cx(panelHeightClass)}
        bodyRef={panelBodyRef}
        bodyClassName="p-0"
      >
        {isInitialLoading ? (
          <div className="p-4">
            <Loading label="Loading alerts…" />
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-4">
            <EmptyState title="No alerts" description="No alerts match the current filters." />
          </div>
        ) : (
          <div className="relative">
            <AlertsQueueTable rows={filtered} selectedId={selected?.id ?? null} onEdit={openDrawerFor} density={view.density} />

            <div
              className={cx(
                "sticky bottom-0 left-0 right-0 border-t border-border/60 bg-background/70 backdrop-blur",
                "px-4 py-3"
              )}
            >
              <div className="flex items-center justify-between gap-3">
                <div className="text-[11px] font-mono text-muted-foreground">
                  Loaded <span className="text-foreground">{alerts.length}</span> alerts
                  {filtered.length !== alerts.length ? <span className="opacity-80"> · after search: {filtered.length}</span> : null}
                </div>

                {hasMore ? (
                  <button
                    type="button"
                    onClick={() => loadMore()}
                    disabled={loadingMore}
                    className={cx(
                      "rounded-md border border-border/60 bg-background/40",
                      "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                      "hover:bg-muted/15 hover:text-foreground",
                      "focus:outline-none focus:ring-2 focus:ring-primary/30",
                      loadingMore && "opacity-60 cursor-not-allowed"
                    )}
                  >
                    {loadingMore ? "Loading…" : "Load older"}
                  </button>
                ) : (
                  <div className="text-[11px] font-mono text-muted-foreground opacity-80">End of queue</div>
                )}
              </div>
            </div>

            <div ref={loadMoreSentinelRef} className="h-6" />
          </div>
        )}
      </Panel>

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={selected ? `Alert #${selected.id}` : "Alert"}
        description={selected ? `${selected.rule_id} · ${fmtTs(selected.created_at)}` : undefined}
        widthClassName="w-[860px]"
      >
        {!selected ? (
          <EmptyState title="No selection" description="Select an alert using the Edit button." />
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Badge variant={sevVariant(String(selected.severity || "unknown"))}>{String(selected.severity || "unknown")}</Badge>
                <div className="font-mono text-xs text-muted-foreground">{selected.rule_id}</div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={openRuleEditor}
                  className={cx("h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm", "hover:bg-muted/30")}
                  title="Open rule editor"
                >
                  Edit rule
                </button>

                <button
                  type="button"
                  onClick={copyDetailsJson}
                  className={cx("h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm", "hover:bg-muted/30")}
                  title="Copy JSON to clipboard"
                >
                  {copied ? "Copied" : "Copy JSON"}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Source</div>
                <div className="font-mono text-sm truncate">{selected.src_ip || "-"}</div>
              </div>

              <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Destination</div>
                <div className="font-mono text-sm truncate">
                  {selected.dst_ip || "-"}
                  {typeof selected.dst_port === "number" ? `:${selected.dst_port}` : ""}
                </div>
              </div>

              <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Confidence</div>
                <div className="font-mono text-sm truncate">{typeof selected.confidence === "number" ? selected.confidence : "-"}</div>
              </div>

              <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">ATT&CK</div>
                <div className="font-mono text-sm truncate">
                  {selected.mitre_tactic || "-"}
                  {selected.mitre_technique_id ? ` · ${selected.mitre_technique_id}` : ""}
                </div>
              </div>
            </div>

            <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-2">
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Description</div>
              <div className="text-sm leading-relaxed">{selected.description || ""}</div>
            </div>

            <div className="rounded-xl border border-border/60 bg-background/20">
              <div className="flex items-center justify-between gap-3 px-3 py-2 border-b border-border/60">
                <div className="text-[11px] font-semibold">Raw event (JSON)</div>
                <label className="flex items-center gap-2 text-[11px] text-muted-foreground select-none">
                  <input
                    type="checkbox"
                    checked={view.wrap_json}
                    onChange={(e) => patch({ wrap_json: e.target.checked })}
                    className="h-4 w-4"
                  />
                  Wrap
                </label>
              </div>

              <pre
                className={cx(
                  "p-3 text-[11px] leading-relaxed overflow-auto",
                  view.wrap_json ? "whitespace-pre-wrap break-words" : "whitespace-pre"
                )}
              >
                {detailsJson}
              </pre>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
