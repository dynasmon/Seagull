import type { CSSProperties, ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { Badge } from "@/shared/components/Badge";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationFactCard,
  InvestigationKeyValueGrid,
  InvestigationMetaStrip,
  InvestigationRawJsonPanel,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
  InvestigationTabs,
  copyTextToClipboard,
} from "@/shared/components/investigation";
import { cx } from "@/shared/lib/cx";
import { usePortalRealtimeSubscription } from "@/shared/realtime";
import type { PortalRealtimeEventPayloadMap } from "@/shared/realtime";

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
const ALERTS_RT_FLUSH_MS = 220;
const ALERTS_RT_BURST_WINDOW_MS = 1000;
const ALERTS_RT_BURST_LIMIT = 80;

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

function sevVariant(sev: string): "critical" | "high" | "medium" | "low" | "neutral" {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
}

function fmtAddr(ip?: string | null, port?: number | null) {
  if (!ip) return "-";
  if (typeof port === "number") return `${ip}:${port}`;
  return ip;
}

function toDetailEntries(details: Record<string, any> | null | undefined): Array<{ key: string; value: string }> {
  if (!details || typeof details !== "object") return [];

  const preferredOrder = [
    "event_type",
    "agent_id",
    "hostname",
    "username",
    "process_name",
    "process_path",
    "command",
    "action",
    "proto",
    "src_port",
    "dst_port",
    "dns_qname",
    "http_host",
    "http_method",
    "tls_sni",
    "ja4",
    "ja3",
    "severity",
    "score",
  ];
  const keys = Object.keys(details);
  keys.sort((a, b) => {
    const ai = preferredOrder.indexOf(a);
    const bi = preferredOrder.indexOf(b);
    if (ai === -1 && bi === -1) return a.localeCompare(b);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });

  const out: Array<{ key: string; value: string }> = [];
  for (const key of keys) {
    const value = (details as Record<string, unknown>)[key];
    if (value === null || value === undefined || value === "") continue;
    if (Array.isArray(value) || typeof value === "object") continue;
    out.push({ key, value: String(value) });
    if (out.length >= 24) break;
  }
  return out;
}

function toDetailNested(details: Record<string, any> | null | undefined): Array<{ key: string; value: any }> {
  if (!details || typeof details !== "object") return [];
  const out: Array<{ key: string; value: any }> = [];
  for (const [k, v] of Object.entries(details)) {
    if (!v || (typeof v !== "object" && !Array.isArray(v))) continue;
    out.push({ key: k, value: v });
    if (out.length >= 8) break;
  }
  return out;
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

function buildAlertFromRealtimeDelta(
  payload: PortalRealtimeEventPayloadMap["ui.alerts.delta.patch"],
  fallbackTimestamp: string,
): Alert | null {
  const projected = payload?.alert;
  const id = Number(projected?.id ?? 0);
  if (!Number.isFinite(id) || id <= 0) return null;

  const createdAt = String(projected?.created_at || fallbackTimestamp || new Date().toISOString());
  return {
    id: Math.trunc(id),
    rule_id: String(projected?.rule_id || "realtime.alert"),
    severity: String(projected?.severity || "medium"),
    confidence: typeof projected?.confidence === "number" ? projected.confidence : undefined,
    src_ip: typeof projected?.src_ip === "string" ? projected.src_ip : null,
    dst_ip: typeof projected?.dst_ip === "string" ? projected.dst_ip : null,
    dst_port: typeof projected?.dst_port === "number" ? projected.dst_port : null,
    description: String(projected?.description || "Realtime alert"),
    details: null,
    created_at: createdAt,
  };
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
  const [drawerTab, setDrawerTab] = useState<"summary" | "evidence" | "raw">("summary");

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
  const realtimeFlushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const realtimeInvalidateTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const realtimePendingRef = useRef<Array<{ payload: PortalRealtimeEventPayloadMap["ui.alerts.delta.patch"]; timestamp: string }>>([]);
  const realtimeBurstWindowStartRef = useRef(0);
  const realtimeBurstCountRef = useRef(0);
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

  const scheduleRealtimeInvalidateRefresh = useCallback(() => {
    if (realtimeInvalidateTimerRef.current) return;
    realtimeInvalidateTimerRef.current = window.setTimeout(() => {
      realtimeInvalidateTimerRef.current = null;
      void loadHead("merge");
    }, 300);
  }, [loadHead]);

  const flushRealtimeDeltaQueue = useCallback(() => {
    realtimeFlushTimerRef.current = null;
    const queued = realtimePendingRef.current;
    if (queued.length === 0) return;
    realtimePendingRef.current = [];

    const severityFilter = String(viewRef.current.severity || "all").toLowerCase();
    const ruleFilter = String(viewRef.current.rule_id || "").trim().toLowerCase();
    if (severityFilter !== "all" || ruleFilter) {
      scheduleRealtimeInvalidateRefresh();
      return;
    }

    setAlerts((prev) => {
      let next = prev;
      for (const item of queued) {
        const action = String(item.payload?.action || "patch").toLowerCase();
        const projected = buildAlertFromRealtimeDelta(item.payload, item.timestamp);
        if (!projected) continue;
        const idx = next.findIndex((row) => row.id === projected.id);
        if (idx >= 0) {
          const current = next[idx];
          const merged: Alert = {
            ...current,
            ...projected,
            description: projected.description || current.description,
            created_at: current.created_at || projected.created_at,
            details: current.details ?? projected.details ?? null,
          };
          if (
            merged.rule_id === current.rule_id &&
            merged.severity === current.severity &&
            merged.src_ip === current.src_ip &&
            merged.dst_ip === current.dst_ip &&
            merged.dst_port === current.dst_port &&
            merged.description === current.description
          ) {
            continue;
          }
          const cloned = next.slice();
          cloned[idx] = merged;
          next = cloned;
          continue;
        }

        if (action === "upsert") {
          next = [projected, ...next].slice(0, Math.max(25, viewRef.current.page_size));
        }
      }
      return next;
    });
    setLastRefresh(new Date());
  }, [scheduleRealtimeInvalidateRefresh]);

  const scheduleRealtimeDeltaFlush = useCallback(() => {
    if (realtimeFlushTimerRef.current) return;
    realtimeFlushTimerRef.current = window.setTimeout(() => {
      flushRealtimeDeltaQueue();
    }, ALERTS_RT_FLUSH_MS);
  }, [flushRealtimeDeltaQueue]);

  usePortalRealtimeSubscription("ui.alerts.delta.patch", (event) => {
    const now = Date.now();
    if ((now - realtimeBurstWindowStartRef.current) > ALERTS_RT_BURST_WINDOW_MS) {
      realtimeBurstWindowStartRef.current = now;
      realtimeBurstCountRef.current = 0;
    }
    realtimeBurstCountRef.current += 1;
    if (realtimeBurstCountRef.current > ALERTS_RT_BURST_LIMIT) {
      realtimePendingRef.current = [];
      scheduleRealtimeInvalidateRefresh();
      return;
    }

    realtimePendingRef.current.push({
      payload: (event.payload || {}) as PortalRealtimeEventPayloadMap["ui.alerts.delta.patch"],
      timestamp: String(event.timestamp || new Date().toISOString()),
    });
    if (realtimePendingRef.current.length > ALERTS_RT_BURST_LIMIT) {
      realtimePendingRef.current = [];
      scheduleRealtimeInvalidateRefresh();
      return;
    }
    scheduleRealtimeDeltaFlush();
  });

  usePortalRealtimeSubscription("ui.alerts.invalidate", () => {
    realtimePendingRef.current = [];
    scheduleRealtimeInvalidateRefresh();
  });

  // Initial load
  useEffect(() => {
    loadHead("reset");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    return () => {
      if (realtimeFlushTimerRef.current) {
        window.clearTimeout(realtimeFlushTimerRef.current);
        realtimeFlushTimerRef.current = null;
      }
      if (realtimeInvalidateTimerRef.current) {
        window.clearTimeout(realtimeInvalidateTimerRef.current);
        realtimeInvalidateTimerRef.current = null;
      }
    };
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
    const ok = await copyTextToClipboard(detailsJson);
    if (!ok) return;
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  }

  function openDrawerFor(a: Alert) {
    setSelected(a);
    setDrawerTab("summary");
    setDrawerOpen(true);
  }

  function openRuleEditor() {
    if (!selected?.rule_id) return;
    nav(`/alerts/rules?rule_id=${encodeURIComponent(selected.rule_id)}`);
  }

  function openEventsPivot() {
    if (!selected) return;
    const sp = new URLSearchParams();
    const primaryQuery =
      (selected.src_ip || "").trim() ||
      (selected.dst_ip || "").trim() ||
      (selected.mitre_technique_id || "").trim() ||
      (selected.rule_id || "").trim();
    if (primaryQuery) sp.set("search", primaryQuery);
    nav(`/events${sp.toString() ? `?${sp.toString()}` : ""}`);
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
        widthClassName="w-[980px]"
      >
        {!selected ? (
          <EmptyState title="No selection" description="Select an alert using the Edit button." />
        ) : (
          <InvestigationShell>
            <InvestigationMetaStrip
              items={[
                { label: "Severity", value: String(selected.severity || "unknown"), variant: sevVariant(String(selected.severity || "unknown")) },
                { label: "Rule", value: selected.rule_id },
                { label: "Created", value: fmtTs(selected.created_at) },
                { label: "Source", value: "alerts" },
                {
                  label: "ATT&CK",
                  value:
                    selected.mitre_technique_id || selected.mitre_tactic
                      ? `${selected.mitre_tactic || "tactic"}${selected.mitre_technique_id ? ` · ${selected.mitre_technique_id}` : ""}`
                      : "-",
                },
              ]}
            />

            <InvestigationActionBar>
              <InvestigationActionButton onClick={openRuleEditor} title="Open rule editor">
                Edit rule
              </InvestigationActionButton>
              <InvestigationActionButton onClick={openEventsPivot} title="Pivot into Events">
                Open in Events
              </InvestigationActionButton>
              <InvestigationActionButton onClick={copyDetailsJson} title="Copy JSON to clipboard">
                {copied ? "Copied" : "Copy JSON"}
              </InvestigationActionButton>
            </InvestigationActionBar>

            <InvestigationTabs
              value={drawerTab}
              onChange={setDrawerTab}
              tabs={[
                { key: "summary", label: "Summary" },
                { key: "evidence", label: "Evidence" },
                { key: "raw", label: "Raw" },
              ]}
            />

            {drawerTab === "summary" ? (
              <InvestigationSection title="Alert summary" subtitle="Highest-value triage facts first.">
                <InvestigationSummaryGrid>
                  <InvestigationFactCard label="Rule ID" value={selected.rule_id} mono />
                  <InvestigationFactCard
                    label="Severity"
                    value={<Badge variant={sevVariant(String(selected.severity || "unknown"))}>{String(selected.severity || "unknown")}</Badge>}
                  />
                  <InvestigationFactCard
                    label="Confidence"
                    value={typeof selected.confidence === "number" ? String(selected.confidence) : "-"}
                    mono
                  />
                  <InvestigationFactCard label="Source IP" value={selected.src_ip || "-"} mono />
                  <InvestigationFactCard label="Destination" value={fmtAddr(selected.dst_ip, selected.dst_port)} mono />
                  <InvestigationFactCard
                    label="ATT&CK"
                    value={
                      selected.mitre_technique || selected.mitre_technique_id || selected.mitre_tactic
                        ? `${selected.mitre_tactic || "-"}${selected.mitre_technique_id ? ` · ${selected.mitre_technique_id}` : ""}${selected.mitre_technique ? ` · ${selected.mitre_technique}` : ""}`
                        : "-"
                    }
                    mono
                  />
                </InvestigationSummaryGrid>
                <div className="mt-4 rounded-lg border border-border/60 bg-background/35 px-3 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Description</div>
                  <div className="mt-1 text-sm leading-relaxed">{selected.description || "No description."}</div>
                </div>
              </InvestigationSection>
            ) : null}

            {drawerTab === "evidence" ? (
              <InvestigationSection
                title="Evidence context"
                subtitle="Structured details extracted from rule output and telemetry context."
              >
                <div className="space-y-4">
                  <InvestigationKeyValueGrid
                    entries={toDetailEntries(selected.details).map((x) => ({ key: x.key, value: x.value }))}
                  />

                  {toDetailNested(selected.details).map((block) => (
                    <div key={block.key} className="rounded-lg border border-border/60 bg-background/35 p-3">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{block.key}</div>
                      <pre className="mt-2 max-h-[220px] overflow-auto rounded border border-border/60 bg-background/30 p-2 text-[11px] leading-relaxed whitespace-pre-wrap break-words">
                        {safeJson(block.value)}
                      </pre>
                    </div>
                  ))}
                </div>
              </InvestigationSection>
            ) : null}

            {drawerTab === "raw" ? <InvestigationRawJsonPanel value={detailsJson} title="Raw alert payload" initialWrap={view.wrap_json} /> : null}
          </InvestigationShell>
        )}
      </Drawer>
    </div>
  );
}
