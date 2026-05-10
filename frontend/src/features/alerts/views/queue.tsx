import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { JsonBlock } from "@/shared/components/JsonBlock";
import {
  DataPaginationFooter,
  DataQueryStateBanner,
  DataStatsStrip,
  DataViewToolbar,
  DebouncedSearchInput,
} from "@/shared/components/DataView";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";
import { TextInput } from "@/shared/components/TextInput";
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
import { getFlowIpContext } from "@/shared/lib/ipClassification";
import { usePortalRealtimeSubscription } from "@/shared/realtime";
import type { PortalRealtimeEventPayloadMap } from "@/shared/realtime";

import { getAlertEvidence, getAlertsPage, runAllRules, triageAlert } from "../api";
import SeverityFilter from "../components/SeverityFilter";
import type { Alert, AlertDisposition, AlertEvidenceItem, AlertStatus, AlertTriageIn } from "../types";

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

function alertIpContext(alert: Alert, side: "src" | "dst") {
  const details = alert.details && typeof alert.details === "object" ? alert.details : null;
  return getFlowIpContext(details?.ip_context, side);
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
    status: "open" as const,
  };
}

function AlertsQueueTable(props: {
  rows: Alert[];
  selectedId: number | null;
  onEdit: (a: Alert) => void;
  selectedRowIds: Set<number>;
  onToggleRow: (alertId: number, nextChecked: boolean) => void;
  onToggleAllRows: (nextChecked: boolean) => void;
  density?: Density;
}) {
  const dense = props.density === "compact";
  const allVisibleSelected = props.rows.length > 0 && props.rows.every((row) => props.selectedRowIds.has(row.id));

  return (
    <div className="w-full">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
          <tr className="border-b border-border/60 text-muted-foreground">
            <th className="px-3 py-2 w-10">
              <input
                type="checkbox"
                checked={allVisibleSelected}
                onChange={(e) => props.onToggleAllRows(e.target.checked)}
                aria-label="Select visible alerts"
                className="h-4 w-4"
              />
            </th>
            <th className="text-left font-medium px-3 py-2">Alert</th>
            <th className="text-left font-medium px-3 py-2">Network</th>
            <th className="text-left font-medium px-3 py-2">Description</th>
            <th className="text-right font-medium px-3 py-2">Actions</th>
          </tr>
        </thead>

        <tbody>
          {props.rows.map((a) => {
            const selected = props.selectedId !== null && a.id === props.selectedId;
            return (
              <tr
                key={a.id}
                className={cx("border-b border-border/40 hover:bg-muted/30", selected && "bg-muted/40")}
                role="button"
                tabIndex={0}
                onClick={() => props.onEdit(a)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    props.onEdit(a);
                  }
                }}
              >
                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <input
                    type="checkbox"
                    checked={props.selectedRowIds.has(a.id)}
                    onClick={(e) => e.stopPropagation()}
                    onChange={(e) => props.onToggleRow(a.id, e.target.checked)}
                    aria-label={`Select alert ${a.id}`}
                    className="h-4 w-4"
                  />
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge variant={sevVariant(String(a.severity || "unknown"))}>{String(a.severity || "unknown")}</Badge>
                    <span className="font-mono text-[12px] break-all">{a.rule_id}</span>
                  </div>
                  <div className="font-mono text-[11px] text-muted-foreground">{fmtTs(a.created_at)}</div>
                </td>

                <td className={cx("px-3 text-[12px]", dense ? "py-1.5" : "py-2")}>
                  <div>
                    <IpAddressPill ip={a.src_ip} ipContext={alertIpContext(a, "src")} compact />
                  </div>
                  <div className="mt-1 text-muted-foreground">
                    <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
                      <IpAddressPill ip={a.dst_ip} ipContext={alertIpContext(a, "dst")} compact />
                      {typeof a.dst_port === "number" ? <span>:{a.dst_port}</span> : null}
                    </span>
                  </div>
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <div className="text-[12px] text-muted-foreground line-clamp-2">{a.description || ""}</div>
                </td>

                <td className={cx("px-3 text-right", dense ? "py-1.5" : "py-2")}>
                  <Button
                    variant="subtle"
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      props.onEdit(a);
                    }}
                    title="Open drawer"
                  >
                    View
                  </Button>
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
  const [searchParams] = useSearchParams();

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
  const [drawerTab, setDrawerTab] = useState<"summary" | "evidence" | "triage" | "raw">("summary");
  const [selectedRowIds, setSelectedRowIds] = useState<Set<number>>(() => new Set());

  const [evidenceItems, setEvidenceItems] = useState<AlertEvidenceItem[]>([]);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const evidenceAlertIdRef = useRef<number | null>(null);

  const [triaging, setTriaging] = useState(false);
  const [triageError, setTriageError] = useState<string | null>(null);
  const [triageNotes, setTriageNotes] = useState("");
  const [triageAssignedTo, setTriageAssignedTo] = useState("");
  const [triagePriority, setTriagePriority] = useState("");
  const [triageRiskScore, setTriageRiskScore] = useState("");
  const [triageCloseDisposition, setTriageCloseDisposition] = useState<AlertDisposition | "">("");

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
  const hydratedFromQueryRef = useRef(false);

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

  useEffect(() => {
    if (hydratedFromQueryRef.current) return;
    hydratedFromQueryRef.current = true;
    const ruleId = String(searchParams.get("rule_id") || "").trim();
    const search = String(searchParams.get("search") || "").trim();
    const severity = String(searchParams.get("severity") || "").trim().toLowerCase();
    const next: Partial<ViewCfg> = {};
    if (ruleId) next.rule_id = ruleId;
    if (search) next.search = search;
    if (severity) next.severity = severity;
    if (Object.keys(next).length > 0) patch(next);
  }, [patch, searchParams]);

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
        setSelectedRowIds(new Set());
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
    setSelectedRowIds(new Set());
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

  useEffect(() => {
    const visible = new Set(filtered.map((row) => row.id));
    setSelectedRowIds((prev) => {
      if (prev.size === 0) return prev;
      const next = new Set<number>();
      prev.forEach((id) => {
        if (visible.has(id)) next.add(id);
      });
      return next;
    });
  }, [filtered]);

  const headerRight = useMemo(() => {
    if (loading && alerts.length === 0) return "Loading…";
    const base = `${filtered.length} alerts`;
    if (!lastRefresh) return base;
    const hh = String(lastRefresh.getHours()).padStart(2, "0");
    const mm = String(lastRefresh.getMinutes()).padStart(2, "0");
    const ss = String(lastRefresh.getSeconds()).padStart(2, "0");
    return `${base} · refreshed ${hh}:${mm}:${ss}`;
  }, [filtered.length, lastRefresh, loading, alerts.length]);

  const severityBreakdown = useMemo(() => {
    const counts: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };
    for (const alert of filtered) {
      const key = String(alert.severity || "unknown").toLowerCase();
      if (counts[key] === undefined) counts.unknown += 1;
      else counts[key] += 1;
    }
    return counts;
  }, [filtered]);

  const selectedRows = useMemo(() => {
    if (selectedRowIds.size === 0) return [];
    return filtered.filter((row) => selectedRowIds.has(row.id));
  }, [filtered, selectedRowIds]);

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

  async function loadEvidenceFor(alertId: number) {
    if (evidenceAlertIdRef.current === alertId) return;
    evidenceAlertIdRef.current = alertId;
    setEvidenceItems([]);
    setEvidenceLoading(true);
    try {
      const items = await getAlertEvidence(alertId);
      if (evidenceAlertIdRef.current === alertId) {
        setEvidenceItems(items);
      }
    } catch {
      if (evidenceAlertIdRef.current === alertId) setEvidenceItems([]);
    } finally {
      if (evidenceAlertIdRef.current === alertId) setEvidenceLoading(false);
    }
  }

  function openDrawerFor(a: Alert) {
    setSelected(a);
    setDrawerTab("summary");
    setDrawerOpen(true);
    setTriageError(null);
    setTriageNotes(a.triage_notes ?? "");
    setTriageAssignedTo(a.assigned_to ?? "");
    setTriagePriority(a.priority != null ? String(a.priority) : "");
    setTriageRiskScore(a.risk_score != null ? String(a.risk_score) : "");
    setTriageCloseDisposition((a.disposition as AlertDisposition) ?? "");
    void loadEvidenceFor(a.id);
  }

  async function handleTriage(patch: AlertTriageIn) {
    if (!selected) return;
    setTriaging(true);
    setTriageError(null);
    try {
      const updated = await triageAlert(selected.id, patch);
      setSelected(updated);
      setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
      setTriageNotes(updated.triage_notes ?? "");
      setTriageAssignedTo(updated.assigned_to ?? "");
      setTriagePriority(updated.priority != null ? String(updated.priority) : "");
      setTriageRiskScore(updated.risk_score != null ? String(updated.risk_score) : "");
      setTriageCloseDisposition((updated.disposition as AlertDisposition) ?? "");
    } catch (e: any) {
      setTriageError(e?.message || "Triage failed");
    } finally {
      setTriaging(false);
    }
  }

  function handleTriageFieldsSave() {
    const body: AlertTriageIn = {};
    if (triageNotes !== (selected?.triage_notes ?? "")) body.triage_notes = triageNotes || null;
    if (triageAssignedTo !== (selected?.assigned_to ?? "")) body.assigned_to = triageAssignedTo || null;
    const p = parseInt(triagePriority, 10);
    if (triagePriority !== (selected?.priority != null ? String(selected.priority) : "")) {
      body.priority = triagePriority ? (Number.isFinite(p) ? p : null) : null;
    }
    const rs = parseInt(triageRiskScore, 10);
    if (triageRiskScore !== (selected?.risk_score != null ? String(selected.risk_score) : "")) {
      body.risk_score = triageRiskScore ? (Number.isFinite(rs) ? rs : null) : null;
    }
    if (Object.keys(body).length === 0) return;
    void handleTriage(body);
  }

  function toggleRowSelection(alertId: number, nextChecked: boolean) {
    setSelectedRowIds((prev) => {
      const next = new Set(prev);
      if (nextChecked) next.add(alertId);
      else next.delete(alertId);
      return next;
    });
  }

  function toggleAllVisibleRows(nextChecked: boolean) {
    setSelectedRowIds((prev) => {
      if (!nextChecked) {
        const next = new Set(prev);
        filtered.forEach((row) => next.delete(row.id));
        return next;
      }
      const next = new Set(prev);
      filtered.forEach((row) => next.add(row.id));
      return next;
    });
  }

  function clearSelectedRows() {
    setSelectedRowIds(new Set());
  }

  function openFirstSelected() {
    if (selectedRows.length === 0) return;
    openDrawerFor(selectedRows[0]);
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

  function openSelectedRuleEditor() {
    if (selectedRows.length === 0) return;
    const firstRule = String(selectedRows[0].rule_id || "").trim();
    if (!firstRule) return;
    nav(`/alerts/rules?rule_id=${encodeURIComponent(firstRule)}`);
  }

  function pivotSelectedToEvents() {
    if (selectedRows.length === 0) return;
    const first = selectedRows[0];
    setSelected(first);
    const sp = new URLSearchParams();
    const query = [
      first.src_ip,
      first.dst_ip,
      first.mitre_technique_id,
      first.rule_id,
    ]
      .filter(Boolean)
      .map((part) => String(part).trim())
      .find(Boolean);
    if (query) sp.set("search", query);
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
      <DataViewToolbar
        left={
          <div>
            <h2 className="text-lg font-semibold">Alert queue</h2>
            <div className="text-xs text-muted-foreground">
              Inspect alert triage queue, pivot into evidence, and tune detections from the same workflow.
            </div>
          </div>
        }
        right={
          <div className="flex flex-wrap items-center gap-2">
            <DebouncedSearchInput
              value={view.search}
              onChange={(value) => patch({ search: value })}
              placeholder="Search rule, IP, technique, description..."
              className="h-9 min-w-[220px] max-w-[360px]"
            />
            <SeverityFilter value={view.severity} onChange={(value) => patch({ severity: value })} />
            <TextInput
              value={view.rule_id}
              onChange={(event) => patch({ rule_id: event.target.value })}
              placeholder="Rule ID (exact)"
              className="h-9 w-[210px]"
              title="Exact server-side rule filter"
            />
            <Button
              variant="subtle"
              size="lg"
              onClick={() => patch({ density: view.density === "comfortable" ? "compact" : "comfortable" })}
              title="Toggle row density"
            >
              {view.density === "compact" ? "Compact" : "Comfort"}
            </Button>
            <Button
              variant={view.infinite_scroll ? "secondary" : "subtle"}
              size="lg"
              onClick={() => patch({ infinite_scroll: !view.infinite_scroll })}
              title="Auto-load older pages when scrolling"
            >
              {view.infinite_scroll ? "Infinite" : "Manual"}
            </Button>
            <Button
              variant="subtle"
              size="lg"
              onClick={() => loadHead("merge")}
              disabled={loading}
              title="Refresh queue"
            >
              Refresh
            </Button>
            <Button
              variant="primary"
              size="lg"
              onClick={handleRunAll}
              disabled={running}
              title="Run all rules now"
            >
              {running ? "Running…" : "Run rules"}
            </Button>
          </div>
        }
      />

      <DataQueryStateBanner
        tone={error ? "danger" : "neutral"}
        message={
          error
            ? error
            : `source realtime+cursor · mode ${view.infinite_scroll ? "infinite" : "manual"} · ${headerRight}`
        }
        right={`${selectedRows.length} selected`}
      />

      <DataStatsStrip
        stats={[
          { label: "Visible", value: filtered.length, hint: `${alerts.length} loaded` },
          { label: "Critical/High", value: severityBreakdown.critical + severityBreakdown.high },
          { label: "Medium/Low", value: severityBreakdown.medium + severityBreakdown.low },
          { label: "Unknown", value: severityBreakdown.unknown },
          { label: "Severity filter", value: view.severity },
          { label: "Rule filter", value: view.rule_id || "-" },
          { label: "Density", value: view.density },
          { label: "Selected", value: selectedRows.length },
        ]}
      />

      {selectedRows.length > 0 ? (
        <DataViewToolbar
          className="py-2"
          left={<div className="text-xs text-muted-foreground">{selectedRows.length} row(s) selected</div>}
          right={
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="subtle" size="md" onClick={openFirstSelected}>Open first evidence</Button>
              <Button variant="subtle" size="md" onClick={openSelectedRuleEditor}>Edit selected rule</Button>
              <Button variant="subtle" size="md" onClick={pivotSelectedToEvents}>Pivot to events</Button>
              <Button variant="subtle" size="md" onClick={clearSelectedRows}>Clear selection</Button>
            </div>
          }
        />
      ) : null}

      <Panel
        title="Queue"
        actions={<span className="text-[10px] font-mono text-muted-foreground">{headerRight}</span>}
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
            <AlertsQueueTable
              rows={filtered}
              selectedId={selected?.id ?? null}
              onEdit={openDrawerFor}
              density={view.density}
              selectedRowIds={selectedRowIds}
              onToggleRow={toggleRowSelection}
              onToggleAllRows={toggleAllVisibleRows}
            />

            <div className="sticky bottom-0 left-0 right-0 border-t border-border/60 bg-background/70 px-4 py-3 backdrop-blur">
              <DataPaginationFooter
                totalCount={filtered.length}
                pageSize={view.page_size}
                onPageSizeChange={(next) => patch({ page_size: next })}
                pageSizeOptions={[50, 100, 200]}
                hasMore={hasMore}
                loadingMore={loadingMore}
                onLoadMore={loadMore}
                loadMoreLabel="Load older"
                error={error}
                onRetry={error ? () => loadHead("merge") : undefined}
              />
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
        headerLabel="Alert"
      >
        {!selected ? (
          <EmptyState title="No selection" description="Select an alert using the View action in the queue." />
        ) : (
          <InvestigationShell>
            <InvestigationMetaStrip
              items={[
                { label: "Severity", value: String(selected.severity || "unknown"), variant: sevVariant(String(selected.severity || "unknown")) },
                { label: "Status", value: selected.status ?? "open" },
                { label: "Rule", value: selected.rule_id },
                { label: "Created", value: fmtTs(selected.created_at) },
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
                { key: "triage", label: "Triage" },
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
                  <InvestigationFactCard
                    label="Source IP"
                    value={<IpAddressPill ip={selected.src_ip} ipContext={alertIpContext(selected, "src")} compact />}
                  />
                  <InvestigationFactCard
                    label="Destination"
                    value={
                      <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
                        <IpAddressPill ip={selected.dst_ip} ipContext={alertIpContext(selected, "dst")} compact />
                        {typeof selected.dst_port === "number" ? <span className="text-muted-foreground">:{selected.dst_port}</span> : null}
                      </span>
                    }
                  />
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
                title="Evidence"
                subtitle="Rule provenance and structured evidence items that triggered this alert."
              >
                <div className="space-y-4">
                  {/* Provenance strip */}
                  {(selected.detector_type || selected.rule_version != null || selected.rule_hash) ? (
                    <div className="rounded-lg border border-border/60 bg-muted/20 px-3 py-2 space-y-1">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1.5">Rule provenance</div>
                      <InvestigationKeyValueGrid
                        entries={[
                          selected.detector_type ? { key: "detector_type", value: selected.detector_type } : null,
                          selected.rule_version != null ? { key: "rule_version", value: String(selected.rule_version) } : null,
                          selected.rule_hash ? { key: "rule_hash", value: selected.rule_hash } : null,
                          selected.ruleset_version ? { key: "ruleset_version", value: selected.ruleset_version } : null,
                        ].filter((x): x is { key: string; value: string } => x !== null)}
                      />
                    </div>
                  ) : null}

                  {/* Structured evidence items */}
                  {evidenceLoading ? (
                    <div className="text-xs text-muted-foreground py-2">Loading evidence…</div>
                  ) : evidenceItems.length > 0 ? (
                    <div className="space-y-2">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Evidence items</div>
                      {evidenceItems.map((ev) => (
                        <div key={ev.id} className="rounded-lg border border-border/60 bg-background/35 px-3 py-2 space-y-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-[11px] text-foreground">{ev.evidence_type}</span>
                            <span className={cx(
                              "text-[10px] rounded px-1.5 py-0.5",
                              ev.evidence_role === "trigger"
                                ? "bg-orange-500/15 text-orange-400"
                                : "bg-muted text-muted-foreground"
                            )}>{ev.evidence_role}</span>
                            {ev.entity_type && (
                              <span className="font-mono text-[11px] text-muted-foreground">
                                {ev.entity_type}={ev.entity_value ?? "-"}
                              </span>
                            )}
                          </div>
                          {ev.matched_field && (
                            <div className="font-mono text-[11px]">
                              <span className="text-muted-foreground">{ev.matched_field}: </span>
                              <span className="text-foreground">{ev.matched_value ?? "-"}</span>
                            </div>
                          )}
                          {ev.summary && (
                            <div className="text-xs text-muted-foreground">{ev.summary}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-xs text-muted-foreground py-1">No structured evidence items for this alert.</div>
                  )}

                  {/* Details fallback */}
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">Detection details</div>
                    <InvestigationKeyValueGrid
                      entries={toDetailEntries(selected.details).map((x) => ({ key: x.key, value: x.value }))}
                    />
                    {toDetailNested(selected.details).map((block) => (
                      <div key={block.key} className="rounded-lg border border-border/60 bg-background/35 p-3 mt-2">
                        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{block.key}</div>
                        <JsonBlock value={block.value} maxHeight="220px" showControls={false} className="mt-2" />
                      </div>
                    ))}
                  </div>
                </div>
              </InvestigationSection>
            ) : null}

            {drawerTab === "triage" ? (
              <InvestigationSection title="Triage" subtitle="Manage alert status, disposition, and analyst notes.">
                <div className="space-y-5">
                  <div className="flex flex-wrap items-center gap-3">
                    <div className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground w-20 shrink-0">Status</div>
                    <span className={cx(
                      "inline-flex items-center rounded-md px-2.5 py-0.5 text-xs font-semibold",
                      selected.status === "open" && "bg-blue-500/15 text-blue-400",
                      selected.status === "acknowledged" && "bg-yellow-500/15 text-yellow-400",
                      selected.status === "investigating" && "bg-orange-500/15 text-orange-400",
                      selected.status === "closed" && "bg-muted text-muted-foreground",
                    )}>
                      {selected.status ?? "open"}
                    </span>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    {(selected.status === "open" || selected.status === "acknowledged") && (
                      <Button
                        variant="subtle"
                        size="sm"
                        disabled={triaging}
                        onClick={() => void handleTriage({ status: "acknowledged" as AlertStatus })}
                      >
                        Acknowledge
                      </Button>
                    )}
                    {(selected.status === "open" || selected.status === "acknowledged") && (
                      <Button
                        variant="subtle"
                        size="sm"
                        disabled={triaging}
                        onClick={() => void handleTriage({ status: "investigating" as AlertStatus })}
                      >
                        Investigate
                      </Button>
                    )}
                    {selected.status !== "closed" && (
                      <div className="flex items-center gap-2">
                        <select
                          value={triageCloseDisposition}
                          onChange={(e) => setTriageCloseDisposition(e.target.value as AlertDisposition | "")}
                          className="h-8 rounded-md border border-border/60 bg-background px-2 text-xs text-foreground"
                          aria-label="Disposition for close"
                        >
                          <option value="">Select disposition…</option>
                          <option value="true_positive">True positive</option>
                          <option value="false_positive">False positive</option>
                          <option value="benign">Benign</option>
                          <option value="duplicate">Duplicate</option>
                          <option value="expected_activity">Expected activity</option>
                          <option value="unknown">Unknown</option>
                        </select>
                        <Button
                          variant="subtle"
                          size="sm"
                          disabled={triaging || !triageCloseDisposition}
                          onClick={() => void handleTriage({ status: "closed" as AlertStatus, disposition: triageCloseDisposition as AlertDisposition })}
                        >
                          Close
                        </Button>
                      </div>
                    )}
                    {selected.status === "closed" && (
                      <Button
                        variant="subtle"
                        size="sm"
                        disabled={triaging}
                        onClick={() => void handleTriage({ status: "open" as AlertStatus })}
                      >
                        Reopen
                      </Button>
                    )}
                  </div>

                  {triageError && (
                    <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                      {triageError}
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Priority (1–4)</label>
                      <TextInput
                        value={triagePriority}
                        onChange={(e) => setTriagePriority(e.target.value)}
                        placeholder="1–4"
                        className="h-8 w-full"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Risk score (0–100)</label>
                      <TextInput
                        value={triageRiskScore}
                        onChange={(e) => setTriageRiskScore(e.target.value)}
                        placeholder="0–100"
                        className="h-8 w-full"
                      />
                    </div>
                    <div className="space-y-1.5 col-span-2">
                      <label className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Assigned to</label>
                      <TextInput
                        value={triageAssignedTo}
                        onChange={(e) => setTriageAssignedTo(e.target.value)}
                        placeholder="analyst username"
                        className="h-8 w-full"
                      />
                    </div>
                    <div className="space-y-1.5 col-span-2">
                      <label className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Notes</label>
                      <textarea
                        value={triageNotes}
                        onChange={(e) => setTriageNotes(e.target.value)}
                        rows={4}
                        placeholder="Analyst notes…"
                        className="w-full rounded-md border border-border/60 bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring resize-none"
                      />
                    </div>
                  </div>

                  <div className="flex justify-end">
                    <Button
                      variant="primary"
                      size="sm"
                      disabled={triaging}
                      onClick={handleTriageFieldsSave}
                    >
                      {triaging ? "Saving…" : "Save fields"}
                    </Button>
                  </div>

                  {(selected.acknowledged_at || selected.closed_at) && (
                    <div className="rounded-lg border border-border/60 bg-muted/20 px-3 py-2 space-y-1">
                      {selected.acknowledged_at && (
                        <div className="text-xs text-muted-foreground">
                          Acknowledged {fmtTs(selected.acknowledged_at)}{selected.acknowledged_by ? ` by ${selected.acknowledged_by}` : ""}
                        </div>
                      )}
                      {selected.closed_at && (
                        <div className="text-xs text-muted-foreground">
                          Closed {fmtTs(selected.closed_at)}{selected.closed_by ? ` by ${selected.closed_by}` : ""}{selected.disposition ? ` · ${selected.disposition.replace(/_/g, " ")}` : ""}
                        </div>
                      )}
                    </div>
                  )}
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
