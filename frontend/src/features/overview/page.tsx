import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode, CSSProperties } from "react";
import { Link } from "react-router-dom";

import EmptyState from "@/shared/components/EmptyState";
import { MetricCard } from "@/shared/components/MetricCard";
import { DataQueryStateBanner, DataStatsStrip, DataViewToolbar } from "@/shared/components/DataView";
import { Table } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";
import type { Alert } from "./types";
import { SimpleTimeSeries } from "./components/Charts";
import { timeSeriesHasSignal } from "./dashboard_state";
import { OverviewLiveProvider, useOverviewLive } from "./live";
import {
  DEFAULT_OVERVIEW_WINDOW_MINUTES,
  durationMinutesBetween,
  resolveOverviewQuery,
  type OverviewQueryState,
  type OverviewResolvedQuery,
} from "./query";
import { resolveStormUiState } from "./live_realtime";
import { severityBadgeClasses } from "@/shared/lib/severity";
import { useOverviewLiteWindow } from "./useOverviewLiteWindow";

import { listAttackChainCases } from "@/features/attack_chain/api";

// Panel heights to keep the dashboard compact (Grafana-style).
const H_PANEL_BIG = 340;
const H_PANEL_SM = 240;
const H_PANEL_TABLE = 340;

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

function toDate(input: unknown): Date | null {
  if (!input) return null;

  if (input instanceof Date) {
    return Number.isNaN(input.getTime()) ? null : input;
  }

  if (typeof input === "string" || typeof input === "number") {
    const d = new Date(input);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  // Defensive: handle common "{ value: ... }" patterns.
  if (typeof input === "object" && (input as any).value) {
    const d = new Date((input as any).value);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  return null;
}

function fmtHHMM(input: unknown) {
  const d = toDate(input);
  if (!d) return "-";
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit" });
}

function fmtDateTime(input: unknown) {
  const d = toDate(input);
  if (!d) return "-";
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

function fmtDurationCompact(totalMinutes: number): string {
  const minutes = Math.max(1, Math.trunc(Number(totalMinutes) || 0));
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  if (hours < 24) return mins === 0 ? `${hours}h` : `${hours}h ${mins}m`;
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  return remHours === 0 ? `${days}d` : `${days}d ${remHours}h`;
}

function fmtRangeSummary(startIso: string | null | undefined, endIso: string | null | undefined): string {
  if (!startIso || !endIso) return "-";
  return `${fmtDateTime(startIso)} → ${fmtDateTime(endIso)}`;
}

function sumRow(row: Record<string, any>): number {
  let total = 0;
  for (const [k, v] of Object.entries(row)) {
    if (k === "t") continue;
    const n = Number(v);
    if (!Number.isFinite(n)) continue;
    total += n;
  }
  return total;
}

function fmtCompact(value: number): string {
  if (!Number.isFinite(value)) return "0";
  return new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

function fmtSource(meta?: { source?: string; source_freshness_seconds?: number | null; degraded_reason?: string | null }) {
  if (!meta) return "source: -";
  const src = String(meta.source || "unknown");
  const fresh = Number.isFinite(meta.source_freshness_seconds as number)
    ? `${Number(meta.source_freshness_seconds)}s`
    : "-";
  const degraded = meta.degraded_reason ? "degraded" : "ok";
  return `source: ${src} · freshness: ${fresh} · ${degraded}`;
}

function inferAttackKindFromRule(ruleIdRaw: unknown): { attack: string; vector: string } {
  const ruleId = String(ruleIdRaw || "").toLowerCase();
  if (!ruleId) return { attack: "ddos", vector: "-" };

  if (ruleId.includes("incident_ddos_correlated")) return { attack: "ddos", vector: "correlated" };
  if (ruleId.includes("http_flood")) return { attack: "ddos", vector: "http_flood" };
  if (ruleId.includes("tls_handshake_flood")) return { attack: "ddos", vector: "tls_handshake_flood" };
  if (ruleId.startsWith("l7_")) return { attack: "ddos", vector: "l7_flood" };
  if (ruleId.startsWith("ddos_")) return { attack: "ddos", vector: "flood" };
  if (ruleId.startsWith("dos_")) return { attack: "dos", vector: "flood" };

  return { attack: "ddos", vector: "-" };
}

function resolveAttackKind(alert: Alert): { attack: string; vector: string } {
  const details: any = normalizeDetails(alert.details);

  const attack =
    details.attack ||
    details.extra_attack ||
    details.group_key?.attack ||
    details.enrichment?.attack ||
    null;

  const vector =
    details.vector ||
    details.extra_vector ||
    details.group_key?.vector ||
    details.subtype ||
    details.enrichment?.vector ||
    null;

  if (attack || vector) {
    return { attack: String(attack || "ddos"), vector: String(vector || "-") };
  }

  // Correlation incidents usually carry base_rule_id with richer semantics.
  if (details.base_rule_id) {
    return inferAttackKindFromRule(details.base_rule_id);
  }

  return inferAttackKindFromRule(alert.rule_id);
}

function CyberPanel({
  title,
  children,
  right,
  className = "",
  isCritical = false,
  scrollY = false,
  bodyClassName = "",
  style
}: {
  title: string;
  children: ReactNode;
  right?: ReactNode;
  className?: string;
  isCritical?: boolean;
  scrollY?: boolean;
  bodyClassName?: string;
  style?: CSSProperties;
}) {
  const borderClass = isCritical
    ? "border-danger/50 shadow-[0_0_15px_rgb(var(--danger)/0.2)]"
    : "border-border/60";
  const bgClass = isCritical ? "bg-danger/5" : "bg-background/70";

  return (
    <div
      className={cx("border", borderClass, bgClass, "backdrop-blur-sm flex flex-col", className)}
      style={style}
    >
      <div
        className={cx(
          "flex items-center justify-between border-b px-3 py-2 shrink-0",
          isCritical ? "border-danger/30 bg-danger/10" : "border-border/60 bg-muted/10"
        )}
      >
        <h3
          className={cx(
            "text-xs font-bold uppercase tracking-widest font-mono",
            isCritical ? "text-danger animate-pulse" : "text-primary/90"
          )}
        >
          {title}
        </h3>
        {right && <div className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">{right}</div>}
      </div>

      <div
        className={cx(
          "p-3 flex-1 min-h-0",
          scrollY ? "overflow-y-auto" : "overflow-hidden",
          bodyClassName
        )}
      >
        {children}
      </div>
    </div>
  );
}

function DashboardSection({
  id,
  title,
  children,
  defaultOpen = true
}: {
  id: string;
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  const key = `nw_overview_section_${id}`;
  const [open, setOpen] = useState(() => {
    try {
      const v = localStorage.getItem(key);
      if (v === null) return defaultOpen;
      return v === "1";
    } catch {
      return defaultOpen;
    }
  });

  function toggle() {
    setOpen((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(key, next ? "1" : "0");
      } catch {
        // no-op
      }
      return next;
    });
  }

  return (
    <div className="space-y-4">
      <button type="button" onClick={toggle} className="w-full flex items-center gap-3 text-left select-none">
        {/* keep arrows exactly as-is */}
        <span className="text-muted-foreground font-mono text-xs">{open ? "▾" : "▸"}</span>
        <span className="text-[11px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
          {title}
        </span>
        <div className="h-px bg-border/60 flex-1" />
      </button>
      {open && <div className="space-y-4">{children}</div>}
    </div>
  );
}


function StatLinkTile({
  to,
  label,
  value,
  description
}: {
  to: string;
  label: string;
  value: string;
  description?: string;
}) {
  return (
    <Link
      to={to}
      className={cx(
        "rounded-xl border border-border/60 bg-background/70 backdrop-blur-md p-4",
        "hover:bg-muted/15 transition-colors",
        "focus:outline-none focus:ring-2 focus:ring-primary/30"
      )}
    >
      <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">{label}</div>
      <div className="mt-2 text-2xl font-semibold tracking-tight">{value}</div>
      {description ? <div className="mt-1 text-xs text-muted-foreground">{description}</div> : null}
    </Link>
  );
}

function BadgeTone({
  text,
  tone
}: {
  text: string;
  tone: "neutral" | "warning" | "danger";
}) {
  const cls =
    tone === "danger"
      ? "border-danger/40 bg-danger/10 text-danger"
      : tone === "warning"
        ? "border-warning/40 bg-warning/10 text-warning"
        : "border-border/60 bg-background/40 text-muted-foreground";
  return <span className={cx("rounded-md border px-2 py-1 text-[10px] font-mono", cls)}>{text}</span>;
}

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cx(
        "h-6 rounded-full border px-2.5 text-[8px] font-mono uppercase tracking-[0.24em] transition-colors",
        active
          ? "border-primary/50 bg-primary/10 text-primary"
          : "border-border/60 bg-background/40 text-muted-foreground hover:bg-muted/15"
      )}
    >
      {children}
    </button>
  );
}

function OverviewRangeControls({
  label = "Range",
  query,
  draft,
  onDraftChange,
  onApplyRange,
  onSetLiveWindow,
  onResetToLive,
  applyDisabled,
}: {
  label?: string;
  query: OverviewQueryState;
  draft: { from: string; to: string };
  onDraftChange: (field: "from" | "to", value: string) => void;
  onApplyRange: () => void;
  onSetLiveWindow: (minutes: number) => void;
  onResetToLive: () => void;
  applyDisabled: boolean;
}) {
  const historical = Boolean(query.from || query.to);

  return (
    <div className="border-b border-border/40 pb-2">
      <div className="flex flex-col gap-2 2xl:flex-row 2xl:items-end 2xl:justify-between">
        <div className="flex flex-wrap items-center gap-1.5">
          <div className="text-[8px] font-mono font-bold uppercase tracking-[0.28em] text-muted-foreground">
            {label}
          </div>
          <div className="text-[8px] font-mono uppercase tracking-[0.16em] text-muted-foreground">
            {historical ? "Historical paused" : `Live ${fmtDurationCompact(query.windowMinutes)}`}
          </div>
          <FilterChip active={!historical && query.windowMinutes === 60} onClick={() => onSetLiveWindow(60)}>60m</FilterChip>
          <FilterChip active={!historical && query.windowMinutes === 360} onClick={() => onSetLiveWindow(360)}>6h</FilterChip>
          <FilterChip active={!historical && query.windowMinutes === 1440} onClick={() => onSetLiveWindow(1440)}>24h</FilterChip>
        </div>

        <div className="flex flex-wrap items-end gap-1.5">
          <label className="flex flex-col gap-1">
            <div className="text-[8px] font-mono uppercase tracking-[0.16em] text-muted-foreground">From</div>
            <input
              type="datetime-local"
              value={draft.from}
              onChange={(e) => onDraftChange("from", e.target.value)}
              className="h-7 w-full rounded-md border border-border/60 bg-background/70 px-2 text-[11px] text-foreground outline-none focus:border-primary/50 sm:w-[11rem]"
            />
          </label>

          <label className="flex flex-col gap-1">
            <div className="text-[8px] font-mono uppercase tracking-[0.16em] text-muted-foreground">To</div>
            <input
              type="datetime-local"
              value={draft.to}
              onChange={(e) => onDraftChange("to", e.target.value)}
              className="h-7 w-full rounded-md border border-border/60 bg-background/70 px-2 text-[11px] text-foreground outline-none focus:border-primary/50 sm:w-[11rem]"
            />
          </label>

          <button
            type="button"
            onClick={onApplyRange}
            disabled={applyDisabled}
            className={cx(
              "h-7 rounded-md border px-2 text-[9px] font-mono uppercase tracking-[0.16em] transition-colors",
              applyDisabled
                ? "cursor-not-allowed border-border/40 bg-background/30 text-muted-foreground/60"
                : "border-primary/40 bg-primary/10 text-primary hover:bg-primary/15"
            )}
          >
            Apply
          </button>

          <button
            type="button"
            onClick={onResetToLive}
            className="h-7 rounded-md border border-border/60 bg-background/40 px-2 text-[9px] font-mono uppercase tracking-[0.16em] text-muted-foreground transition-colors hover:bg-muted/15"
          >
            Live
          </button>
        </div>
      </div>
    </div>
  );
}

function QuickPivot({
  to,
  label,
  hint
}: {
  to: string;
  label: string;
  hint: string;
}) {
  return (
    <Link
      to={to}
      className={cx(
        "rounded-lg border border-border/60 bg-background/70 px-3 py-2.5",
        "hover:bg-muted/15 focus:outline-none focus:ring-2 focus:ring-primary/30"
      )}
    >
      <div className="text-[10px] font-mono uppercase tracking-[0.15em] text-muted-foreground">{label}</div>
      <div className="mt-1 text-xs text-foreground">{hint}</div>
    </Link>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`px-2 py-0.5 text-[10px] uppercase font-mono border ${severityBadgeClasses(severity)} font-medium`}>
      {severity}
    </span>
  );
}

function OverviewPageView({
  resolvedQuery,
}: {
  resolvedQuery: OverviewResolvedQuery;
}) {
  const { snapshot, storm, isLoading, error, lastUpdatedAt } = useOverviewLive();
  const trafficWindow = useOverviewLiteWindow({ baseQuery: resolvedQuery });
  const ddosWindow = useOverviewLiteWindow({ baseQuery: resolvedQuery });

  const derived = useMemo(() => {
    if (!snapshot) {
      return {
        totalAgents: 0,
        onlineAgents: 0,
        events5m: 0,
        events1h: 0,
        alerts1h: 0,
        lastEventTs: "-",
        ddos5m: 0,
        ddosPackets5m: 0,
        ddosPeakPps: 0,
        ddosLastKind: "-",
        ddosLastTarget: "-"
      };
    }

    const totalAgents = snapshot.kpis.total_agents;
    const onlineAgents = snapshot.kpis.online_agents;
    const eventsWindow = snapshot.traffic.data.reduce((acc, row) => acc + sumRow(row), 0);
    const events5mFromChart = snapshot.traffic.data.slice(-5).reduce((acc, row) => acc + sumRow(row), 0);
    const events5m = snapshot.kpis.events_5m > 0 ? snapshot.kpis.events_5m : events5mFromChart;
    const alertsWindow = snapshot.kpis.alerts_60m;


    const lastEvent = snapshot.raw_events?.[0]?.timestamp ? new Date(snapshot.raw_events[0].timestamp) : null;
    const lastEventTs = lastEvent ? fmtDateTime(lastEvent) : "-";

    const ddosRows = snapshot.ddos.data.slice(-5);
    const ddos5m = ddosRows.reduce((acc, row) => acc + sumRow(row), 0);
    const ddosVolRows = snapshot.ddos_volume?.data?.slice(-5) || [];
    const ddosPackets5m = ddosVolRows.reduce((acc, row) => acc + Number(row?.packets || 0), 0);
    const ddosPeakPps = ddosVolRows.reduce((acc, row) => Math.max(acc, Number(row?.peak_pps || 0)), 0);

    const lastDdosAlert = snapshot.ddos_alerts?.[0] || null;
    let ddosLastKind = "-";
    let ddosLastTarget = "-";

    if (lastDdosAlert) {
      const details: any = normalizeDetails(lastDdosAlert.details);
      const { attack, vector } = resolveAttackKind(lastDdosAlert);
      ddosLastKind = `${attack} / ${vector}`;

      const proto = (details.proto || details.protocol || "-") as string;
      const dstIp = lastDdosAlert.dst_ip || "-";
      const dstPort = lastDdosAlert.dst_port ? String(lastDdosAlert.dst_port) : "-";
      ddosLastTarget = `${dstIp}:${dstPort}/${proto}`;
    }

    return {
      totalAgents,
      onlineAgents,
      events5m,
      events1h: eventsWindow,
      alerts1h: alertsWindow,
      lastEventTs,
      ddos5m,
      ddosPackets5m,
      ddosPeakPps,
      ddosLastKind,
      ddosLastTarget
    };
  }, [snapshot]);

  const qualityRows = useMemo(() => {
    return (storm?.quality_by_event_type || []).slice(0, 8);
  }, [storm]);

  const [acTile, setAcTile] = useState<{
    loading: boolean;
    error: string | null;
    openCount: number;
    hasMore: boolean;
    maxScore: number;
    lastSeen: string | null;
  }>({ loading: true, error: null, openCount: 0, hasMore: false, maxScore: 0, lastSeen: null });
  const acLastFetchRef = useRef(0);

  // Lightweight attack-chain tile: kept independent of the overview snapshot API.
  useEffect(() => {
    if (!snapshot) return;
    const now = Date.now();
    if (now - acLastFetchRef.current < 15000) return;
    acLastFetchRef.current = now;

    const sinceIso = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    setAcTile((p) => ({ ...p, loading: true, error: null }));

    listAttackChainCases({ status: "open", page_size: 200, since: sinceIso })
      .then((out) => {
        const items = out.items || [];
        const maxScore = items.reduce((m, x) => Math.max(m, x.score || 0), 0);
        const lastSeen = items.length ? items[0].last_seen_at : null;
        setAcTile({
          loading: false,
          error: null,
          openCount: items.length,
          hasMore: Boolean(out.has_more),
          maxScore,
          lastSeen
        });
      })
      .catch((e: any) => {
        setAcTile((p) => ({ ...p, loading: false, error: e?.message || "Failed" }));
      });
  }, [snapshot, lastUpdatedAt]);

  const trafficSourceMeta = snapshot?.meta?.sources?.traffic;
  const trafficChart = trafficWindow.snapshot?.traffic ?? snapshot?.traffic;
  const trafficChartSourceMeta = trafficWindow.snapshot?.meta?.sources?.traffic ?? trafficSourceMeta;
  const ddosVolumeBaseSourceMeta = snapshot?.meta?.sources?.ddos_volume;
  const ddosChart = ddosWindow.snapshot?.ddos ?? snapshot?.ddos;
  const ddosVolumeChart = ddosWindow.snapshot?.ddos_volume ?? snapshot?.ddos_volume;
  const ddosVolumeSourceMeta = ddosWindow.snapshot?.meta?.sources?.ddos_volume ?? ddosVolumeBaseSourceMeta;
  const ingestRatesSourceMeta = snapshot?.meta?.sources?.ingest_rates;
  const degradedSources = [trafficSourceMeta, ddosVolumeBaseSourceMeta, ingestRatesSourceMeta].filter(
    (x) => Boolean(x?.degraded_reason)
  ).length;
  const stormUi = resolveStormUiState(storm, snapshot?.meta);
  const stormEffectiveActive = stormUi.effectiveActive;
  const stormBacklogEvents = storm?.backlog_events ?? Number(snapshot?.meta?.backlog_events || 0);
  const stormBacklogMessages = storm?.backlog_messages ?? Number(snapshot?.meta?.backlog_messages || 0);
  const stormDropPercent = storm?.drop_percent ?? 0;
  const stormPhaseLabel = stormUi.phaseLabel;
  const hasDdosDetectionsSignal = timeSeriesHasSignal(ddosChart?.data || []);
  const hasDdosVolumeSignal = timeSeriesHasSignal(ddosVolumeChart?.data || []);
  const activeWindowStart = snapshot?.query_meta?.query_window_start || snapshot?.meta?.window_start || resolvedQuery.startTs || null;
  const activeWindowEnd = snapshot?.query_meta?.query_window_end || snapshot?.meta?.window_end || resolvedQuery.endTs || null;
  const windowDurationMinutes = durationMinutesBetween(activeWindowStart, activeWindowEnd) ?? resolvedQuery.windowMinutes;
  const windowLabel = fmtDurationCompact(windowDurationMinutes);
  const rangeSummary = fmtRangeSummary(activeWindowStart, activeWindowEnd);

  if (isLoading && !snapshot) {
    return (
      <div className="min-h-screen p-6">
        <EmptyState title="LOADING" hint="Fetching overview snapshot..." />
      </div>
    );
  }

  if (!snapshot) {
    return (
      <div className="min-h-screen p-6">
        <EmptyState title="NO DATA" hint={error || "Overview snapshot is empty"} />
      </div>
    );
  }

  const headerRight = (
    <div className="flex flex-wrap items-center justify-end gap-2">
      {resolvedQuery.fixedRange ? <BadgeTone text="Historical range" tone="neutral" /> : null}
      {degradedSources > 0 ? <BadgeTone text={`Degraded sources: ${degradedSources}`} tone="warning" /> : null}
      {snapshot.meta?.ddos_telemetry_dropped_per_sec > 0 ? (
        <BadgeTone text={`DDoS drop/s: ${snapshot.meta.ddos_telemetry_dropped_per_sec}`} tone="warning" />
      ) : null}
      {error ? <BadgeTone text="API error" tone="danger" /> : null}
      {lastUpdatedAt ? <BadgeTone text={`Updated ${fmtHHMM(lastUpdatedAt)}`} tone="neutral" /> : null}
    </div>
  );

  return (
    <div className="min-h-screen pb-20 font-sans text-sm text-foreground space-y-4">
      <DataViewToolbar
        left={<div className="text-xs font-mono uppercase tracking-[0.35em] text-muted-foreground">Overview</div>}
        right={headerRight}
      />

      {snapshot.query_meta ? (
        <DataQueryStateBanner
          tone={snapshot.query_meta.degraded_reason ? "warning" : "neutral"}
          message={`range ${rangeSummary} · query ${snapshot.query_meta.source}${!resolvedQuery.fixedRange && typeof snapshot.query_meta.source_freshness_seconds === "number" ? ` · ${snapshot.query_meta.source_freshness_seconds}s` : ""}${snapshot.query_meta.cache_hit ? " · cache" : ""}${resolvedQuery.fixedRange ? " · realtime paused" : ""}`}
        />
      ) : null}

      <DataStatsStrip
        stats={[
          { label: "Events (5m)", value: derived.events5m },
          { label: `Events (${windowLabel})`, value: derived.events1h },
          { label: "Active agents", value: `${derived.onlineAgents}/${derived.totalAgents}` },
          { label: "Alerts (window)", value: derived.alerts1h },
          { label: "DDoS detections (5m)", value: derived.ddos5m },
          { label: "DDoS peak PPS", value: fmtCompact(derived.ddosPeakPps) },
          { label: "Storm phase", value: stormPhaseLabel },
          { label: "Ingest EPS", value: storm?.eps ?? 0 },
        ]}
      />

      <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-4">
        <QuickPivot to="/events" label="Event Stream" hint="Live telemetry and drilldown" />
        <QuickPivot to="/alerts/queue" label="Alerts Queue" hint="Active detections and triage" />
        <QuickPivot to="/attack-chain" label="Attack Chains" hint="Open incident timelines" />
        <QuickPivot to="/events/ddos" label="DDoS Module" hint="Detection stream and attack posture" />
        <QuickPivot to="/events/network" label="Protocol Intel" hint="L4/L7 evidence and pivots" />
        <QuickPivot to="/events/ssh" label="SSH Insights" hint="Auth anomalies and source IP context" />
        <QuickPivot to="/investigations" label="Investigations" hint="Workspaces and evidence tracking" />
        <QuickPivot to="/inventory" label="Inventory" hint="Agent asset and exposure context" />
      </div>

      <DashboardSection id="ingestion" title="INGESTION & HEALTH" defaultOpen>
        <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
          <MetricCard title="EVENTS (last 5m)" value={derived.events5m} />
          <MetricCard title={`EVENTS (${windowLabel})`} value={derived.events1h} />
          <MetricCard
            title="ACTIVE AGENTS"
            value={derived.onlineAgents}
            helper={`TOTAL: ${derived.totalAgents}`}
            tone={derived.onlineAgents > 0 ? "success" : "warning"}
          />
          <MetricCard title="LAST EVENT TS" value={derived.lastEventTs} tone={derived.lastEventTs === "-" ? "warning" : "default"} />
          <MetricCard title="ALERTS (window)" value={derived.alerts1h} tone={derived.alerts1h > 0 ? "warning" : "success"} />

          <StatLinkTile
            to="/attack-chain"
            label="ATTACK CHAINS (open)"
            value={acTile.loading ? "…" : acTile.hasMore ? `${acTile.openCount}+` : String(acTile.openCount)}
            description={
              acTile.error
                ? `Error: ${acTile.error}`
                : `Last 24h · max score ${acTile.maxScore}${acTile.lastSeen ? ` · last ${fmtDateTime(acTile.lastSeen)}` : ""}`
            }
          />

          <MetricCard
            title="STORM MODE"
            value={
              storm?.phase === "storm"
                ? "ATTACK"
                : storm?.phase === "shedding"
                  ? "SHEDDING"
                : storm?.phase === "draining"
                  ? "DRAINING"
                  : stormEffectiveActive
                    ? "ACTIVE"
                    : "OK"
            }
            helper={
              storm
                ? `${storm.reason}${storm.open_alert_id ? ` · alert #${storm.open_alert_id}` : ""}`
                : snapshot.meta?.protection_active
                  ? "ingest protection active"
                  : "unavailable"
            }
            tone={
              storm?.phase === "storm" || storm?.phase === "shedding"
                ? "warning"
                : storm?.phase === "draining"
                  ? "default"
                  : stormEffectiveActive
                    ? "warning"
                    : "success"
            }
          />

          <MetricCard
            title="EPS (ingest)"
            value={storm?.eps ?? 0}
            helper={storm?.phase === "storm" ? "storm window" : "last second"}
            tone={storm?.phase === "storm" ? "warning" : "default"}
          />

          <MetricCard
            title="SAMPLE (hot/warm)"
            value={storm ? `${storm.sample_hot_percent}% / ${storm.sample_warm_percent}%` : "-"}
            helper="hot=Postgres · warm=ES"
            tone={stormEffectiveActive ? "warning" : "default"}
          />

          <MetricCard
            title="DROP %"
            value={`${stormDropPercent}%`}
            helper="dropped from raw ingestion"
            tone={stormDropPercent > 0 || snapshot.meta?.ddos_telemetry_dropped_per_sec > 0 ? "warning" : "success"}
          />

          <MetricCard
            title="BACKLOG (events)"
            value={stormBacklogEvents}
            helper={`messages: ${stormBacklogMessages}`}
            tone={stormBacklogEvents > 50000 ? "warning" : "default"}
          />

          <MetricCard
            title="EPS (process)"
            value={storm?.process_rate_eps ?? 0}
            helper={storm ? `ingest: ${storm.ingest_rate_eps ?? storm.eps}` : undefined}
            tone={storm && (storm.process_rate_eps ?? 0) < (storm.ingest_rate_eps ?? storm.eps ?? 0) ? "warning" : "success"}
          />

          <MetricCard
            title="WORKERS"
            value={storm?.workers_active ?? 0}
            helper={storm?.processed_messages_per_sec ? `msgs/s: ${storm.processed_messages_per_sec}` : undefined}
            tone={storm && (storm.workers_active ?? 0) > 0 ? "success" : "warning"}
          />

          <MetricCard
            title="DRAIN TIME"
            value={storm?.phase === "draining" ? `${storm?.draining_seconds ?? 0}s` : "-"}
            helper={storm?.phase === "draining" ? "recovery window" : "not draining"}
            tone={storm?.phase === "draining" ? "default" : "success"}
          />
        </div>
        <div className="mt-4 rounded-xl border border-border/60 bg-background/60 p-4">
          <div className="flex items-center justify-between gap-2">
            <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
              Telemetry Quality
            </div>
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
              by event type (rolling window)
            </div>
          </div>
          {qualityRows.length === 0 ? (
            <div className="mt-3 text-xs text-muted-foreground">Quality breakdown unavailable right now.</div>
          ) : (
            <div className="mt-3 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
              {qualityRows.map((q) => (
                <div key={q.event_type} className="rounded-lg border border-border/60 bg-background/40 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-sm font-semibold tracking-tight truncate">{q.event_type}</div>
                    <div className="text-[11px] font-mono text-muted-foreground">{q.received}</div>
                  </div>
                  <div className="mt-2 grid grid-cols-3 gap-1 text-[10px] font-mono">
                    <div className="rounded border border-success/40 bg-success/10 px-2 py-1 text-success text-center">
                      keep {q.kept_percent}%
                    </div>
                    <div className="rounded border border-danger/40 bg-danger/10 px-2 py-1 text-danger text-center">
                      drop {q.drop_percent}%
                    </div>
                    <div className="rounded border border-info/40 bg-info/10 px-2 py-1 text-info text-center">
                      analytics {q.analytics_percent}%
                    </div>
                  </div>
                  <div className="mt-2 text-[11px] text-muted-foreground font-mono">
                    hot {q.hot_kept} · warm {q.warm_kept} · analytics {q.analytics_kept}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </DashboardSection>

      <DashboardSection id="volume" title="EVENT VOLUME" defaultOpen>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <CyberPanel
            title="Events per minute by type"
            className={cx("lg:col-span-2")}
            style={{ height: H_PANEL_BIG }}
            bodyClassName="flex flex-col gap-3"
            right={
              <div className="flex items-center gap-3">
                {trafficWindow.isLoading ? (
                  <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">syncing</span>
                ) : null}
                {trafficWindow.error ? (
                  <span className="text-[10px] font-mono uppercase tracking-wider text-danger">refresh error</span>
                ) : null}
                <span className="text-[10px] font-mono text-muted-foreground">{fmtSource(trafficChartSourceMeta)}</span>
                <Link to="/events" className="text-[10px] font-mono uppercase tracking-wider text-primary hover:underline">
                  View events
                </Link>
              </div>
            }
          >
            <OverviewRangeControls
              label="Event Chart Range"
              query={trafficWindow.query}
              draft={trafficWindow.draft}
              onDraftChange={trafficWindow.onDraftChange}
              onApplyRange={trafficWindow.onApplyRange}
              onSetLiveWindow={trafficWindow.onSetLiveWindow}
              onResetToLive={trafficWindow.onResetToLive}
              applyDisabled={trafficWindow.applyDisabled}
            />
            {!trafficChart || trafficChart.data.length === 0 ? (
              <div className="flex min-h-0 flex-1 items-center justify-center">
                <EmptyState title="NO SIGNAL" hint="Waiting for telemetry..." />
              </div>
            ) : (
              <div className="flex min-h-0 flex-1 items-center justify-center overflow-hidden">
                <div className="w-full max-w-full flex justify-center">
                  <SimpleTimeSeries
                    data={trafficChart.data}
                    seriesKeys={trafficChart.series}
                    height={190}
                    allowHorizontalScroll={false}
                  />
                </div>
              </div>
            )}
          </CyberPanel>

          <div className="grid grid-cols-1 gap-4">
            <CyberPanel title="SSH auth failures per minute" style={{ height: H_PANEL_SM }}>
              {snapshot.ssh_failures.data.length === 0 ? (
                <div className="flex items-center justify-center h-full text-[10px] text-muted-foreground font-mono tracking-widest">
                  NO SSH FAILURES
                </div>
              ) : (
                <div className="h-full w-full flex items-center justify-center overflow-hidden">
                  <div className="w-full max-w-full flex justify-center">
                    <SimpleTimeSeries
                      data={snapshot.ssh_failures.data}
                      seriesKeys={snapshot.ssh_failures.series}
                      height={160}
                      allowHorizontalScroll={false}
                    />
                  </div>
                </div>
              )}
            </CyberPanel>

            <CyberPanel title="Ingest vs processed (events/min)" style={{ height: H_PANEL_SM }} right={fmtSource(ingestRatesSourceMeta)}>
              {!snapshot.ingest_rates || snapshot.ingest_rates.data.length === 0 ? (
                <div className="flex items-center justify-center h-full text-[10px] text-muted-foreground font-mono tracking-widest">
                  NO INGEST RATE SIGNAL
                </div>
              ) : (
                <div className="h-full w-full flex items-center justify-center overflow-hidden">
                  <div className="w-full max-w-full flex justify-center">
                    <SimpleTimeSeries
                      data={snapshot.ingest_rates.data}
                      seriesKeys={snapshot.ingest_rates.series}
                      height={160}
                      allowHorizontalScroll={false}
                    />
                  </div>
                </div>
              )}
            </CyberPanel>
          </div>
        </div>
      </DashboardSection>

      <DashboardSection id="ssh" title="SSH AUTH DEEP DIVE" defaultOpen>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <CyberPanel
            title="Recent SSH auth events (normalized)"
            style={{ height: H_PANEL_TABLE }}
            scrollY
            right={<span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">scroll</span>}
          >
            {snapshot.recent_ssh.length === 0 ? (
              <EmptyState title="NO SSH EVENTS" hint="No SSH auth events available in the current window." />
            ) : (
              <Table
                scrollX={false}
                className="text-xs"
                columns={[
                    {
                      key: "time",
                      title: "TIME",
                      className: "font-mono text-muted-foreground w-28",
                      render: (r: any) => {
                        const raw = r.timestamp || r.ts || r.time;
                        if (!raw) return "-";
                        const d = new Date(raw);
                        return Number.isNaN(d.getTime()) ? String(raw) : fmtDateTime(d);
                      }
                    },
                    {
                      key: "agent",
                      title: "AGENT",
                      className: "font-mono text-foreground w-32",
                      render: (r: any) => r.agent_id || r.agent || "-"
                    },
                    {
                      key: "src",
                      title: "SRC",
                      className: "font-mono text-muted-foreground w-32",
                      render: (r: any) => r.src_ip || r.src || "-"
                    },
                    {
                      key: "dst",
                      title: "DST",
                      className: "font-mono text-muted-foreground w-32",
                      render: (r: any) => r.dst_ip || r.dst || "-"
                    },
                    {
                      key: "dst_port",
                      title: "DST PORT",
                      className: "font-mono text-muted-foreground w-24",
                      render: (r: any) => (r.dst_port ?? "-")
                    },
                    {
                      key: "proto",
                      title: "PROTO",
                      className: "font-mono text-muted-foreground w-20",
                      render: (r: any) => r.proto || "-"
                    },
                    {
                      key: "action",
                      title: "ACTION",
                      className: "font-mono text-foreground w-40",
                      render: (r: any) => r.action || "-"
                    },
                    {
                      key: "username",
                      title: "USERNAME",
                      className: "font-mono text-foreground w-40",
                      render: (r: any) => r.username || r.user || "-"
                    }
                  ]}
                  rows={snapshot.recent_ssh as any}
                  rowKey={(r: any, i) =>
                    `${r.timestamp || r.ts || r.time || "row"}-${r.id ?? "na"}-${r.agent_id || "na"}-${r.src_ip || r.src || "na"}-${i}`
                  }
              />
            )}
          </CyberPanel>

          <CyberPanel
            title="Recent alerts"
            style={{ height: H_PANEL_TABLE }}
            scrollY
            right={
              <Link to="/alerts" className="text-[10px] font-mono uppercase tracking-wider text-primary hover:underline">
                View alerts
              </Link>
            }
          >
            {snapshot.recent_alerts.length === 0 ? (
              <EmptyState title="NO ALERTS" hint="No alerts found in the current window." />
            ) : (
              <Table
                scrollX={false}
                className="text-xs"
                columns={[
                    {
                      key: "created_at",
                      title: "TIME",
                      className: "font-mono text-muted-foreground w-24",
                      render: (r: Alert) => fmtHHMM(new Date(r.created_at))
                    },
                    { key: "severity", title: "SEV", className: "w-20", render: (r: Alert) => <SeverityBadge severity={r.severity} /> },
                    { key: "rule_id", title: "RULE", className: "font-mono text-muted-foreground w-56" },
                    { key: "description", title: "DETECTION", className: "font-mono text-foreground" },
                    { key: "src_ip", title: "SRC", className: "font-mono text-muted-foreground w-32", render: (r: Alert) => r.src_ip || "-" }
                  ]}
                  rows={snapshot.recent_alerts}
                  rowKey={(r, i) => `${r.id ?? "na"}-${r.created_at || "na"}-${r.rule_id || "na"}-${i}`}
              />
            )}
          </CyberPanel>
        </div>
      </DashboardSection>

      <DashboardSection id="talkers" title="TOP TALKERS & PORTS" defaultOpen>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <CyberPanel title="Top Source IPs (events)" style={{ height: H_PANEL_TABLE }} scrollY>
            {snapshot.top_sources.length === 0 ? (
              <EmptyState title="NO DATA" hint="No source IPs available." />
            ) : (
              <Table
                className="text-xs"
                columns={[
                  { key: "src_ip", title: "SRC IP", className: "font-mono text-foreground" },
                  { key: "count", title: "EVENTS", className: "text-right font-mono text-primary w-24" }
                ]}
                rows={snapshot.top_sources}
                rowKey={(r, i) => `${r.src_ip || "na"}-${i}`}
              />
            )}
          </CyberPanel>

          <CyberPanel title="Top Destination Ports (flows)" style={{ height: H_PANEL_TABLE }} scrollY>
            {snapshot.ports.length === 0 ? (
              <EmptyState title="NO DATA" hint="No port activity available." />
            ) : (
              <div className="space-y-3">
                {snapshot.ports.map((p) => (
                  <div key={p.port} className="flex items-center gap-3 text-xs">
                    <div className="w-14 text-muted-foreground font-mono text-right">:{p.port}</div>
                    <div className="flex-1 h-1.5 bg-muted/20 overflow-hidden">
                      <div
                        className="h-full bg-primary/70"
                        style={{
                          width: `${Math.min(100, (p.count / Math.max(1, snapshot.ports[0]?.count || 1)) * 100)}%`
                        }}
                      />
                    </div>
                    <div className="w-12 text-right font-mono text-foreground">{p.count}</div>
                  </div>
                ))}
              </div>
            )}
          </CyberPanel>
        </div>
      </DashboardSection>

      <DashboardSection id="raw" title="RAW TELEMETRY" defaultOpen={false}>
        <CyberPanel
          title="Recent Events"
          style={{ height: H_PANEL_TABLE }}
          scrollY
          right={<span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">scroll</span>}
        >
          {snapshot.raw_events.length === 0 ? (
            <EmptyState title="NO EVENTS" hint="No raw events are available." />
          ) : (
            <Table
              scrollX={false}
              className="text-xs"
              columns={[
                  {
                    key: "timestamp",
                    title: "TIME",
                    className: "font-mono text-muted-foreground w-28",
                    render: (r: any) => fmtDateTime(new Date(r.timestamp))
                  },
                  { key: "agent_id", title: "AGENT", className: "font-mono text-foreground w-32" },
                  { key: "event_type", title: "TYPE", className: "font-mono text-info w-28" },
                  { key: "src_ip", title: "SRC", className: "font-mono text-muted-foreground w-32", render: (r: any) => r.src_ip || "-" },
                  { key: "dst_ip", title: "DST", className: "font-mono text-muted-foreground w-32", render: (r: any) => r.dst_ip || "-" },
                  { key: "dst_port", title: "DST PORT", className: "font-mono text-muted-foreground w-24", render: (r: any) => (r.dst_port ?? "-") }
                ]}
                rows={snapshot.raw_events}
                rowKey={(r: any, i) => `${r.id ?? "na"}-${r.timestamp || "na"}-${r.agent_id || "na"}-${i}`}
            />
          )}
        </CyberPanel>
      </DashboardSection>

      <DashboardSection id="ddos" title="DOS / DDOS" defaultOpen>
        <div className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <MetricCard title="DoS/DDoS detections (last 5m)" value={derived.ddos5m} tone={derived.ddos5m > 0 ? "warning" : "success"} />
            <MetricCard
              title="DDoS packets est. (last 5m)"
              value={derived.ddosPackets5m}
              helper={`peak pps: ${fmtCompact(derived.ddosPeakPps)}`}
              tone={derived.ddosPackets5m > 0 ? "warning" : "success"}
            />
            <MetricCard title="Last attack kind" value={derived.ddosLastKind} helper={`peak pps: ${fmtCompact(derived.ddosPeakPps)}`} />
            <MetricCard title="Last target" value={derived.ddosLastTarget} />
            <MetricCard title="Alerts (critical/high)" value={snapshot.ddos_alerts.length} tone={snapshot.ddos_alerts.length > 0 ? "warning" : "success"} />
          </div>

          <OverviewRangeControls
            label="DDoS Chart Range"
            query={ddosWindow.query}
            draft={ddosWindow.draft}
            onDraftChange={ddosWindow.onDraftChange}
            onApplyRange={ddosWindow.onApplyRange}
            onSetLiveWindow={ddosWindow.onSetLiveWindow}
            onResetToLive={ddosWindow.onResetToLive}
            applyDisabled={ddosWindow.applyDisabled}
          />

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            <CyberPanel
              title="DoS/DDoS detections per minute"
              style={{ height: H_PANEL_SM }}
              right={
                ddosWindow.isLoading ? (
                  <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">syncing</span>
                ) : ddosWindow.error ? (
                  <span className="text-[10px] font-mono uppercase tracking-wider text-danger">refresh error</span>
                ) : null
              }
            >
              {!hasDdosDetectionsSignal ? (
                <EmptyState title="NO DDOS" hint="No DoS/DDoS detections available." />
              ) : (
                <div className="h-full w-full flex items-center justify-center overflow-hidden">
                  <div className="w-full max-w-full flex justify-center">
                    <SimpleTimeSeries
                      data={ddosChart?.data || []}
                      seriesKeys={ddosChart?.series || []}
                      height={160}
                      allowHorizontalScroll={false}
                    />
                  </div>
                </div>
              )}
            </CyberPanel>

            <CyberPanel
              title="Estimated DDoS packet volume / peak PPS"
              style={{ height: H_PANEL_SM }}
              right={
                <div className="flex items-center gap-3">
                  {ddosWindow.isLoading ? (
                    <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">syncing</span>
                  ) : null}
                  {ddosWindow.error ? (
                    <span className="text-[10px] font-mono uppercase tracking-wider text-danger">refresh error</span>
                  ) : null}
                  <span className="text-[10px] font-mono text-muted-foreground">{fmtSource(ddosVolumeSourceMeta)}</span>
                </div>
              }
            >
              {!hasDdosVolumeSignal ? (
                <EmptyState title="NO DDOS VOLUME" hint="No continuous DDoS telemetry available in the selected window." />
              ) : (
                <div className="h-full w-full flex items-center justify-center overflow-hidden">
                  <div className="w-full max-w-full flex justify-center">
                    <SimpleTimeSeries
                      data={ddosVolumeChart?.data || []}
                      seriesKeys={ddosVolumeChart?.series || []}
                      height={160}
                      allowHorizontalScroll={false}
                    />
                  </div>
                </div>
              )}
            </CyberPanel>

            <CyberPanel title="Recent DoS/DDoS detections" style={{ height: H_PANEL_TABLE }} scrollY>
              {snapshot.ddos_alerts.length === 0 ? (
                <EmptyState title="NO DDOS ALERTS" hint="No critical/high DoS/DDoS alerts found." />
              ) : (
                <Table
                  scrollX={false}
                  className="text-xs"
                  columns={[
                      {
                        key: "created_at",
                        title: "TIME",
                        className: "font-mono text-muted-foreground w-28",
                        render: (r: Alert) => fmtDateTime(new Date(r.created_at))
                      },
                      { key: "severity", title: "SEV", className: "w-20", render: (r: Alert) => <SeverityBadge severity={r.severity} /> },
                      { key: "rule_id", title: "RULE", className: "font-mono text-muted-foreground w-64" },
                      { key: "src_ip", title: "SRC", className: "font-mono text-muted-foreground w-32", render: (r: Alert) => r.src_ip || "-" },
                      { key: "dst_ip", title: "DST", className: "font-mono text-muted-foreground w-32", render: (r: Alert) => r.dst_ip || "-" },
                      { key: "dst_port", title: "DST PORT", className: "font-mono text-muted-foreground w-24", render: (r: Alert) => (r.dst_port ?? "-") },
                      { key: "description", title: "DESC", className: "font-mono text-foreground" }
                    ]}
                    rows={snapshot.ddos_alerts}
                    rowKey={(r, i) => `${r.id ?? "na"}-${r.created_at || "na"}-${r.rule_id || "na"}-${i}`}
                />
              )}
            </CyberPanel>
          </div>
        </div>
      </DashboardSection>
    </div>
  );
}

export default function OverviewPage() {
  const resolvedQuery = useMemo(
    () =>
      resolveOverviewQuery({
        windowMinutes: DEFAULT_OVERVIEW_WINDOW_MINUTES,
        from: "",
        to: "",
      }),
    [],
  );

  return (
    <OverviewLiveProvider query={resolvedQuery}>
      <OverviewPageView resolvedQuery={resolvedQuery} />
    </OverviewLiveProvider>
  );
}
