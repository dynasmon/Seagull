import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import EmptyState from "@/shared/components/EmptyState";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { MetricCard } from "@/shared/components/MetricCard";
import { DataQueryStateBanner, DataStatsStrip, DataViewToolbar } from "@/shared/components/DataView";
import { Table } from "@/shared/components/Table";
import { getFlowIpContext } from "@/shared/lib/ipClassification";
import type { Alert } from "./types";
import { SimpleTimeSeries } from "./components/Charts";
import { timeSeriesHasSignal } from "./dashboard_state";
import { OverviewLiveProvider, useOverviewLive } from "./live";
import {
  DEFAULT_OVERVIEW_WINDOW_MINUTES,
  durationMinutesBetween,
  resolveOverviewQuery,
  type OverviewResolvedQuery,
} from "./query";
import { resolveStormUiState } from "./live_realtime";
import { useOverviewLiteWindow } from "./useOverviewLiteWindow";

import {
  DashboardSection,
  HeaderBadge,
  OverviewPanel,
  OverviewRangeControls,
  QuickPivot,
  SeverityBadge,
  StatLinkTile,
} from "./components";

import { listAttackChainCases } from "@/features/attack_chain/api";

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

function overviewIpContext(row: any, side: "src" | "dst") {
  const direct = getFlowIpContext(row?.ip_context, side);
  if (direct) return direct;
  const details = normalizeDetails(row?.details);
  const fromDetails = getFlowIpContext(details.ip_context, side);
  if (fromDetails) return fromDetails;
  return getFlowIpContext(row?.extra?.ip_context, side);
}

function ipWithPort(ip: string | null | undefined, ipContext: any, port?: number | null) {
  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
      <IpAddressPill ip={ip} ipContext={ipContext} compact />
      {typeof port === "number" ? <span className="text-muted-foreground">:{port}</span> : null}
    </span>
  );
}

function toDate(input: unknown): Date | null {
  if (!input) return null;
  if (input instanceof Date) return Number.isNaN(input.getTime()) ? null : input;
  if (typeof input === "string" || typeof input === "number") {
    const d = new Date(input);
    return Number.isNaN(d.getTime()) ? null : d;
  }
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
  return `${src} · ${fresh} · ${degraded}`;
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
  if (details.base_rule_id) {
    return inferAttackKindFromRule(details.base_rule_id);
  }
  return inferAttackKindFromRule(alert.rule_id);
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
        ddosLastTarget: "-",
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
    let ddosLastTarget: ReactNode = "-";

    if (lastDdosAlert) {
      const details: any = normalizeDetails(lastDdosAlert.details);
      const { attack, vector } = resolveAttackKind(lastDdosAlert);
      ddosLastKind = `${attack} / ${vector}`;
      const proto = (details.proto || details.protocol || "-") as string;
      ddosLastTarget = (
        <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
          {ipWithPort(lastDdosAlert.dst_ip, overviewIpContext(lastDdosAlert, "dst"), lastDdosAlert.dst_port)}
          <span className="text-muted-foreground">/{proto || "-"}</span>
        </span>
      );
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
      ddosLastTarget,
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
          lastSeen,
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
    (x) => Boolean(x?.degraded_reason),
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
      <div className="space-y-4">
        <EmptyState title="Loading" hint="Fetching overview snapshot..." />
      </div>
    );
  }

  if (!snapshot) {
    return (
      <div className="space-y-4">
        <EmptyState title="No data" hint={error || "Overview snapshot is empty"} />
      </div>
    );
  }

  const headerRight = (
    <div className="flex flex-wrap items-center justify-end gap-2">
      {resolvedQuery.fixedRange ? <HeaderBadge text="Historical range" tone="neutral" /> : null}
      {degradedSources > 0 ? <HeaderBadge text={`Degraded sources: ${degradedSources}`} tone="warning" /> : null}
      {snapshot.meta?.ddos_telemetry_dropped_per_sec > 0 ? (
        <HeaderBadge text={`DDoS drop/s: ${snapshot.meta.ddos_telemetry_dropped_per_sec}`} tone="warning" />
      ) : null}
      {error ? <HeaderBadge text="API error" tone="danger" /> : null}
      {lastUpdatedAt ? <HeaderBadge text={`Updated ${fmtHHMM(lastUpdatedAt)}`} tone="neutral" /> : null}
    </div>
  );

  return (
    <div className="space-y-4 pb-16">
      <DataViewToolbar
        left={
          <div className="space-y-1">
            <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-primary/90">Command center</div>
            <div className="text-lg font-semibold tracking-tight text-foreground">Operational overview</div>
          </div>
        }
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
          { label: "Active agents", value: `${derived.onlineAgents}/${derived.totalAgents}`, tone: derived.onlineAgents > 0 ? "success" : "warning" },
          { label: "Alerts (window)", value: derived.alerts1h, tone: derived.alerts1h > 0 ? "warning" : "default" },
          { label: "DDoS detections (5m)", value: derived.ddos5m, tone: derived.ddos5m > 0 ? "warning" : "default" },
          { label: "DDoS peak PPS", value: fmtCompact(derived.ddosPeakPps), tone: derived.ddosPeakPps > 0 ? "warning" : "default" },
          { label: "Storm phase", value: stormPhaseLabel, tone: stormEffectiveActive ? "warning" : "success" },
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

      <DashboardSection id="ingestion" title="Ingestion & health" defaultOpen>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-6">
          <MetricCard size="sm" title="Events (last 5m)" value={derived.events5m} />
          <MetricCard size="sm" title={`Events (${windowLabel})`} value={derived.events1h} />
          <MetricCard
            size="sm"
            title="Active agents"
            value={derived.onlineAgents}
            helper={`total ${derived.totalAgents}`}
            tone={derived.onlineAgents > 0 ? "success" : "warning"}
          />
          <MetricCard
            size="sm"
            title="Last event ts"
            value={derived.lastEventTs}
            tone={derived.lastEventTs === "-" ? "warning" : "default"}
          />
          <MetricCard
            size="sm"
            title="Alerts (window)"
            value={derived.alerts1h}
            tone={derived.alerts1h > 0 ? "warning" : "success"}
          />
          <StatLinkTile
            to="/attack-chain"
            label="Attack chains (open)"
            value={acTile.loading ? "…" : acTile.hasMore ? `${acTile.openCount}+` : String(acTile.openCount)}
            description={
              acTile.error
                ? `Error: ${acTile.error}`
                : `last 24h · max score ${acTile.maxScore}${acTile.lastSeen ? ` · last ${fmtDateTime(acTile.lastSeen)}` : ""}`
            }
          />

          <MetricCard
            size="sm"
            title="Storm mode"
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
            size="sm"
            title="EPS (ingest)"
            value={storm?.eps ?? 0}
            helper={storm?.phase === "storm" ? "storm window" : "last second"}
            tone={storm?.phase === "storm" ? "warning" : "default"}
          />

          <MetricCard
            size="sm"
            title="Sample (hot/warm)"
            value={storm ? `${storm.sample_hot_percent}% / ${storm.sample_warm_percent}%` : "-"}
            helper="hot=Postgres · warm=ES"
            tone={stormEffectiveActive ? "warning" : "default"}
          />

          <MetricCard
            size="sm"
            title="Drop %"
            value={`${stormDropPercent}%`}
            helper="dropped from raw ingestion"
            tone={stormDropPercent > 0 || snapshot.meta?.ddos_telemetry_dropped_per_sec > 0 ? "warning" : "success"}
          />

          <MetricCard
            size="sm"
            title="Backlog (events)"
            value={stormBacklogEvents}
            helper={`messages: ${stormBacklogMessages}`}
            tone={stormBacklogEvents > 50000 ? "warning" : "default"}
          />

          <MetricCard
            size="sm"
            title="EPS (process)"
            value={storm?.process_rate_eps ?? 0}
            helper={storm ? `ingest: ${storm.ingest_rate_eps ?? storm.eps}` : undefined}
            tone={storm && (storm.process_rate_eps ?? 0) < (storm.ingest_rate_eps ?? storm.eps ?? 0) ? "warning" : "success"}
          />

          <MetricCard
            size="sm"
            title="Workers"
            value={storm?.workers_active ?? 0}
            helper={storm?.processed_messages_per_sec ? `msgs/s: ${storm.processed_messages_per_sec}` : undefined}
            tone={storm && (storm.workers_active ?? 0) > 0 ? "success" : "warning"}
          />

          <MetricCard
            size="sm"
            title="Drain time"
            value={storm?.phase === "draining" ? `${storm?.draining_seconds ?? 0}s` : "-"}
            helper={storm?.phase === "draining" ? "recovery window" : "not draining"}
            tone={storm?.phase === "draining" ? "default" : "success"}
          />
        </div>

        <OverviewPanel title="Telemetry quality" right={<span className="text-[10px] text-muted-foreground">rolling window</span>}>
          {qualityRows.length === 0 ? (
            <div className="text-xs text-muted-foreground">Quality breakdown unavailable right now.</div>
          ) : (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
              {qualityRows.map((q) => (
                <div key={q.event_type} className="rounded-md border border-border bg-surface-2/40 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="truncate text-sm font-semibold tracking-tight">{q.event_type}</div>
                    <div className="font-mono text-[11px] text-muted-foreground">{q.received}</div>
                  </div>
                  <div className="mt-2 grid grid-cols-3 gap-1 text-[10px] font-mono">
                    <div className="rounded border border-success/40 bg-success/10 px-2 py-1 text-center text-success">
                      keep {q.kept_percent}%
                    </div>
                    <div className="rounded border border-danger/40 bg-danger/10 px-2 py-1 text-center text-danger">
                      drop {q.drop_percent}%
                    </div>
                    <div className="rounded border border-info/40 bg-info/10 px-2 py-1 text-center text-info">
                      analytics {q.analytics_percent}%
                    </div>
                  </div>
                  <div className="mt-2 font-mono text-[11px] text-muted-foreground">
                    hot {q.hot_kept} · warm {q.warm_kept} · analytics {q.analytics_kept}
                  </div>
                </div>
              ))}
            </div>
          )}
        </OverviewPanel>
      </DashboardSection>

      <DashboardSection id="volume" title="Event volume" defaultOpen>
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          <OverviewPanel
            title="Events per minute by type"
            className="lg:col-span-2"
            style={{ height: H_PANEL_BIG }}
            right={
              <div className="flex items-center gap-3">
                {trafficWindow.isLoading ? (
                  <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">syncing</span>
                ) : null}
                {trafficWindow.error ? (
                  <span className="text-[10px] uppercase tracking-[0.1em] text-danger">refresh error</span>
                ) : null}
                <span className="font-mono text-[10px] text-muted-foreground">{fmtSource(trafficChartSourceMeta)}</span>
                <Link to="/events" className="text-[10px] font-semibold uppercase tracking-[0.1em] text-primary hover:underline">
                  View events
                </Link>
              </div>
            }
          >
            <OverviewRangeControls
              label="Event chart range"
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
                <EmptyState title="No signal" hint="Waiting for telemetry..." />
              </div>
            ) : (
              <div className="flex min-h-0 flex-1 items-center justify-center overflow-hidden">
                <div className="flex w-full max-w-full justify-center">
                  <SimpleTimeSeries
                    data={trafficChart.data}
                    seriesKeys={trafficChart.series}
                    height={190}
                    allowHorizontalScroll={false}
                  />
                </div>
              </div>
            )}
          </OverviewPanel>

          <div className="grid grid-cols-1 gap-3">
            <OverviewPanel title="SSH auth failures per minute" style={{ height: H_PANEL_SM }}>
              {snapshot.ssh_failures.data.length === 0 ? (
                <div className="flex h-full items-center justify-center text-xs text-muted-foreground">No SSH failures</div>
              ) : (
                <div className="flex h-full w-full items-center justify-center overflow-hidden">
                  <div className="flex w-full max-w-full justify-center">
                    <SimpleTimeSeries
                      data={snapshot.ssh_failures.data}
                      seriesKeys={snapshot.ssh_failures.series}
                      height={160}
                      allowHorizontalScroll={false}
                    />
                  </div>
                </div>
              )}
            </OverviewPanel>

            <OverviewPanel
              title="Ingest vs processed (events/min)"
              style={{ height: H_PANEL_SM }}
              right={<span className="font-mono text-[10px] text-muted-foreground">{fmtSource(ingestRatesSourceMeta)}</span>}
            >
              {!snapshot.ingest_rates || snapshot.ingest_rates.data.length === 0 ? (
                <div className="flex h-full items-center justify-center text-xs text-muted-foreground">No ingest rate signal</div>
              ) : (
                <div className="flex h-full w-full items-center justify-center overflow-hidden">
                  <div className="flex w-full max-w-full justify-center">
                    <SimpleTimeSeries
                      data={snapshot.ingest_rates.data}
                      seriesKeys={snapshot.ingest_rates.series}
                      height={160}
                      allowHorizontalScroll={false}
                    />
                  </div>
                </div>
              )}
            </OverviewPanel>
          </div>
        </div>
      </DashboardSection>

      <DashboardSection id="ssh" title="SSH auth deep dive" defaultOpen>
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
          <OverviewPanel
            title="Recent SSH auth events (normalized)"
            style={{ height: H_PANEL_TABLE }}
            scrollY
            right={<span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">scroll</span>}
          >
            {snapshot.recent_ssh.length === 0 ? (
              <EmptyState title="No SSH events" hint="No SSH auth events available in the current window." />
            ) : (
              <Table
                scrollX={false}
                className="text-xs"
                columns={[
                  {
                    key: "time",
                    title: "Time",
                    className: "font-mono text-muted-foreground w-28",
                    render: (r: any) => {
                      const raw = r.timestamp || r.ts || r.time;
                      if (!raw) return "-";
                      const d = new Date(raw);
                      return Number.isNaN(d.getTime()) ? String(raw) : fmtDateTime(d);
                    },
                  },
                  {
                    key: "agent",
                    title: "Agent",
                    className: "font-mono text-foreground w-32",
                    render: (r: any) => r.agent_id || r.agent || "-",
                  },
                  {
                    key: "src",
                    title: "Src",
                    className: "font-mono text-muted-foreground w-32",
                    render: (r: any) => <IpAddressPill ip={r.src_ip || r.src} ipContext={overviewIpContext(r, "src")} compact />,
                  },
                  {
                    key: "dst",
                    title: "Dst",
                    className: "font-mono text-muted-foreground w-32",
                    render: (r: any) => <IpAddressPill ip={r.dst_ip || r.dst} ipContext={overviewIpContext(r, "dst")} compact />,
                  },
                  {
                    key: "dst_port",
                    title: "Dst port",
                    className: "font-mono text-muted-foreground w-20",
                    render: (r: any) => r.dst_port ?? "-",
                  },
                  { key: "proto", title: "Proto", className: "font-mono text-muted-foreground w-20", render: (r: any) => r.proto || "-" },
                  { key: "action", title: "Action", className: "font-mono text-foreground", render: (r: any) => r.action || "-" },
                  { key: "username", title: "Username", className: "font-mono text-foreground", render: (r: any) => r.username || r.user || "-" },
                ]}
                rows={snapshot.recent_ssh as any}
                rowKey={(r: any, i) =>
                  `${r.timestamp || r.ts || r.time || "row"}-${r.id ?? "na"}-${r.agent_id || "na"}-${r.src_ip || r.src || "na"}-${i}`
                }
              />
            )}
          </OverviewPanel>

          <OverviewPanel
            title="Recent alerts"
            style={{ height: H_PANEL_TABLE }}
            scrollY
            right={
              <Link to="/alerts" className="text-[10px] font-semibold uppercase tracking-[0.1em] text-primary hover:underline">
                View alerts
              </Link>
            }
          >
            {snapshot.recent_alerts.length === 0 ? (
              <EmptyState title="No alerts" hint="No alerts found in the current window." />
            ) : (
              <Table
                scrollX={false}
                className="text-xs"
                columns={[
                  {
                    key: "created_at",
                    title: "Time",
                    className: "font-mono text-muted-foreground w-24",
                    render: (r: Alert) => fmtHHMM(new Date(r.created_at)),
                  },
                  { key: "severity", title: "Sev", className: "w-20", render: (r: Alert) => <SeverityBadge severity={r.severity} withDot /> },
                  { key: "rule_id", title: "Rule", className: "font-mono text-muted-foreground w-56" },
                  { key: "description", title: "Detection", className: "font-mono text-foreground" },
                  {
                    key: "src_ip",
                    title: "Src",
                    className: "font-mono text-muted-foreground w-32",
                    render: (r: Alert) => <IpAddressPill ip={r.src_ip} ipContext={overviewIpContext(r, "src")} compact />,
                  },
                ]}
                rows={snapshot.recent_alerts}
                rowKey={(r, i) => `${r.id ?? "na"}-${r.created_at || "na"}-${r.rule_id || "na"}-${i}`}
              />
            )}
          </OverviewPanel>
        </div>
      </DashboardSection>

      <DashboardSection id="talkers" title="Top talkers & ports" defaultOpen>
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
          <OverviewPanel title="Top source IPs (events)" style={{ height: H_PANEL_TABLE }} scrollY>
            {snapshot.top_sources.length === 0 ? (
              <EmptyState title="No data" hint="No source IPs available." />
            ) : (
              <Table
                className="text-xs"
                columns={[
                  {
                    key: "src_ip",
                    title: "Src IP",
                    className: "font-mono text-foreground",
                    render: (r: any) => <IpAddressPill ip={r.src_ip} ipContext={overviewIpContext(r, "src")} compact />,
                  },
                  { key: "count", title: "Events", className: "text-right font-mono text-primary w-24" },
                ]}
                rows={snapshot.top_sources}
                rowKey={(r, i) => `${r.src_ip || "na"}-${i}`}
              />
            )}
          </OverviewPanel>

          <OverviewPanel title="Top destination ports (flows)" style={{ height: H_PANEL_TABLE }} scrollY>
            {snapshot.ports.length === 0 ? (
              <EmptyState title="No data" hint="No port activity available." />
            ) : (
              <div className="space-y-2.5">
                {snapshot.ports.map((p) => (
                  <div key={p.port} className="flex items-center gap-3 text-xs">
                    <div className="w-14 text-right font-mono text-muted-foreground">:{p.port}</div>
                    <div className="h-1.5 flex-1 overflow-hidden rounded bg-muted/30">
                      <div
                        className="h-full rounded bg-primary/70"
                        style={{
                          width: `${Math.min(100, (p.count / Math.max(1, snapshot.ports[0]?.count || 1)) * 100)}%`,
                        }}
                      />
                    </div>
                    <div className="w-12 text-right font-mono text-foreground">{p.count}</div>
                  </div>
                ))}
              </div>
            )}
          </OverviewPanel>
        </div>
      </DashboardSection>

      <DashboardSection id="raw" title="Raw telemetry" defaultOpen={false}>
        <OverviewPanel
          title="Recent events"
          style={{ height: H_PANEL_TABLE }}
          scrollY
          right={<span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">scroll</span>}
        >
          {snapshot.raw_events.length === 0 ? (
            <EmptyState title="No events" hint="No raw events are available." />
          ) : (
            <Table
              scrollX={false}
              className="text-xs"
              columns={[
                {
                  key: "timestamp",
                  title: "Time",
                  className: "font-mono text-muted-foreground w-28",
                  render: (r: any) => fmtDateTime(new Date(r.timestamp)),
                },
                { key: "agent_id", title: "Agent", className: "font-mono text-foreground w-32" },
                { key: "event_type", title: "Type", className: "font-mono text-info w-28" },
                {
                  key: "src_ip",
                  title: "Src",
                  className: "font-mono text-muted-foreground w-32",
                  render: (r: any) => <IpAddressPill ip={r.src_ip} ipContext={overviewIpContext(r, "src")} compact />,
                },
                {
                  key: "dst_ip",
                  title: "Dst",
                  className: "font-mono text-muted-foreground w-32",
                  render: (r: any) => <IpAddressPill ip={r.dst_ip} ipContext={overviewIpContext(r, "dst")} compact />,
                },
                {
                  key: "dst_port",
                  title: "Dst port",
                  className: "font-mono text-muted-foreground w-20",
                  render: (r: any) => r.dst_port ?? "-",
                },
              ]}
              rows={snapshot.raw_events}
              rowKey={(r: any, i) => `${r.id ?? "na"}-${r.timestamp || "na"}-${r.agent_id || "na"}-${i}`}
            />
          )}
        </OverviewPanel>
      </DashboardSection>

      <DashboardSection id="ddos" title="DoS / DDoS posture" defaultOpen>
        <div className="space-y-3">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <MetricCard
              size="sm"
              title="DoS/DDoS detections (5m)"
              value={derived.ddos5m}
              tone={derived.ddos5m > 0 ? "warning" : "success"}
            />
            <MetricCard
              size="sm"
              title="DDoS packets est. (5m)"
              value={derived.ddosPackets5m}
              helper={`peak pps: ${fmtCompact(derived.ddosPeakPps)}`}
              tone={derived.ddosPackets5m > 0 ? "warning" : "success"}
            />
            <MetricCard
              size="sm"
              title="Last attack kind"
              value={derived.ddosLastKind}
              helper={`peak pps: ${fmtCompact(derived.ddosPeakPps)}`}
            />
            <MetricCard size="sm" title="Last target" value={derived.ddosLastTarget} />
            <MetricCard
              size="sm"
              title="Alerts (crit/high)"
              value={snapshot.ddos_alerts.length}
              tone={snapshot.ddos_alerts.length > 0 ? "warning" : "success"}
            />
          </div>

          <OverviewRangeControls
            label="DDoS chart range"
            query={ddosWindow.query}
            draft={ddosWindow.draft}
            onDraftChange={ddosWindow.onDraftChange}
            onApplyRange={ddosWindow.onApplyRange}
            onSetLiveWindow={ddosWindow.onSetLiveWindow}
            onResetToLive={ddosWindow.onResetToLive}
            applyDisabled={ddosWindow.applyDisabled}
          />

          <div className="grid grid-cols-1 gap-3 xl:grid-cols-3">
            <OverviewPanel
              title="DoS/DDoS detections per minute"
              style={{ height: H_PANEL_SM }}
              right={
                ddosWindow.isLoading ? (
                  <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">syncing</span>
                ) : ddosWindow.error ? (
                  <span className="text-[10px] uppercase tracking-[0.1em] text-danger">refresh error</span>
                ) : null
              }
            >
              {!hasDdosDetectionsSignal ? (
                <EmptyState title="No DDoS" hint="No DoS/DDoS detections available." />
              ) : (
                <div className="flex h-full w-full items-center justify-center overflow-hidden">
                  <div className="flex w-full max-w-full justify-center">
                    <SimpleTimeSeries
                      data={ddosChart?.data || []}
                      seriesKeys={ddosChart?.series || []}
                      height={160}
                      allowHorizontalScroll={false}
                    />
                  </div>
                </div>
              )}
            </OverviewPanel>

            <OverviewPanel
              title="Estimated DDoS packet volume / peak PPS"
              style={{ height: H_PANEL_SM }}
              right={
                <div className="flex items-center gap-3">
                  {ddosWindow.isLoading ? (
                    <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">syncing</span>
                  ) : null}
                  {ddosWindow.error ? (
                    <span className="text-[10px] uppercase tracking-[0.1em] text-danger">refresh error</span>
                  ) : null}
                  <span className="font-mono text-[10px] text-muted-foreground">{fmtSource(ddosVolumeSourceMeta)}</span>
                </div>
              }
            >
              {!hasDdosVolumeSignal ? (
                <EmptyState title="No DDoS volume" hint="No continuous DDoS telemetry available in the selected window." />
              ) : (
                <div className="flex h-full w-full items-center justify-center overflow-hidden">
                  <div className="flex w-full max-w-full justify-center">
                    <SimpleTimeSeries
                      data={ddosVolumeChart?.data || []}
                      seriesKeys={ddosVolumeChart?.series || []}
                      height={160}
                      allowHorizontalScroll={false}
                    />
                  </div>
                </div>
              )}
            </OverviewPanel>

            <OverviewPanel title="Recent DoS/DDoS detections" style={{ height: H_PANEL_TABLE }} scrollY isCritical={snapshot.ddos_alerts.length > 0}>
              {snapshot.ddos_alerts.length === 0 ? (
                <EmptyState title="No DDoS alerts" hint="No critical/high DoS/DDoS alerts found." />
              ) : (
                <Table
                  scrollX={false}
                  className="text-xs"
                  columns={[
                    {
                      key: "created_at",
                      title: "Time",
                      className: "font-mono text-muted-foreground w-28",
                      render: (r: Alert) => fmtDateTime(new Date(r.created_at)),
                    },
                    { key: "severity", title: "Sev", className: "w-20", render: (r: Alert) => <SeverityBadge severity={r.severity} withDot /> },
                    { key: "rule_id", title: "Rule", className: "font-mono text-muted-foreground w-64" },
                    {
                      key: "src_ip",
                      title: "Src",
                      className: "font-mono text-muted-foreground w-32",
                      render: (r: Alert) => <IpAddressPill ip={r.src_ip} ipContext={overviewIpContext(r, "src")} compact />,
                    },
                    {
                      key: "dst_ip",
                      title: "Dst",
                      className: "font-mono text-muted-foreground w-32",
                      render: (r: Alert) => <IpAddressPill ip={r.dst_ip} ipContext={overviewIpContext(r, "dst")} compact />,
                    },
                    {
                      key: "dst_port",
                      title: "Dst port",
                      className: "font-mono text-muted-foreground w-20",
                      render: (r: Alert) => r.dst_port ?? "-",
                    },
                    { key: "description", title: "Desc", className: "font-mono text-foreground" },
                  ]}
                  rows={snapshot.ddos_alerts}
                  rowKey={(r, i) => `${r.id ?? "na"}-${r.created_at || "na"}-${r.rule_id || "na"}-${i}`}
                />
              )}
            </OverviewPanel>
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
