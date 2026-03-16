import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode, CSSProperties } from "react";
import { Link } from "react-router-dom";

import EmptyState from "@/shared/components/EmptyState";
import { Table } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";
import type { Alert, StormStatus } from "./types";
import { SimpleTimeSeries } from "./components/Charts";
import { useOverviewLive } from "./live";

import { getStormStatus } from "./api";

import { listAttackChainCases } from "@/features/attack_chain/api";

// One overview snapshot covers this time window.
const WINDOW_MINUTES = 60;

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
    ? "border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.2)]"
    : "border-border/60";
  const bgClass = isCritical ? "bg-red-950/10" : "bg-background/70";

  return (
    <div
      className={cx("border", borderClass, bgClass, "backdrop-blur-sm flex flex-col", className)}
      style={style}
    >
      <div
        className={cx(
          "flex items-center justify-between border-b px-3 py-2 shrink-0",
          isCritical ? "border-red-500/30 bg-red-500/10" : "border-border/60 bg-muted/10"
        )}
      >
        <h3
          className={cx(
            "text-xs font-bold uppercase tracking-widest font-mono",
            isCritical ? "text-red-400 animate-pulse" : "text-primary/90"
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
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1 font-mono">{label}</div>
      <div className={cx("text-3xl font-bold font-mono tracking-tight leading-none", valueClass)}>{value}</div>
      {hint && <div className="text-[10px] text-muted-foreground font-mono opacity-70 mt-1">{hint}</div>}
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

function SeverityBadge({ severity }: { severity: string }) {
  const s = (severity || "").toLowerCase();
  let color = "text-muted-foreground border-border/60 bg-muted/10";

  if (s === "critical") color = "text-red-500 border-red-500 bg-red-500/10";
  else if (s === "high") color = "text-orange-500 border-orange-500 bg-orange-500/10";
  else if (s === "medium") color = "text-yellow-500 border-yellow-500 bg-yellow-500/10";
  else if (s === "low") color = "text-blue-500 border-blue-500 bg-blue-500/10";

  return <span className={`px-2 py-0.5 text-[10px] uppercase font-mono border ${color} font-medium`}>{severity}</span>;
}

export default function OverviewPage() {
  const { snapshot, isLoading, error, lastUpdatedAt } = useOverviewLive();

  const [storm, setStorm] = useState<StormStatus | null>(null);

  useEffect(() => {
    let alive = true;

    const tick = async () => {
      try {
        const s = await getStormStatus();
        if (!alive) return;
        setStorm(s);
      } catch {
        if (!alive) return;
        setStorm(null);
      }
    };

    tick();
    const timer = window.setInterval(tick, 3000);

    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

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
    const events5m = snapshot.kpis.events_5m;
    const alerts1h = snapshot.kpis.alerts_60m;

    const events1h = snapshot.traffic.data.reduce((acc, row) => acc + sumRow(row), 0);

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
      events1h,
      alerts1h,
      lastEventTs,
      ddos5m,
      ddosPackets5m,
      ddosPeakPps,
      ddosLastKind,
      ddosLastTarget
    };
  }, [snapshot]);

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
    <div className="flex items-center gap-3">
      {error && <span className="text-[10px] font-mono text-red-400">API ERROR</span>}
      {lastUpdatedAt && (
        <span className="text-[10px] font-mono text-muted-foreground">UPDATED: {fmtHHMM(lastUpdatedAt)}</span>
      )}
    </div>
  );

  return (
    <div className="min-h-screen pb-20 font-sans text-sm text-foreground">
      <div className="flex items-center justify-between mb-4">
        <div className="text-xs font-mono uppercase tracking-[0.35em] text-muted-foreground">Overview</div>
        {headerRight}
      </div>

      <DashboardSection id="ingestion" title="INGESTION & HEALTH" defaultOpen>
        <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
          <StatTile label="EVENTS (last 5m)" value={derived.events5m} />
          <StatTile label={`EVENTS (last ${WINDOW_MINUTES}m)`} value={derived.events1h} />
          <StatTile
            label="ACTIVE AGENTS"
            value={derived.onlineAgents}
            hint={`TOTAL: ${derived.totalAgents}`}
            tone={derived.onlineAgents > 0 ? "good" : "warn"}
          />
          <StatTile label="LAST EVENT TS" value={derived.lastEventTs} tone={derived.lastEventTs === "-" ? "warn" : "default"} />
          <StatTile label="ALERTS (last 1h)" value={derived.alerts1h} tone={derived.alerts1h > 0 ? "warn" : "good"} />

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

          <StatTile
            label="STORM MODE"
            value={
              storm?.phase === "storm"
                ? "ATTACK"
                : storm?.phase === "shedding"
                  ? "SHEDDING"
                : storm?.phase === "draining"
                  ? "DRAINING"
                  : storm?.active
                    ? "ACTIVE"
                    : "OK"
            }
            hint={
              storm
                ? `${storm.reason}${storm.open_alert_id ? ` · alert #${storm.open_alert_id}` : ""}`
                : "unavailable"
            }
            tone={
              storm?.phase === "storm" || storm?.phase === "shedding"
                ? "warn"
                : storm?.phase === "draining"
                  ? "default"
                  : storm?.active
                    ? "warn"
                    : "good"
            }
          />

          <StatTile
            label="EPS (ingest)"
            value={storm?.eps ?? 0}
            hint={storm?.phase === "storm" ? "storm window" : "last second"}
            tone={storm?.phase === "storm" ? "warn" : "default"}
          />

          <StatTile
            label="SAMPLE (hot/warm)"
            value={storm ? `${storm.sample_hot_percent}% / ${storm.sample_warm_percent}%` : "-"}
            hint="hot=Postgres · warm=ES"
            tone={storm?.active ? "warn" : "default"}
          />

          <StatTile
            label="DROP %"
            value={storm ? `${storm.drop_percent}%` : "0%"}
            hint="dropped from raw ingestion"
            tone={storm && storm.drop_percent > 0 ? "warn" : "good"}
          />

          <StatTile
            label="BACKLOG (events)"
            value={storm?.backlog_events ?? 0}
            hint={storm ? `messages: ${storm.backlog_messages}` : undefined}
            tone={storm && storm.backlog_events > 50000 ? "warn" : "default"}
          />

          <StatTile
            label="EPS (process)"
            value={storm?.process_rate_eps ?? 0}
            hint={storm ? `ingest: ${storm.ingest_rate_eps ?? storm.eps}` : undefined}
            tone={storm && (storm.process_rate_eps ?? 0) < (storm.ingest_rate_eps ?? storm.eps ?? 0) ? "warn" : "good"}
          />

          <StatTile
            label="WORKERS"
            value={storm?.workers_active ?? 0}
            hint={storm?.processed_messages_per_sec ? `msgs/s: ${storm.processed_messages_per_sec}` : undefined}
            tone={storm && (storm.workers_active ?? 0) > 0 ? "good" : "warn"}
          />

          <StatTile
            label="DRAIN TIME"
            value={storm?.phase === "draining" ? `${storm?.draining_seconds ?? 0}s` : "-"}
            hint={storm?.phase === "draining" ? "recovery window" : "not draining"}
            tone={storm?.phase === "draining" ? "default" : "good"}
          />
        </div>
      </DashboardSection>

      <DashboardSection id="volume" title="EVENT VOLUME" defaultOpen>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <CyberPanel
            title="Events per minute by type"
            className={cx("lg:col-span-2")}
            style={{ height: H_PANEL_BIG }}
            right={
              <Link to="/events" className="text-[10px] font-mono uppercase tracking-wider text-primary hover:underline">
                View events
              </Link>
            }
          >
            {snapshot.traffic.data.length === 0 ? (
              <EmptyState title="NO SIGNAL" hint="Waiting for telemetry..." />
            ) : (
              <div className="h-full w-full flex items-center justify-center overflow-hidden">
                <div className="w-full max-w-full flex justify-center">
                  <SimpleTimeSeries
                    data={snapshot.traffic.data}
                    seriesKeys={snapshot.traffic.series}
                    height={250}
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

            <CyberPanel title="Alert severity" style={{ height: H_PANEL_SM }}>
              {snapshot.alert_severity.data.length === 0 ? (
                <div className="flex items-center justify-center h-full text-[10px] text-muted-foreground font-mono tracking-widest">
                  NO ACTIVE THREATS
                </div>
              ) : (
                <div className="h-full w-full flex items-center justify-center overflow-hidden">
                  <div className="w-full max-w-full flex justify-center">
                    <SimpleTimeSeries
                      data={snapshot.alert_severity.data}
                      seriesKeys={snapshot.alert_severity.series}
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
                        const raw = r.ts || r.time || r.timestamp;
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
                  rowKey={(r: any, i) => `${r.ts || r.time || r.timestamp || "row"}-${i}`}
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
                  rowKey={(r) => String(r.id)}
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
                rowKey={(r) => r.src_ip}
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
                  { key: "event_type", title: "TYPE", className: "font-mono text-blue-400 w-28" },
                  { key: "src_ip", title: "SRC", className: "font-mono text-muted-foreground w-32", render: (r: any) => r.src_ip || "-" },
                  { key: "dst_ip", title: "DST", className: "font-mono text-muted-foreground w-32", render: (r: any) => r.dst_ip || "-" },
                  { key: "dst_port", title: "DST PORT", className: "font-mono text-muted-foreground w-24", render: (r: any) => (r.dst_port ?? "-") }
                ]}
                rows={snapshot.raw_events}
                rowKey={(r: any) => String(r.id)}
            />
          )}
        </CyberPanel>
      </DashboardSection>

      <DashboardSection id="ddos" title="DOS / DDOS" defaultOpen>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <StatTile label="DoS/DDoS detections (last 5m)" value={derived.ddos5m} tone={derived.ddos5m > 0 ? "warn" : "good"} />
          <StatTile
            label="DDoS packets est. (last 5m)"
            value={derived.ddosPackets5m}
            hint={`peak pps: ${fmtCompact(derived.ddosPeakPps)}`}
            tone={derived.ddosPackets5m > 0 ? "warn" : "good"}
          />
          <StatTile label="Last attack kind" value={derived.ddosLastKind} hint={`peak pps: ${fmtCompact(derived.ddosPeakPps)}`} />
          <StatTile label="Last target" value={derived.ddosLastTarget} />
          <StatTile label="Alerts (critical/high)" value={snapshot.ddos_alerts.length} tone={snapshot.ddos_alerts.length > 0 ? "warn" : "good"} />
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <CyberPanel title="DoS/DDoS detections per minute" style={{ height: H_PANEL_SM }}>
            {snapshot.ddos.data.length === 0 ? (
              <EmptyState title="NO DDOS" hint="No DoS/DDoS detections available." />
            ) : (
              <div className="h-full w-full flex items-center justify-center overflow-hidden">
                <div className="w-full max-w-full flex justify-center">
                  <SimpleTimeSeries
                    data={snapshot.ddos.data}
                    seriesKeys={snapshot.ddos.series}
                    height={160}
                    allowHorizontalScroll={false}
                  />
                </div>
              </div>
            )}
          </CyberPanel>

          <CyberPanel title="Estimated DDoS packet volume / peak PPS" style={{ height: H_PANEL_SM }}>
            {!snapshot.ddos_volume || snapshot.ddos_volume.data.length === 0 ? (
              <EmptyState title="NO DDOS VOLUME" hint="No packet telemetry captured from dos_attack events." />
            ) : (
              <div className="h-full w-full flex items-center justify-center overflow-hidden">
                <div className="w-full max-w-full flex justify-center">
                  <SimpleTimeSeries
                    data={snapshot.ddos_volume.data}
                    seriesKeys={snapshot.ddos_volume.series}
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
                  rowKey={(r) => String(r.id)}
              />
            )}
          </CyberPanel>
        </div>
      </DashboardSection>
    </div>
  );
}
