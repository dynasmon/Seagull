import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import EmptyState from "@/shared/components/EmptyState";
import { Table } from "@/shared/components/Table";
import { SimpleTimeSeries } from "./components/Charts";

import { getAgents, getPortStats, getRecentAlerts, getRecentEvents } from "./api";
import type { Agent, Alert, NetEvent } from "./types";

const MAX_FETCH_LIMIT = 1000;
const VISUAL_TABLE_LIMIT = 30;

function minutesAgo(d: Date) {
  return Math.floor((Date.now() - d.getTime()) / 60000);
}

function bucketMinute(iso: string) {
  const d = new Date(iso);
  d.setSeconds(0, 0);
  return d;
}

function fmtHHMM(d: Date) {
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit" });
}

function CyberPanel({
  title,
  children,
  right,
  className = "",
  isCritical = false
}: {
  title: string;
  children: ReactNode;
  right?: ReactNode;
  className?: string;
  isCritical?: boolean;
}) {
  const borderClass = isCritical ? "border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.2)]" : "border-border/60";
  const bgClass = isCritical ? "bg-red-950/10" : "bg-background/50";

  return (
    <div className={`border ${borderClass} ${bgClass} backdrop-blur-sm flex flex-col transition-all duration-300 ${className}`}>
      <div className={`flex items-center justify-between border-b ${isCritical ? "border-red-500/30 bg-red-500/10" : "border-border/60 bg-muted/10"} px-4 py-2 shrink-0`}>
        <h3 className={`text-xs font-bold uppercase tracking-widest font-mono ${isCritical ? "text-red-400 animate-pulse" : "text-primary/90"}`}>
          {title}
        </h3>
        {right && <div className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">{right}</div>}
      </div>
      <div className="p-4 flex-1 min-h-0 relative overflow-hidden">{children}</div>
    </div>
  );
}

function StatBlock({
  label,
  value,
  sub,
  active = false,
  warning = false
}: {
  label: string;
  value: string | number;
  sub?: string;
  active?: boolean;
  warning?: boolean;
}) {
  let colorClass = "text-foreground";
  if (warning) colorClass = "text-red-500 animate-pulse";
  else if (active) colorClass = "text-primary";

  return (
    <div className={`flex flex-col px-6 py-3 border-r border-border/60 last:border-r-0 ${warning ? "bg-red-500/5" : ""}`}>
      <span className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1 font-mono">{label}</span>
      <div className={`text-2xl font-bold font-mono tracking-tight leading-none mb-1 ${colorClass}`}>
        {value}
      </div>
      {sub && <span className="text-[10px] text-muted-foreground font-mono opacity-70">{sub}</span>}
    </div>
  );
}

function SectionDivider({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-4 py-6">
      <div className="h-px bg-border/60 flex-1"></div>
      <span className="text-[10px] font-mono uppercase text-muted-foreground tracking-[0.3em]">{label}</span>
      <div className="h-px bg-border/60 flex-1"></div>
    </div>
  );
}

function CyberBadge({ severity }: { severity: string }) {
  const s = (severity || "").toLowerCase();
  let color = "text-muted-foreground border-border/60 bg-muted/10";

  if (s === "critical") color = "text-red-500 border-red-500 bg-red-500/10";
  else if (s === "high") color = "text-orange-500 border-orange-500 bg-orange-500/10";
  else if (s === "medium") color = "text-yellow-500 border-yellow-500 bg-yellow-500/10";
  else if (s === "low") color = "text-blue-500 border-blue-500 bg-blue-500/10";

  return <span className={`px-2 py-0.5 text-[10px] uppercase font-mono border ${color} font-medium`}>{severity}</span>;
}

export default function OverviewPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [ports, setPorts] = useState<Array<{ port: number; count: number }>>([]);

  const [isSaturated, setIsSaturated] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [a, e, al, ps] = await Promise.all([
          getAgents(),
          getRecentEvents({ limit: MAX_FETCH_LIMIT }),
          getRecentAlerts(200),
          getPortStats(10)
        ]);

        if (!alive) return;

        setAgents(a);
        setEvents(e);
        setAlerts(al);
        setPorts(ps);

        setIsSaturated(e.length >= MAX_FETCH_LIMIT);
      } catch (err) {
        console.error("Telemetry link failed", err);
      }
    })();

    return () => {
      alive = false;
    };
  }, []);

  const kpis = useMemo(() => {
    const now = Date.now();
    const last5m = now - 5 * 60_000;

    let onlineAgents = 0;
    for (const a of agents) {
      if (new Date(a.last_seen_at).getTime() >= last5m) onlineAgents++;
    }

    let events5m = 0;
    for (const e of events) {
      if (new Date(e.timestamp).getTime() >= last5m) events5m++;
    }

    const last60m = now - 60 * 60_000;
    const alerts60m = alerts.filter((a) => new Date(a.created_at).getTime() >= last60m).length;

    const lastEvent = events[0]?.timestamp ? new Date(events[0].timestamp) : null;
    const lastEventAge = lastEvent ? minutesAgo(lastEvent) : null;

    return { onlineAgents, events5m, alerts60m, lastEventAge };
  }, [agents, events, alerts]);

  const eventsByMinute = useMemo(() => {
    if (events.length === 0) return { data: [], series: [] as string[] };

    const typeCounts = new Map<string, number>();
    const timeMap = new Map<number, Record<string, any>>();

    for (const ev of events) {
      typeCounts.set(ev.event_type, (typeCounts.get(ev.event_type) || 0) + 1);

      const d = bucketMinute(ev.timestamp);
      const key = d.getTime();

      if (!timeMap.has(key)) timeMap.set(key, { t: fmtHHMM(d) });
      const row = timeMap.get(key)!;
      row[ev.event_type] = (row[ev.event_type] || 0) + 1;
    }

    const topTypes = [...typeCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([k]) => k);

    const finalData: any[] = [];
    const sortedTimes = [...timeMap.keys()].sort((a, b) => a - b).slice(-60);

    for (const timeKey of sortedTimes) {
      const rawRow = timeMap.get(timeKey)!;
      const cleanRow: any = { t: rawRow.t };

      for (const typeKey in rawRow) {
        if (typeKey === "t") continue;
        if (topTypes.includes(typeKey)) cleanRow[typeKey] = rawRow[typeKey];
        else cleanRow["other"] = (cleanRow["other"] || 0) + rawRow[typeKey];
      }
      finalData.push(cleanRow);
    }

    return { data: finalData, series: [...topTypes, "other"] };
  }, [events]);

  const sshFailuresByMinute = useMemo(() => {
    const m = new Map<number, any>();
    for (const ev of events) {
      if (ev.event_type !== "ssh_auth") continue;
      const extra = ev.extra as any;
      if (!extra || extra.action === "accepted") continue;

      const d = bucketMinute(ev.timestamp);
      const key = d.getTime();
      const row = m.get(key) || { t: fmtHHMM(d), failures: 0 };
      row.failures += 1;
      m.set(key, row);
    }
    const data = [...m.entries()].sort((a, b) => a[0] - b[0]).slice(-60).map(([, v]) => v);
    return { data, series: ["failures"] };
  }, [events]);

  const alertsByMinute = useMemo(() => {
    const m = new Map<number, any>();
    for (const al of alerts) {
      const d = bucketMinute(al.created_at);
      const key = d.getTime();
      const sev = (al.severity || "unknown").toLowerCase();
      const row = m.get(key) || { t: fmtHHMM(d) };
      row[sev] = (row[sev] || 0) + 1;
      m.set(key, row);
    }
    const data = [...m.entries()].sort((a, b) => a[0] - b[0]).slice(-60).map(([, v]) => v);
    return { data, series: ["critical", "high", "medium", "low", "unknown"] };
  }, [alerts]);

  const topSources = useMemo(() => {
    const c = new Map<string, number>();
    for (const ev of events) {
      if (!ev.src_ip) continue;
      c.set(ev.src_ip, (c.get(ev.src_ip) || 0) + 1);
    }
    return [...c.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([src_ip, count]) => ({ src_ip, count }));
  }, [events]);

  const recentSSH = useMemo(() => {
    const limit = 20;
    const result: any[] = [];
    let count = 0;

    for (const e of events) {
      if (e.event_type === "ssh_auth") {
        result.push({
          ts: fmtHHMM(new Date(e.timestamp)),
          src: e.src_ip || "-",
          user: (e.extra as any)?.username || "-",
          action: (e.extra as any)?.action || "-",
          dst: e.dst_ip || "-"
        });
        count++;
        if (count >= limit) break;
      }
    }
    return result;
  }, [events]);

  return (
    <div className="min-h-screen pb-20 font-sans text-sm text-foreground">
      <div className="mb-8 border border-border/60 bg-card/30 backdrop-blur-md">
        <div className="flex flex-wrap items-center divide-x divide-border/60">
          <div className="flex-1 min-w-[150px]">
            <StatBlock label="ACTIVE AGENTS" value={kpis.onlineAgents} sub={`TOTAL: ${agents.length}`} active={kpis.onlineAgents > 0} />
          </div>
          <div className="flex-1 min-w-[150px]">
            <StatBlock
              label="EVENT FLOW (5m)"
              value={isSaturated ? `${kpis.events5m}+` : kpis.events5m}
              sub={isSaturated ? "FETCH LIMIT REACHED" : "DETECTED EVENTS"}
              warning={isSaturated}
            />
          </div>
          <div className="flex-1 min-w-[150px]">
            <StatBlock
              label="ALERTS (1h)"
              value={kpis.alerts60m}
              sub={kpis.lastEventAge !== null ? `LAST SIG: ${kpis.lastEventAge}m AGO` : "NO SIGNAL"}
            />
          </div>
        </div>
      </div>

      <div className="space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <CyberPanel
            title={isSaturated ? "NETWORK TRAFFIC (CAPPED)" : "NETWORK TRAFFIC"}
            className="lg:col-span-2 min-h-[300px]"
            isCritical={isSaturated}
            right={
              <Link to="/events" className="text-[10px] font-mono uppercase tracking-wider text-primary hover:underline">
                View all events
              </Link>
            }
          >
            {eventsByMinute.data.length === 0 ? (
              <EmptyState title="NO SIGNAL" hint="Waiting for telemetry..." />
            ) : (
              <div className="h-[280px] w-full">
                <SimpleTimeSeries data={eventsByMinute.data} seriesKeys={eventsByMinute.series} />
              </div>
            )}
          </CyberPanel>

          <div className="space-y-6 flex flex-col h-full">
            <CyberPanel title="AUTH FAILURES (SSH)" className="flex-1 min-h-[160px]">
              <div className="h-full min-h-[120px]">
                {sshFailuresByMinute.data.length === 0 ? (
                  <div className="flex items-center justify-center h-full text-[10px] text-muted-foreground font-mono tracking-widest">SYSTEM SECURE</div>
                ) : (
                  <SimpleTimeSeries data={sshFailuresByMinute.data} seriesKeys={sshFailuresByMinute.series} />
                )}
              </div>
            </CyberPanel>

            <CyberPanel title="ALERT SEVERITY" className="flex-1 min-h-[160px]">
              <div className="h-full min-h-[120px]">
                {alertsByMinute.data.length === 0 ? (
                  <div className="flex items-center justify-center h-full text-[10px] text-muted-foreground font-mono tracking-widest">NO ACTIVE THREATS</div>
                ) : (
                  <SimpleTimeSeries data={alertsByMinute.data} seriesKeys={alertsByMinute.series} />
                )}
              </div>
            </CyberPanel>
          </div>
        </div>

        <SectionDivider label="THREAT INTELLIGENCE & NETWORK" />

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <CyberPanel title="ALERT LOG" right={<Link to="/alerts" className="text-[10px] font-mono uppercase tracking-wider text-primary hover:underline">View all</Link>}>
            <Table
              className="text-xs"
              columns={[
                { key: "created_at", title: "TIME", className: "font-mono text-muted-foreground w-24", render: (r: Alert) => fmtHHMM(new Date(r.created_at)) },
                { key: "severity", title: "SEV", width: 80, render: (r: Alert) => <CyberBadge severity={r.severity} /> },
                { key: "description", title: "DETECTION", className: "font-mono text-foreground" },
                { key: "src_ip", title: "SRC", className: "font-mono text-muted-foreground w-28", render: (r: Alert) => r.src_ip || "-" }
              ]}
              rows={alerts.slice(0, 25)}
              rowKey={(r) => String(r.id)}
            />
          </CyberPanel>

          <CyberPanel title="SSH AUTH STREAM" right="LATEST 20">
            <Table
              className="text-xs"
              columns={[
                { key: "ts", title: "TIME", className: "font-mono w-20 text-muted-foreground" },
                { key: "user", title: "USER", className: "font-mono text-blue-400" },
                {
                  key: "action",
                  title: "STATUS",
                  className: "font-mono",
                  render: (r: any) =>
                    r.action === "failed" ? <span className="text-red-500 font-bold">FAIL</span> : <span className="text-green-500/80">{r.action}</span>
                },
                { key: "src", title: "SOURCE IP", className: "font-mono text-muted-foreground" }
              ]}
              rows={recentSSH}
              rowKey={(r, i) => `${r.ts}-${i}`}
            />
          </CyberPanel>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <CyberPanel title="TOP SOURCES (IP)" className="md:col-span-1">
            <Table
              className="text-xs"
              columns={[
                { key: "src_ip", title: "IP ADDRESS", className: "font-mono text-foreground" },
                { key: "count", title: "HITS", className: "text-right font-mono text-primary" }
              ]}
              rows={topSources}
              rowKey={(r) => r.src_ip}
            />
          </CyberPanel>

          <CyberPanel title="PORT STATISTICS" className="md:col-span-1">
            <div className="space-y-3 pt-2">
              {ports.map((p) => (
                <div key={p.port} className="flex items-center gap-3 text-xs">
                  <div className="w-12 text-muted-foreground font-mono text-right">:{p.port}</div>
                  <div className="flex-1 h-1.5 bg-muted/20 overflow-hidden">
                    <div
                      className="h-full bg-primary/70"
                      style={{ width: `${Math.min(100, (p.count / Math.max(1, ports[0]?.count || 1)) * 100)}%` }}
                    />
                  </div>
                  <div className="w-10 text-right font-mono text-foreground">{p.count}</div>
                </div>
              ))}
              {ports.length === 0 && <div className="text-[10px] text-muted-foreground font-mono text-center py-4 uppercase">NO PORT ACTIVITY</div>}
            </div>
          </CyberPanel>

          <CyberPanel
            title="RAW EVENT STREAM"
            className="md:col-span-1"
            right={
              <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                Showing last {VISUAL_TABLE_LIMIT}
              </span>
            }
          >
            <div className="overflow-hidden h-[300px] relative">
              <div className="absolute inset-0 overflow-y-auto space-y-1 font-mono text-[10px] scrollbar-hide">
                {events.slice(0, VISUAL_TABLE_LIMIT).map((e, i) => (
                  <div key={i} className="flex gap-2 border-b border-border/20 pb-1 mb-1 text-muted-foreground hover:bg-primary/5 hover:text-foreground transition-colors cursor-default">
                    <span className="opacity-50 w-10 shrink-0">{fmtHHMM(new Date(e.timestamp))}</span>
                    <span className="text-blue-400 w-14 shrink-0 truncate">{e.event_type}</span>
                    <span className="truncate flex-1">
                      {e.src_ip} → {e.dst_ip}:{e.dst_port}
                    </span>
                  </div>
                ))}
                {events.length > VISUAL_TABLE_LIMIT && (
                  <div className="text-center py-2 text-xs text-muted-foreground">
                    +{events.length - VISUAL_TABLE_LIMIT} more events available (use <Link to="/events" className="text-primary hover:underline">Events</Link>)
                  </div>
                )}
                {events.length === 0 && <div className="text-center pt-10 opacity-50">WAITING FOR PACKETS...</div>}
              </div>
            </div>
          </CyberPanel>
        </div>
      </div>
    </div>
  );
}
