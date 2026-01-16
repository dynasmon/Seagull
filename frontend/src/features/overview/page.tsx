import { useEffect, useMemo, useState } from "react";
import { Card } from "@/shared/components/Card";
import { Badge } from "@/shared/components/Badge";
import { Table } from "@/shared/components/Table";
import Loading from "@/shared/components/Loading";
import EmptyState from "@/shared/components/EmptyState";

import { getAgents, getPortStats, getRecentAlerts, getRecentEvents } from "./api";
import type { Agent, Alert, NetEvent } from "./types";
import { SimpleTimeSeries } from "./components/Charts";

function minutesAgo(d: Date) {
  return Math.floor((Date.now() - d.getTime()) / 60000);
}

function bucketMinute(iso: string) {
  const d = new Date(iso);
  d.setSeconds(0, 0);
  return d;
}

function fmtHHMM(d: Date) {
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

function severityVariant(sev: string) {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
}

export default function OverviewPage() {
  const [loading, setLoading] = useState(true);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [ports, setPorts] = useState<Array<{ port: number; count: number }>>([]);

  useEffect(() => {
    let alive = true;
    (async () => {
      setLoading(true);
      try {
        const [a, e, al, ps] = await Promise.all([
          getAgents(),
          getRecentEvents({ limit: 1000 }),
          getRecentAlerts(200),
          getPortStats(10)
        ]);
        if (!alive) return;
        setAgents(a);
        setEvents(e);
        setAlerts(al);
        setPorts(ps);
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const kpis = useMemo(() => {
    const now = Date.now();
    const last5m = now - 5 * 60_000;
    const last60m = now - 60 * 60_000;

    const onlineAgents = agents.filter((a) => new Date(a.last_seen_at).getTime() >= last5m).length;
    const events5m = events.filter((e) => new Date(e.timestamp).getTime() >= last5m).length;
    const events60m = events.filter((e) => new Date(e.timestamp).getTime() >= last60m).length;
    const alerts60m = alerts.filter((a) => new Date(a.created_at).getTime() >= last60m).length;

    const lastEvent = events[0]?.timestamp ? new Date(events[0].timestamp) : null;
    const lastEventAge = lastEvent ? minutesAgo(lastEvent) : null;

    return { onlineAgents, events5m, events60m, alerts60m, lastEventAge };
  }, [agents, events, alerts]);

  const eventsByMinute = useMemo(() => {
    // Top 3 event types in the fetched window
    const counts = new Map<string, number>();
    for (const ev of events) counts.set(ev.event_type, (counts.get(ev.event_type) || 0) + 1);
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k]) => k);

    const m = new Map<number, Record<string, any>>();
    for (const ev of events) {
      const d = bucketMinute(ev.timestamp);
      const key = d.getTime();
      const row = m.get(key) || { t: fmtHHMM(d) };
      const k = top.includes(ev.event_type) ? ev.event_type : "other";
      row[k] = (row[k] || 0) + 1;
      m.set(key, row);
    }

    const data = [...m.entries()]
      .sort((a, b) => a[0] - b[0])
      .slice(-60) // last ~60 points
      .map(([, v]) => v);

    const series = [...top, "other"];
    return { data, series };
  }, [events]);

  const sshFailuresByMinute = useMemo(() => {
    const m = new Map<number, any>();
    for (const ev of events) {
      if (ev.event_type !== "ssh_auth") continue;
      const action = String(ev.extra?.action || "").toLowerCase();
      if (!action || action === "accepted") continue;

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
    const series = ["critical", "high", "medium", "low", "unknown"];
    return { data, series };
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
    return events
      .filter((e) => e.event_type === "ssh_auth")
      .slice(0, 20)
      .map((e) => ({
        ts: new Date(e.timestamp).toLocaleString(),
        src: e.src_ip || "-",
        user: e.extra?.username || "-",
        action: e.extra?.action || "-",
        dst: e.dst_ip || "-"
      }));
  }, [events]);

  if (loading) return <Loading label="Loading dashboard..." />;

  return (
    <div className="space-y-4">
      {/* Row: Ingestion & Health (como no Grafana) */}
      <div className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
        Ingestion &amp; Health
      </div>

      <div className="grid grid-cols-24 gap-3">
        <Card className="col-span-6" title="Agents Online (last 5m)">
          <div className="text-3xl font-semibold">{kpis.onlineAgents}</div>
          <div className="text-sm text-[var(--muted)]">/ {agents.length} total</div>
        </Card>

        <Card className="col-span-6" title="Events (last 5m)">
          <div className="text-3xl font-semibold">{kpis.events5m}</div>
          <div className="text-sm text-[var(--muted)]">based on last 1000 events</div>
        </Card>

        <Card className="col-span-6" title="Events (last 60m)">
          <div className="text-3xl font-semibold">{kpis.events60m}</div>
          <div className="text-sm text-[var(--muted)]">based on last 1000 events</div>
        </Card>

        <Card className="col-span-6" title="Alerts (last 60m)">
          <div className="text-3xl font-semibold">{kpis.alerts60m}</div>
          <div className="text-sm text-[var(--muted)]">
            last event age: {kpis.lastEventAge === null ? "-" : `${kpis.lastEventAge}m`}
          </div>
        </Card>
      </div>

      {/* Row: Event Volume */}
      <div className="pt-2 text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
        Event Volume
      </div>

      <div className="grid grid-cols-24 gap-3">
        <Card className="col-span-24" title="Events per minute by type (approx)">
          {eventsByMinute.data.length === 0 ? (
            <EmptyState title="No data" hint="Generate traffic/telemetry and refresh." />
          ) : (
            <SimpleTimeSeries data={eventsByMinute.data} seriesKeys={eventsByMinute.series} />
          )}
        </Card>

        <Card className="col-span-12" title="SSH auth failures per minute (approx)">
          {sshFailuresByMinute.data.length === 0 ? (
            <EmptyState title="No SSH failures" hint="Try bruteforce against SSH and refresh." />
          ) : (
            <SimpleTimeSeries data={sshFailuresByMinute.data} seriesKeys={sshFailuresByMinute.series} />
          )}
        </Card>

        <Card className="col-span-12" title="Alerts per minute by severity (approx)">
          {alertsByMinute.data.length === 0 ? (
            <EmptyState title="No alerts" hint="Run rules (or wait rules-worker) and refresh." />
          ) : (
            <SimpleTimeSeries data={alertsByMinute.data} seriesKeys={alertsByMinute.series} />
          )}
        </Card>
      </div>

      {/* Row: SSH Auth Deep Dive */}
      <div className="pt-2 text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
        SSH Auth Deep Dive
      </div>

      <div className="grid grid-cols-24 gap-3">
        <Card className="col-span-24" title="Recent SSH Auth Events">
          <Table
            columns={[
              { key: "ts", title: "Time" },
              { key: "src", title: "src_ip" },
              { key: "user", title: "user" },
              { key: "action", title: "action" },
              { key: "dst", title: "dst_ip" }
            ]}
            rows={recentSSH}
            rowKey={(r, i) => `${r.ts}-${i}`}
          />
        </Card>
      </div>

      {/* Row: Top Talkers & Ports */}
      <div className="pt-2 text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
        Top Talkers &amp; Ports
      </div>

      <div className="grid grid-cols-24 gap-3">
        <Card className="col-span-12" title="Top source IPs (by events)">
          <Table
            columns={[
              { key: "src_ip", title: "src_ip" },
              { key: "count", title: "count", className: "text-right" }
            ]}
            rows={topSources}
            rowKey={(r) => r.src_ip}
          />
        </Card>

        <Card className="col-span-12" title="Top destination ports">
          <div className="space-y-2">
            {ports.map((p) => (
              <div key={p.port} className="flex items-center gap-3">
                <div className="w-16 text-sm text-[var(--muted)]">{p.port}</div>
                <div className="h-2 flex-1 rounded bg-[var(--panel2)]">
                  <div
                    className="h-2 rounded bg-[var(--text)]/40"
                    style={{
                      width: `${Math.min(100, (p.count / Math.max(1, ports[0]?.count || 1)) * 100)}%`
                    }}
                  />
                </div>
                <div className="w-14 text-right text-sm text-[var(--muted)]">{p.count}</div>
              </div>
            ))}
            {ports.length === 0 && <EmptyState title="No ports yet" hint="Generate flow events and refresh." />}
          </div>
        </Card>
      </div>

      {/* Row: Alerts */}
      <div className="pt-2 text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
        Alerts
      </div>

      <div className="grid grid-cols-24 gap-3">
        <Card className="col-span-24" title="Recent Alerts">
          <Table
            columns={[
              { key: "created_at", title: "Time", render: (r: Alert) => new Date(r.created_at).toLocaleString() },
              { key: "severity", title: "severity", render: (r: Alert) => <Badge variant={severityVariant(r.severity) as any}>{r.severity}</Badge> },
              { key: "rule_id", title: "rule_id" },
              { key: "src_ip", title: "src_ip", render: (r: Alert) => r.src_ip || "-" },
              { key: "dst_ip", title: "dst_ip", render: (r: Alert) => r.dst_ip || "-" },
              { key: "dst_port", title: "dst_port", render: (r: Alert) => (r.dst_port ?? "-") },
              { key: "description", title: "description" }
            ]}
            rows={alerts.slice(0, 25)}
            rowKey={(r) => String(r.id)}
          />
        </Card>
      </div>

      {/* Row: Raw Telemetry */}
      <div className="pt-2 text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
        Raw Telemetry
      </div>

      <div className="grid grid-cols-24 gap-3">
        <Card className="col-span-24" title="Recent Events">
          <Table
            columns={[
              { key: "timestamp", title: "Time", render: (r: NetEvent) => new Date(r.timestamp).toLocaleString() },
              { key: "agent_id", title: "agent" },
              { key: "event_type", title: "event_type" },
              { key: "src_ip", title: "src_ip", render: (r: NetEvent) => r.src_ip || "-" },
              { key: "dst_ip", title: "dst_ip", render: (r: NetEvent) => r.dst_ip || "-" },
              { key: "dst_port", title: "dst_port", render: (r: NetEvent) => (r.dst_port ?? "-") },
              { key: "proto", title: "proto", render: (r: NetEvent) => r.proto || "-" }
            ]}
            rows={events.slice(0, 25)}
            rowKey={(r) => String(r.id)}
          />
        </Card>
      </div>
    </div>
  );
}
