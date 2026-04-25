import { useCallback, useMemo, useRef, useState } from "react";

import { getRecentEvents } from "@/features/events/api";
import type { NetEvent } from "@/features/events/types";
import { getOverview, getStormStatus } from "@/features/overview/api";
import type { OverviewSnapshot, StormStatus } from "@/features/overview/types";
import { Card } from "@/shared/components/Card";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { useLiveRefresh, usePortalRealtime } from "@/shared/realtime";
import { Table } from "@/shared/components/Table";
import { MetricCard } from "@/shared/components/MetricCard";
import InternalRefreshToolbar from "@/features/internal/components/InternalRefreshToolbar";

import { getBackendHealth, getMetricsSnapshot } from "../api";
import type { MetricsSnapshot } from "../types";

function fmtWhen(d?: Date | null) {
  if (!d) return "-";
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

function topCounts(values: string[], limit = 8) {
  const map = new Map<string, number>();
  for (const v of values) {
    const k = (v || "").trim();
    if (!k) continue;
    map.set(k, (map.get(k) || 0) + 1);
  }
  return Array.from(map.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, Math.max(1, limit))
    .map(([key, count]) => ({ key, count }));
}

export default function InternalDebugView() {
  const { connection, diagnostics } = usePortalRealtime();
  const [overview, setOverview] = useState<OverviewSnapshot | null>(null);
  const [storm, setStorm] = useState<StormStatus | null>(null);
  const [metrics, setMetrics] = useState<MetricsSnapshot | null>(null);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [backendUp, setBackendUp] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const inFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    try {
      const [h, o, s, m, ev] = await Promise.all([
        getBackendHealth(),
        getOverview({ window_minutes: 60 }),
        getStormStatus(),
        getMetricsSnapshot(),
        getRecentEvents({ limit: 400 })
      ]);
      setBackendUp((h?.status || "").toLowerCase() === "ok");
      setOverview(o);
      setStorm(s);
      setMetrics(m);
      setEvents(ev);
      setError(null);
    } catch (e: any) {
      setError(e?.message || "Failed to load debug dashboard");
    } finally {
      setBusy(false);
      inFlight.current = false;
    }
  }, []);
  const live = useLiveRefresh({
    profile: "admin",
    refresh,
  });

  const eventTypeRows = useMemo(() => topCounts(events.map((e) => e.event_type), 10), [events]);

  const reqCounterRows = useMemo(() => {
    const rows = (metrics?.counters || []).filter((c) => c.name === "http_requests_total");
    return rows
      .map((r) => ({
        method: r.labels.method || "-",
        path: r.labels.path || "-",
        status: r.labels.status || "-",
        value: Number(r.value || 0)
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 12);
  }, [metrics]);

  const latencyRows = useMemo(() => {
    const rows = (metrics?.histograms || []).filter((h) => h.name === "http_request_duration_ms");
    return rows
      .map((r) => ({
        method: r.labels.method || "-",
        path: r.labels.path || "-",
        status: r.labels.status || "-",
        count: Number(r.count || 0),
        avg: Number(r.avg || 0),
        max: Number(r.max || 0)
      }))
      .sort((a, b) => b.avg - a.avg)
      .slice(0, 12);
  }, [metrics]);

  if (busy && !overview && !storm && !metrics) {
    return <Loading label="Loading internal debug dashboards..." />;
  }

  return (
    <div className="space-y-6">
      <InternalRefreshToolbar lastUpdatedLabel={fmtWhen(live.state.lastUpdatedAt)} onRefresh={live.refreshNow} busy={busy} />

      {error ? <div className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">{error}</div> : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <MetricCard title="Backend" value={backendUp ? "UP" : "DOWN"} tone={backendUp ? "success" : "warning"} />
        <MetricCard
          title="Realtime"
          value={`${connection.status}${connection.transport ? `/${connection.transport}` : ""}`}
          tone={connection.status === "open" && !connection.isFallbackTransport ? "success" : "warning"}
        />
        <MetricCard title="Online agents" value={overview?.kpis.online_agents ?? "-"} tone="success" />
        <MetricCard title="Events / 5m" value={overview?.kpis.events_5m ?? "-"} />
        <MetricCard
          title="Alerts / 60m"
          value={overview?.kpis.alerts_60m ?? "-"}
          tone={(overview?.kpis.alerts_60m || 0) > 0 ? "warning" : "default"}
        />
        <MetricCard title="Storm phase" value={storm?.phase || "ok"} tone={storm?.active ? "warning" : "success"} />
        <MetricCard
          title="Backlog events"
          value={storm?.backlog_events ?? "-"}
          tone={(storm?.backlog_events || 0) > 0 ? "warning" : "default"}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card title="HTTP Request Counters" right={`Top ${reqCounterRows.length}`}>
          {reqCounterRows.length === 0 ? (
            <EmptyState title="No counters" hint="No HTTP counters emitted yet." />
          ) : (
            <Table
              rows={reqCounterRows}
              rowKey={(r, i) => `${r.method}:${r.path}:${r.status}:${i}`}
              columns={[
                { key: "method", title: "Method", className: "font-mono text-xs" },
                { key: "path", title: "Path", className: "font-mono text-xs" },
                { key: "status", title: "Status", className: "font-mono text-xs" },
                { key: "value", title: "Count", className: "text-right font-mono text-xs", render: (r) => Number(r.value).toLocaleString("en-US") }
              ]}
            />
          )}
        </Card>

        <Card title="HTTP Latency (avg ms)" right={`Top ${latencyRows.length}`}>
          {latencyRows.length === 0 ? (
            <EmptyState title="No latency data" hint="Histogram metrics are still empty." />
          ) : (
            <Table
              rows={latencyRows}
              rowKey={(r, i) => `${r.method}:${r.path}:${r.status}:${i}`}
              columns={[
                { key: "method", title: "Method", className: "font-mono text-xs" },
                { key: "path", title: "Path", className: "font-mono text-xs" },
                { key: "status", title: "Status", className: "font-mono text-xs" },
                { key: "count", title: "N", className: "text-right font-mono text-xs", render: (r) => Math.round(r.count) },
                { key: "avg", title: "Avg", className: "text-right font-mono text-xs", render: (r) => `${Math.round(r.avg)} ms` },
                { key: "max", title: "Max", className: "text-right font-mono text-xs", render: (r) => `${Math.round(r.max)} ms` }
              ]}
            />
          )}
        </Card>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card title="Realtime Diagnostics" right={connection.isFallbackTransport ? "degraded" : (connection.transport || connection.status)}>
          <div className="grid grid-cols-2 gap-3">
            <MetricCard title="Reconnects" value={diagnostics.reconnectCount} tone={diagnostics.reconnectCount > 0 ? "warning" : "default"} />
            <MetricCard title="Fallback polls" value={diagnostics.fallbackPollingActivations} tone={diagnostics.fallbackPollingActivations > 0 ? "warning" : "default"} />
            <MetricCard title="Fallback transport" value={diagnostics.fallbackTransportCount} tone={diagnostics.fallbackTransportCount > 0 ? "warning" : "default"} />
            <MetricCard title="Cursor gaps" value={diagnostics.cursorGapCount} tone={diagnostics.cursorGapCount > 0 ? "warning" : "success"} />
            <MetricCard title="Replay overflow" value={diagnostics.replayOverflowCount} tone={diagnostics.replayOverflowCount > 0 ? "warning" : "success"} />
            <MetricCard title="Malformed envelopes" value={diagnostics.malformedEnvelopeCount} tone={diagnostics.malformedEnvelopeCount > 0 ? "warning" : "success"} />
          </div>
          <div className="mt-3 text-xs text-muted-foreground">
            Last failure: {diagnostics.lastFailureKind || "-"} {diagnostics.lastFailureMessage ? `(${diagnostics.lastFailureMessage})` : ""}
          </div>
        </Card>

        <Card title="Event Type Distribution" right={`Sample ${events.length}`}>
          {eventTypeRows.length === 0 ? (
            <EmptyState title="No events" hint="No recent events returned." />
          ) : (
            <Table
              rows={eventTypeRows}
              rowKey={(r) => r.key}
              columns={[
                { key: "key", title: "Event type", className: "font-mono text-xs" },
                { key: "count", title: "Count", className: "text-right font-mono text-xs", render: (r) => r.count.toLocaleString("en-US") }
              ]}
            />
          )}
        </Card>

        <Card title="Ingest Pressure Detail" right={storm?.active ? "active" : "ok"}>
          {!storm ? (
            <EmptyState title="No ingest status" hint="Ingest status endpoint returned no payload." />
          ) : (
            <div className="grid grid-cols-2 gap-3">
              <MetricCard title="EPS" value={storm.eps} tone={storm.active ? "warning" : "default"} />
              <MetricCard title="Drop %" value={`${storm.drop_percent}%`} tone={storm.drop_percent > 0 ? "warning" : "success"} />
              <MetricCard title="Hot sample" value={`${storm.sample_hot_percent}%`} />
              <MetricCard title="Warm sample" value={`${storm.sample_warm_percent}%`} />
              <MetricCard
                title="Backlog msgs"
                value={storm.backlog_messages}
                tone={storm.backlog_messages > 0 ? "warning" : "default"}
              />
              <MetricCard title="Reason" value={storm.reason || "ok"} tone={storm.active ? "warning" : "success"} />
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
