import { useCallback, useRef, useState } from "react";

import { Card } from "@/shared/components/Card";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Table } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";
import { useLiveRefresh } from "@/shared/realtime";
import InternalRefreshToolbar from "@/features/internal/components/InternalRefreshToolbar";
import InternalStatTile from "@/features/internal/components/InternalStatTile";

import { getSystemStatus } from "../api";
import type { SystemStatusResponse } from "../types";

type LatencyBand = "normal" | "attention" | "abnormal";

function fmtSeconds(s: number) {
  if (!Number.isFinite(s) || s <= 0) return "0s";
  if (s < 60) return `${Math.round(s)}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${Math.floor(s % 60)}s`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return `${h}h ${rm}m`;
}

function classifyLatency(ms?: number | null): LatencyBand | null {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return null;
  if (ms <= 80) return "normal";
  if (ms <= 150) return "attention";
  return "abnormal";
}

function LatencyPill({ ms }: { ms?: number | null }) {
  if (typeof ms !== "number" || !Number.isFinite(ms)) {
    return <span className="text-[10px] font-mono text-muted-foreground">-</span>;
  }
  const band = classifyLatency(ms);
  const klass =
    band === "normal"
      ? "border-success/50 bg-success/10 text-success"
      : band === "attention"
        ? "border-warning/50 bg-warning/10 text-warning"
        : "border-danger/50 bg-danger/10 text-danger";
  return <span className={cx("rounded border px-2 py-0.5 text-[10px] font-mono", klass)}>{ms.toFixed(2)} ms</span>;
}

function StatusPill({ value }: { value: string }) {
  const v = (value || "").toLowerCase();
  const klass =
    v === "ok"
      ? "border-success/50 bg-success/10 text-success"
      : v === "down"
        ? "border-danger/50 bg-danger/10 text-danger"
        : v === "storm"
          ? "border-warning/50 bg-warning/10 text-warning"
          : "border-warning/40 bg-warning/10 text-warning";
  return <span className={cx("rounded border px-2 py-0.5 text-[10px] font-mono uppercase", klass)}>{value}</span>;
}

export default function InternalHealthView() {
  const [snapshot, setSnapshot] = useState<SystemStatusResponse | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const inFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    try {
      const data = await getSystemStatus();
      setSnapshot(data);
      setError(null);
    } catch (e: any) {
      setError(e?.message || "Failed to load system status");
    } finally {
      setBusy(false);
      inFlight.current = false;
    }
  }, []);
  const live = useLiveRefresh({
    profile: "admin",
    refresh,
  });

  if (busy && !snapshot) {
    return <Loading label="Loading health/status..." />;
  }

  if (!snapshot && error) {
    return <EmptyState title="Health unavailable" hint={error} />;
  }

  const rows = snapshot
    ? [
        {
          component: "api",
          status: snapshot.components.api.status,
          detail: snapshot.components.api.error || "Core API process",
          latency_ms: snapshot.components.api.latency_ms ?? null
        },
        {
          component: "database",
          status: snapshot.components.database.status,
          detail: snapshot.components.database.error || "PostgreSQL",
          latency_ms: snapshot.components.database.latency_ms ?? null
        },
        {
          component: "redis",
          status: snapshot.components.redis.status,
          detail: snapshot.components.redis.error || "Redis",
          latency_ms: snapshot.components.redis.latency_ms ?? null
        },
        {
          component: "elasticsearch",
          status: snapshot.components.elasticsearch.status,
          detail: snapshot.components.elasticsearch.error || `${snapshot.components.elasticsearch.mode} mode`,
          latency_ms: snapshot.components.elasticsearch.latency_ms ?? null
        },
        {
          component: "clickhouse",
          status: snapshot.components.clickhouse.status,
          detail: snapshot.components.clickhouse.error || (snapshot.components.clickhouse.enabled ? "analytics enabled" : "analytics disabled"),
          latency_ms: snapshot.components.clickhouse.latency_ms ?? null
        },
        {
          component: "ingest_pressure",
          status: snapshot.components.ingest_pressure.status,
          detail: snapshot.components.ingest_pressure.storm.reason || "ok",
          latency_ms: snapshot.components.ingest_pressure.latency_ms ?? null
        }
      ]
    : [];

  return (
    <div className="space-y-6">
      <InternalRefreshToolbar
        lastUpdatedLabel={live.state.lastUpdatedAt ? live.state.lastUpdatedAt.toLocaleString() : "-"}
        onRefresh={live.refreshNow}
        busy={busy}
      />

      {error ? <div className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">{error}</div> : null}

      {snapshot ? (
        <>
          <Card title="Service">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
              <InternalStatTile label="Environment" value={snapshot.service.environment} />
              <InternalStatTile label="Version" value={snapshot.service.version} />
              <InternalStatTile label="Uptime" value={fmtSeconds(snapshot.service.uptime_seconds)} />
              <InternalStatTile label="Counters" value={snapshot.observability.counters_total} />
              <InternalStatTile label="Histograms" value={snapshot.observability.histograms_total} />
            </div>
          </Card>

          <Card title="Component Status">
            <Table
              rows={rows}
              rowKey={(r) => r.component}
              columns={[
                { key: "component", title: "Component", className: "font-mono text-xs" },
                { key: "status", title: "Status", className: "font-mono text-xs", render: (r) => <StatusPill value={r.status} /> },
                {
                  key: "latency_ms",
                  title: "Latency",
                  className: "font-mono text-xs",
                  render: (r) => <LatencyPill ms={r.latency_ms} />
                },
                { key: "detail", title: "Detail", className: "font-mono text-xs" }
              ]}
            />
          </Card>

          <div className="grid gap-6 xl:grid-cols-2">
            <Card title="Fleet Health">
              <div className="grid gap-4 grid-cols-2">
                <InternalStatTile label="Total agents" value={snapshot.fleet.total_agents} />
                <InternalStatTile label="Online" value={snapshot.fleet.online_agents} />
                <InternalStatTile label="Offline" value={snapshot.fleet.offline_agents} />
                <InternalStatTile label="Revoked" value={snapshot.fleet.revoked_agents} />
                <InternalStatTile label="Inventory fresh" value={snapshot.fleet.inventory.fresh} />
                <InternalStatTile label="Inventory stale" value={snapshot.fleet.inventory.stale} />
              </div>
            </Card>

            <Card title="Ingest Status">
              <div className="grid gap-4 grid-cols-2">
                <InternalStatTile label="Phase" value={snapshot.components.ingest_pressure.storm.phase || "ok"} />
                <InternalStatTile label="EPS" value={snapshot.components.ingest_pressure.storm.eps} />
                <InternalStatTile label="Drop %" value={`${snapshot.components.ingest_pressure.storm.drop_percent}%`} />
                <InternalStatTile label="Backlog events" value={snapshot.components.ingest_pressure.storm.backlog_events} />
                <InternalStatTile label="Backlog msgs" value={snapshot.components.ingest_pressure.storm.backlog_messages} />
                <InternalStatTile label="Open alert" value={snapshot.components.ingest_pressure.storm.open_alert_id ?? "-"} />
              </div>
            </Card>
          </div>
        </>
      ) : null}
    </div>
  );
}
