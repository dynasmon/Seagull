import { useCallback, useEffect, useRef, useState } from "react";

import { Card } from "@/shared/components/Card";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Table } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";

import { getSystemStatus } from "../api";
import type { SystemStatusResponse } from "../types";

const POLL_MS = 12000;

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
      ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-400"
      : band === "attention"
        ? "border-amber-500/50 bg-amber-500/10 text-amber-300"
        : "border-red-500/50 bg-red-500/10 text-red-400";
  return <span className={cx("rounded border px-2 py-0.5 text-[10px] font-mono", klass)}>{ms.toFixed(2)} ms</span>;
}

function StatusPill({ value }: { value: string }) {
  const v = (value || "").toLowerCase();
  const klass =
    v === "ok"
      ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-400"
      : v === "down"
        ? "border-red-500/50 bg-red-500/10 text-red-400"
        : v === "storm"
          ? "border-amber-500/50 bg-amber-500/10 text-amber-400"
          : "border-amber-500/40 bg-amber-500/10 text-amber-300";
  return <span className={cx("rounded border px-2 py-0.5 text-[10px] font-mono uppercase", klass)}>{value}</span>;
}

function StatTile({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-md border border-border/60 bg-background/60 px-4 py-3">
      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className="mt-2 text-2xl font-bold font-mono">{value}</div>
    </div>
  );
}

export default function InternalHealthView() {
  const [snapshot, setSnapshot] = useState<SystemStatusResponse | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);

  const inFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const data = await getSystemStatus();
      setSnapshot(data);
      setError(null);
      setLastUpdatedAt(new Date());
    } catch (e: any) {
      setError(e?.message || "Failed to load system status");
    } finally {
      setBusy(false);
      inFlight.current = false;
    }
  }, []);

  useEffect(() => {
    let alive = true;
    refresh();
    const t = window.setInterval(() => {
      if (!alive) return;
      refresh();
    }, POLL_MS);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [refresh]);

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
          component: "ingest_pressure",
          status: snapshot.components.ingest_pressure.status,
          detail: snapshot.components.ingest_pressure.storm.reason || "ok",
          latency_ms: snapshot.components.ingest_pressure.latency_ms ?? null
        }
      ]
    : [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">
          Last update: {lastUpdatedAt ? lastUpdatedAt.toLocaleString() : "-"}
        </div>
        <button
          type="button"
          onClick={refresh}
          className="border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest hover:bg-primary/5"
        >
          Refresh now
        </button>
      </div>

      {error ? <div className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</div> : null}

      {snapshot ? (
        <>
          <Card title="Service">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
              <StatTile label="Environment" value={snapshot.service.environment} />
              <StatTile label="Version" value={snapshot.service.version} />
              <StatTile label="Uptime" value={fmtSeconds(snapshot.service.uptime_seconds)} />
              <StatTile label="Counters" value={snapshot.observability.counters_total} />
              <StatTile label="Histograms" value={snapshot.observability.histograms_total} />
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
                <StatTile label="Total agents" value={snapshot.fleet.total_agents} />
                <StatTile label="Online" value={snapshot.fleet.online_agents} />
                <StatTile label="Offline" value={snapshot.fleet.offline_agents} />
                <StatTile label="Revoked" value={snapshot.fleet.revoked_agents} />
                <StatTile label="Inventory fresh" value={snapshot.fleet.inventory.fresh} />
                <StatTile label="Inventory stale" value={snapshot.fleet.inventory.stale} />
              </div>
            </Card>

            <Card title="Ingest Status">
              <div className="grid gap-4 grid-cols-2">
                <StatTile label="Phase" value={snapshot.components.ingest_pressure.storm.phase || "ok"} />
                <StatTile label="EPS" value={snapshot.components.ingest_pressure.storm.eps} />
                <StatTile label="Drop %" value={`${snapshot.components.ingest_pressure.storm.drop_percent}%`} />
                <StatTile label="Backlog events" value={snapshot.components.ingest_pressure.storm.backlog_events} />
                <StatTile label="Backlog msgs" value={snapshot.components.ingest_pressure.storm.backlog_messages} />
                <StatTile label="Open alert" value={snapshot.components.ingest_pressure.storm.open_alert_id ?? "-"} />
              </div>
            </Card>
          </div>
        </>
      ) : null}
    </div>
  );
}
