import type { ReactNode } from "react";
import { useMemo } from "react";

import EmptyState from "@/shared/components/EmptyState";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { MetricCard } from "@/shared/components/MetricCard";
import { Panel } from "@/shared/components/Panel";
import { getFlowIpContext } from "@/shared/lib/ipClassification";

import { SimpleTimeSeries } from "@/features/overview/components/Charts";

import type { NetEvent } from "../../types";
import { extractDdosFields, ddosLabel, isDdosEvent } from "../../lib/ddos";

import DdosEventsTable from "./DdosEventsTable";

function targetNode(event: NetEvent): { raw: string; value: ReactNode } {
  const raw = `${event.dst_ip || "-"}:${event.dst_port ?? "-"}/${event.proto || "-"}`;
  return {
    raw,
    value: (
      <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
        <IpAddressPill ip={event.dst_ip} ipContext={getFlowIpContext(event.extra?.ip_context, "dst")} compact />
        <span className="text-muted-foreground">
          :{event.dst_port ?? "-"}/{event.proto || "-"}
        </span>
      </span>
    ),
  };
}

function buildMetricSeries(events: NetEvent[], keys: string[]) {
  const buckets = new Map<number, Record<string, any>>();
  for (const e of events) {
    const ts = new Date(e.timestamp).getTime();
    if (!Number.isFinite(ts)) continue;

    const b = Math.floor(ts / 60_000) * 60_000;
    const row = buckets.get(b) || { t: new Date(b).toISOString() };
    const fields = extractDdosFields(e.extra);

    for (const k of keys) {
      const v = (fields as any)[k] as number | null;
      if (typeof v !== "number" || !Number.isFinite(v)) continue;
      const prev = row[k];
      if (typeof prev !== "number" || v > prev) row[k] = v;
    }

    buckets.set(b, row);
  }

  const data = Array.from(buckets.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([, row]) => row);

  return { data, series: keys };
}

export default function DdosDeepDive({
  events,
  selectedId,
  onSelect,
}: {
  events: NetEvent[];
  selectedId: number | null;
  onSelect: (e: NetEvent) => void;
}) {
  const ddosEvents = useMemo(() => events.filter((e) => isDdosEvent(e)), [events]);

  const latest = useMemo(() => {
    const copy = [...ddosEvents];
    copy.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return copy[0] || null;
  }, [ddosEvents]);

  const topKinds = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of ddosEvents) {
      const k = ddosLabel(extractDdosFields(e.extra));
      m.set(k, (m.get(k) || 0) + 1);
    }
    return Array.from(m.entries())
      .map(([key, count]) => ({ key, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [ddosEvents]);

  const metrics1 = useMemo(() => buildMetricSeries(ddosEvents, ["pps", "bps"]), [ddosEvents]);
  const metrics2 = useMemo(() => buildMetricSeries(ddosEvents, ["unique_src_ips", "src_entropy_norm"]), [ddosEvents]);
  const metrics3 = useMemo(() => buildMetricSeries(ddosEvents, ["http_rps", "tls_handshake_rps"]), [ddosEvents]);
  const metrics4 = useMemo(() => buildMetricSeries(ddosEvents, ["tcp_syn_ratio", "confidence"]), [ddosEvents]);

  const recent = useMemo(() => {
    const copy = [...ddosEvents];
    copy.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return copy.slice(0, 120);
  }, [ddosEvents]);

  if (ddosEvents.length === 0) {
    return <EmptyState title="No DDoS detections" hint="This scope has no DDoS-classified telemetry in the current window." />;
  }

  const latestFields = latest ? extractDdosFields(latest.extra) : null;
  const latestTarget = latest ? targetNode(latest) : null;

  return (
    <div className="min-w-0 space-y-4">
      {latest && latestFields && (
        <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard size="sm" title="Latest kind" value={ddosLabel(latestFields)} />
          <MetricCard size="sm" title="Target" value={latestTarget?.value ?? "-"} helper={latestTarget?.raw} />
          <MetricCard size="sm" title="Unique src IPs" value={String(latestFields.unique_src_ips ?? "-")} />
          <MetricCard
            size="sm"
            title="Confidence"
            value={latestFields.confidence === null ? "-" : latestFields.confidence.toFixed(2)}
            tone={(latestFields.confidence ?? 0) >= 0.7 ? "danger" : "default"}
          />
        </div>
      )}

      <div className="grid min-w-0 grid-cols-1 gap-3 2xl:grid-cols-12">
        <div className="space-y-3 2xl:col-span-9 min-w-0">
          <div className="grid min-w-0 grid-cols-1 gap-3 lg:grid-cols-2">
            <Panel title="PPS / BPS">
              <div className="h-[260px] w-full min-w-0 overflow-hidden">
                <SimpleTimeSeries data={metrics1.data} seriesKeys={metrics1.series} height={240} allowHorizontalScroll={false} />
              </div>
            </Panel>

            <Panel title="Unique src / entropy">
              <div className="h-[260px] w-full min-w-0 overflow-hidden">
                <SimpleTimeSeries data={metrics2.data} seriesKeys={metrics2.series} height={240} allowHorizontalScroll={false} />
              </div>
            </Panel>

            <Panel title="HTTP RPS / TLS HS RPS">
              <div className="h-[260px] w-full min-w-0 overflow-hidden">
                <SimpleTimeSeries data={metrics3.data} seriesKeys={metrics3.series} height={240} allowHorizontalScroll={false} />
              </div>
            </Panel>

            <Panel title="SYN ratio / confidence">
              <div className="h-[260px] w-full min-w-0 overflow-hidden">
                <SimpleTimeSeries data={metrics4.data} seriesKeys={metrics4.series} height={240} allowHorizontalScroll={false} />
              </div>
            </Panel>
          </div>
        </div>

        <div className="min-w-0 2xl:col-span-3">
          <Panel
            title="Top kinds"
            actions={<span className="text-[10.5px] text-muted-foreground">{ddosEvents.length} events</span>}
          >
            {topKinds.length === 0 ? (
              <div className="text-[11px] text-muted-foreground">No classification keys found.</div>
            ) : (
              <div className="space-y-1.5">
                {topKinds.map((k) => (
                  <div
                    key={k.key}
                    className="flex min-w-0 items-center justify-between gap-3 rounded-md border border-border bg-surface-2/40 px-3 py-1.5 font-mono text-[11.5px]"
                  >
                    <div className="truncate text-foreground" title={k.key}>
                      {k.key}
                    </div>
                    <div className="text-muted-foreground">{k.count}</div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>

      <Panel title="Recent DDoS detections" padded={false}>
        <div className="h-[420px] overflow-hidden">
          <DdosEventsTable rows={recent} selectedId={selectedId} onSelect={onSelect} />
        </div>
      </Panel>
    </div>
  );
}
