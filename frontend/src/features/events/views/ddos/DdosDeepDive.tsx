import type { ReactNode } from "react";
import { useMemo } from "react";

import EmptyState from "@/shared/components/EmptyState";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { cx } from "@/shared/lib/cx";
import { getFlowIpContext } from "@/shared/lib/ipClassification";

import { SimpleTimeSeries } from "@/features/overview/components/Charts";

import type { NetEvent } from "../../types";
import { extractDdosFields, ddosLabel, isDdosEvent } from "../../lib/ddos";

import DdosEventsTable from "./DdosEventsTable";

function MiniPanel({
  title,
  right,
  children
}: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border/60 bg-background/40 backdrop-blur-sm flex flex-col shadow-sm overflow-hidden min-w-0">
      <div className="border-b border-border/60 bg-muted/10 px-4 py-3 flex items-center justify-between gap-3">
        <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">{title}</div>
        {right ? <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{right}</div> : null}
      </div>
      <div className="p-4 flex-1 min-h-0 min-w-0 overflow-hidden">{children}</div>
    </div>
  );
}

function SummaryCard({
  label,
  value,
  titleValue,
  tone = "default"
}: {
  label: string;
  value: ReactNode;
  titleValue?: string;
  tone?: "default" | "warn";
}) {
  const raw = typeof value === "string" ? value : titleValue || "";
  const compact = raw.length > 26;
  const mid = raw.length > 16;
  const valueSize = compact ? "text-sm" : mid ? "text-lg" : "text-2xl";
  const valueClass = tone === "warn" ? "text-danger" : "text-foreground";

  return (
    <div className="rounded-lg border border-border/60 bg-background/40 px-5 py-5 shadow-sm min-w-0">
      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className={cx("mt-2 font-mono font-bold tracking-tight leading-none truncate", valueSize, valueClass)} title={raw || undefined}>
        {value}
      </div>
    </div>
  );
}

function targetNode(event: NetEvent) {
  const raw = `${event.dst_ip || "-"}:${event.dst_port ?? "-"}/${event.proto || "-"}`;
  return {
    raw,
    value: (
      <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
        <IpAddressPill ip={event.dst_ip} ipContext={getFlowIpContext(event.extra?.ip_context, "dst")} compact />
        <span className="text-muted-foreground">:{event.dst_port ?? "-"}/{event.proto || "-"}</span>
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
  onSelect
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
    <div className="space-y-6 min-w-0">
      {latest && latestFields && (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 min-w-0">
          <SummaryCard label="Latest kind" value={ddosLabel(latestFields)} />
          <SummaryCard label="Target" value={latestTarget?.value ?? "-"} titleValue={latestTarget?.raw} />
          <SummaryCard label="Unique src IPs" value={`${latestFields.unique_src_ips ?? "-"}`} />
          <SummaryCard
            label="Confidence"
            value={latestFields.confidence === null ? "-" : latestFields.confidence.toFixed(2)}
            tone={(latestFields.confidence ?? 0) >= 0.7 ? "warn" : "default"}
          />
        </div>
      )}

      <div className="grid grid-cols-1 2xl:grid-cols-12 gap-6 min-w-0">
        <div className="2xl:col-span-9 space-y-6 min-w-0">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-w-0">
            <MiniPanel title="PPS / BPS">
              <div className="h-[280px] w-full min-w-0 overflow-hidden">
                <SimpleTimeSeries data={metrics1.data} seriesKeys={metrics1.series} height={260} allowHorizontalScroll={false} />
              </div>
            </MiniPanel>

            <MiniPanel title="Unique src / Entropy">
              <div className="h-[280px] w-full min-w-0 overflow-hidden">
                <SimpleTimeSeries data={metrics2.data} seriesKeys={metrics2.series} height={260} allowHorizontalScroll={false} />
              </div>
            </MiniPanel>

            <MiniPanel title="HTTP RPS / TLS HS RPS">
              <div className="h-[280px] w-full min-w-0 overflow-hidden">
                <SimpleTimeSeries data={metrics3.data} seriesKeys={metrics3.series} height={260} allowHorizontalScroll={false} />
              </div>
            </MiniPanel>

            <MiniPanel title="SYN ratio / Confidence">
              <div className="h-[280px] w-full min-w-0 overflow-hidden">
                <SimpleTimeSeries data={metrics4.data} seriesKeys={metrics4.series} height={260} allowHorizontalScroll={false} />
              </div>
            </MiniPanel>
          </div>
        </div>

        <div className="2xl:col-span-3 min-w-0">
          <MiniPanel title="Top kinds" right={`${ddosEvents.length} events`}>
            {topKinds.length === 0 ? (
              <div className="text-[11px] text-muted-foreground">No classification keys found.</div>
            ) : (
              <div className="space-y-2">
                {topKinds.map((k) => (
                  <div key={k.key} className="flex items-center justify-between gap-3 text-[11px] font-mono min-w-0">
                    <div className="truncate text-foreground" title={k.key}>
                      {k.key}
                    </div>
                    <div className="text-muted-foreground">{k.count}</div>
                  </div>
                ))}
              </div>
            )}
          </MiniPanel>
        </div>
      </div>

      <MiniPanel title="Recent DDoS detections">
        <div className="h-[420px] overflow-hidden">
          <DdosEventsTable rows={recent} selectedId={selectedId} onSelect={onSelect} />
        </div>
      </MiniPanel>
    </div>
  );
}
