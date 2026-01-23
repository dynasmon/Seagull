import type { ReactNode } from "react";
import { useMemo } from "react";

import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";

import { SimpleTimeSeries } from "@/features/overview/components/Charts";

import type { NetEvent } from "../../types";
import { extractDdosFields, ddosLabel } from "../../lib/ddos";

import DdosEventsTable from "./DdosEventsTable";

function MiniPanel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="border border-border/60 bg-background/40 backdrop-blur-sm flex flex-col">
      <div className="border-b border-border/60 bg-muted/10 px-3 py-2">
        <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">{title}</div>
      </div>
      <div className="p-3 flex-1 min-h-0 overflow-hidden">{children}</div>
    </div>
  );
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
  const ddosEvents = useMemo(() => events.filter((e) => e.event_type === "dos_attack"), [events]);

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
    return <EmptyState title="No DDoS detections" hint="This agent has no 'dos_attack' events in the current window." />;
  }

  const latestFields = latest ? extractDdosFields(latest.extra) : null;

  return (
    <div className="space-y-4">
      {latest && latestFields && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div className="border border-border/60 bg-background/40 px-3 py-2">
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Latest kind</div>
            <div className="mt-1 text-sm font-mono">{ddosLabel(latestFields)}</div>
          </div>
          <div className="border border-border/60 bg-background/40 px-3 py-2">
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Target</div>
            <div className="mt-1 text-sm font-mono">
              {(latest.dst_ip || "-") + ":" + (latest.dst_port ?? "-") + "/" + (latest.proto || "-")}
            </div>
          </div>
          <div className="border border-border/60 bg-background/40 px-3 py-2">
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Unique src IPs</div>
            <div className="mt-1 text-sm font-mono">{latestFields.unique_src_ips ?? "-"}</div>
          </div>
          <div className="border border-border/60 bg-background/40 px-3 py-2">
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Confidence</div>
            <div className={cx("mt-1 text-sm font-mono", (latestFields.confidence ?? 0) >= 0.7 ? "text-red-400" : "text-foreground")}>
              {latestFields.confidence === null ? "-" : latestFields.confidence.toFixed(2)}
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4">
          <MiniPanel title="PPS / BPS">
            <div className="h-[180px] w-full overflow-hidden">
              <SimpleTimeSeries data={metrics1.data} seriesKeys={metrics1.series} height={170} allowHorizontalScroll={false} />
            </div>
          </MiniPanel>

          <MiniPanel title="Unique src / Entropy">
            <div className="h-[180px] w-full overflow-hidden">
              <SimpleTimeSeries data={metrics2.data} seriesKeys={metrics2.series} height={170} allowHorizontalScroll={false} />
            </div>
          </MiniPanel>

          <MiniPanel title="HTTP RPS / TLS HS RPS">
            <div className="h-[180px] w-full overflow-hidden">
              <SimpleTimeSeries data={metrics3.data} seriesKeys={metrics3.series} height={170} allowHorizontalScroll={false} />
            </div>
          </MiniPanel>

          <MiniPanel title="SYN ratio / Confidence">
            <div className="h-[180px] w-full overflow-hidden">
              <SimpleTimeSeries data={metrics4.data} seriesKeys={metrics4.series} height={170} allowHorizontalScroll={false} />
            </div>
          </MiniPanel>
        </div>

        <MiniPanel title="Top kinds">
          {topKinds.length === 0 ? (
            <div className="text-[11px] text-muted-foreground">No classification keys found.</div>
          ) : (
            <div className="space-y-2">
              {topKinds.map((k) => (
                <div key={k.key} className="flex items-center justify-between gap-3 text-[11px] font-mono">
                  <div className="truncate text-foreground">{k.key}</div>
                  <div className="text-muted-foreground">{k.count}</div>
                </div>
              ))}
            </div>
          )}
        </MiniPanel>
      </div>

      <MiniPanel title="Recent DDoS detections">
        <div className="h-[320px] overflow-hidden">
          <DdosEventsTable rows={recent} selectedId={selectedId} onSelect={onSelect} />
        </div>
      </MiniPanel>
    </div>
  );
}
