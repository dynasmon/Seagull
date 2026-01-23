import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";

import type { NetEvent } from "../types";
import { fmtDateTime } from "../lib/aggregates";
import { extractDdosFields, ddosLabel, fmtHumanRate } from "../lib/ddos";
import { normalizeDetails, safeNumber } from "../lib/normalize";

function Kv({ k, v }: { k: string; v: any }) {
  const val = v === undefined || v === null || v === "" ? "-" : String(v);
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{k}</div>
      <div className="text-[11px] font-mono text-foreground text-right">{val}</div>
    </div>
  );
}

export default function EventDetailsPanel({ event }: { event: NetEvent | null }) {
  if (!event) {
    return <EmptyState title="Select an event" hint="Click an event row to inspect fields and metadata." />;
  }

  const extra = normalizeDetails(event.extra);
  const src = event.src_ip ? `${event.src_ip}${event.src_port ? `:${event.src_port}` : ""}` : "-";
  const dst = event.dst_ip ? `${event.dst_ip}${event.dst_port ? `:${event.dst_port}` : ""}` : "-";

  const isDdos = event.event_type === "dos_attack";
  const ddos = isDdos ? extractDdosFields(extra) : null;

  return (
    <div className="space-y-4">
      <div className="grid gap-3">
        <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Summary</div>
        <div className="border border-border/60 bg-background/40 p-3">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-xs font-mono uppercase tracking-widest text-muted-foreground">{event.event_type}</div>
              <div className="mt-1 text-sm">
                <span className="font-mono">{src}</span> → <span className="font-mono">{dst}</span>
                {event.proto ? <span className="text-muted-foreground"> ({event.proto})</span> : null}
              </div>
              <div className="mt-2 text-[11px] text-muted-foreground font-mono">
                ts={fmtDateTime(new Date(event.timestamp))} · agent={event.agent_id} · schema={event.schema_version} · id={event.id}
              </div>
            </div>

            {isDdos && ddos && (
              <div className="shrink-0 text-right">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Detection</div>
                <div className="mt-1 text-sm font-mono">{ddosLabel(ddos)}</div>
                <div
                  className={cx(
                    "mt-1 inline-flex items-center gap-2 rounded-md border px-2 py-1 text-[10px] font-mono uppercase tracking-widest",
                    ddos.severity.toLowerCase() === "critical"
                      ? "border-red-500/60 bg-red-500/10 text-red-400"
                      : ddos.severity.toLowerCase() === "high"
                        ? "border-orange-500/60 bg-orange-500/10 text-orange-300"
                        : "border-border/60 bg-background/30 text-muted-foreground"
                  )}
                >
                  sev {ddos.severity || "-"}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {isDdos && ddos && (
        <div className="space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">DDoS fields</div>
          <div className="border border-border/60 bg-background/40 p-3 space-y-2">
            <Kv k="confidence" v={ddos.confidence === null ? "-" : ddos.confidence.toFixed(2)} />
            <Kv k="pps" v={ddos.pps === null ? "-" : fmtHumanRate(ddos.pps)} />
            <Kv k="bps" v={ddos.bps === null ? "-" : fmtHumanRate(ddos.bps)} />
            <Kv k="unique_src_ips" v={ddos.unique_src_ips === null ? "-" : Math.round(ddos.unique_src_ips)} />
            <Kv k="src_entropy_norm" v={ddos.src_entropy_norm === null ? "-" : ddos.src_entropy_norm.toFixed(3)} />
            <Kv k="http_rps" v={ddos.http_rps === null ? "-" : fmtHumanRate(ddos.http_rps)} />
            <Kv k="tls_handshake_rps" v={ddos.tls_handshake_rps === null ? "-" : fmtHumanRate(ddos.tls_handshake_rps)} />
            <Kv k="tcp_syn_ratio" v={ddos.tcp_syn_ratio === null ? "-" : ddos.tcp_syn_ratio.toFixed(3)} />
          </div>
        </div>
      )}

      {isDdos && ddos && ddos.top_src.length > 0 && (
        <div className="space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Top sources</div>
          <div className="border border-border/60 bg-background/40 p-3 space-y-2">
            {ddos.top_src.slice(0, 10).map((x, i) => (
              <div key={`${x.ip || "-"}-${i}`} className="flex items-center justify-between gap-3 text-[11px] font-mono">
                <div className="text-foreground truncate">{x.ip || "-"}</div>
                <div className="text-muted-foreground">{safeNumber(x.count) ?? "-"}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground mb-2">Extra (raw)</div>
        <pre className="border border-border/60 bg-background/40 p-3 text-[11px] leading-relaxed overflow-auto">
          {JSON.stringify(extra, null, 2)}
        </pre>
      </div>
    </div>
  );
}
