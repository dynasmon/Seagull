import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { cx } from "@/shared/lib/cx";
import { getFlowIpContext } from "@/shared/lib/ipClassification";

import type { NetEvent } from "../../types";
import { fmtDateTime } from "../../lib/aggregates";
import { extractDdosFields, ddosLabel, fmtHumanRate } from "../../lib/ddos";

function num(v: any): string {
  if (v === null || v === undefined) return "-";
  if (typeof v === "number" && Number.isFinite(v)) return `${Math.round(v)}`;
  return String(v);
}

export default function DdosEventsTable({
  rows,
  selectedId,
  onSelect
}: {
  rows: NetEvent[];
  selectedId: number | null;
  onSelect: (e: NetEvent) => void;
}) {
  return (
    <div className="border border-border/60 bg-background/40">
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-background/70 backdrop-blur">
          <tr className="border-b border-border/60 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
            <th className="px-3 py-2 text-left">time / kind</th>
            <th className="px-3 py-2 text-left">target</th>
            <th className="px-3 py-2 text-right">traffic</th>
            <th className="px-3 py-2 text-left">assessment</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((e, idx) => {
            const active = selectedId === e.id;
            const d = extractDdosFields(e.extra);
            return (
              <tr
                key={`${e.id ?? "na"}-${e.timestamp || "na"}-${e.agent_id || "na"}-${idx}`}
                onClick={() => onSelect(e)}
                className={cx(
                  "border-b border-border/50 cursor-pointer",
                  active ? "bg-primary/10" : "hover:bg-muted/10"
                )}
              >
                <td className="px-3 py-2">
                  <div className="font-mono text-muted-foreground">{fmtDateTime(new Date(e.timestamp))}</div>
                  <div className="font-mono text-foreground">{ddosLabel(d)}</div>
                </td>
                <td className="px-3 py-2 text-muted-foreground break-all">
                  <span className="inline-flex max-w-full flex-wrap items-center gap-0.5 font-mono">
                    <IpAddressPill ip={e.dst_ip} ipContext={getFlowIpContext(e.extra?.ip_context, "dst")} compact />
                    <span className="text-muted-foreground">:{e.dst_port ?? "-"}/{e.proto || "-"}</span>
                  </span>
                </td>
                <td className="px-3 py-2 font-mono text-right">
                  <div className="text-foreground">{d.pps === null ? "-" : fmtHumanRate(d.pps)} pps</div>
                  <div className="text-foreground">{d.bps === null ? "-" : fmtHumanRate(d.bps)} bps</div>
                  <div className="text-muted-foreground">{num(d.unique_src_ips)} src IPs</div>
                </td>
                <td className="px-3 py-2 font-mono">
                  <div className="text-foreground">{d.confidence === null ? "-" : d.confidence.toFixed(2)} conf</div>
                  <div className="text-muted-foreground">{d.severity || "-"}</div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
