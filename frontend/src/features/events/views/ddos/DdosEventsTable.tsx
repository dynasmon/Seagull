import { cx } from "@/shared/lib/cx";

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
    <div className="overflow-auto border border-border/60 bg-background/40">
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-background/70 backdrop-blur">
          <tr className="border-b border-border/60 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
            <th className="px-3 py-2 text-left whitespace-nowrap">time</th>
            <th className="px-3 py-2 text-left whitespace-nowrap">kind</th>
            <th className="px-3 py-2 text-left whitespace-nowrap">target</th>
            <th className="px-3 py-2 text-right whitespace-nowrap">pps</th>
            <th className="px-3 py-2 text-right whitespace-nowrap">bps</th>
            <th className="px-3 py-2 text-right whitespace-nowrap">src ips</th>
            <th className="px-3 py-2 text-right whitespace-nowrap">conf</th>
            <th className="px-3 py-2 text-left whitespace-nowrap">sev</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((e, idx) => {
            const active = selectedId === e.id;
            const d = extractDdosFields(e.extra);
            const target = `${e.dst_ip || "-"}:${e.dst_port ?? "-"}/${e.proto || "-"}`;
            return (
              <tr
                key={`${e.id ?? "na"}-${e.timestamp || "na"}-${e.agent_id || "na"}-${idx}`}
                onClick={() => onSelect(e)}
                className={cx(
                  "border-b border-border/50 cursor-pointer",
                  active ? "bg-primary/10" : "hover:bg-muted/10"
                )}
              >
                <td className="px-3 py-2 font-mono text-muted-foreground whitespace-nowrap">{fmtDateTime(new Date(e.timestamp))}</td>
                <td className="px-3 py-2 font-mono text-foreground whitespace-nowrap">{ddosLabel(d)}</td>
                <td className="px-3 py-2 font-mono text-muted-foreground whitespace-nowrap">{target}</td>
                <td className="px-3 py-2 font-mono text-right text-foreground whitespace-nowrap">{d.pps === null ? "-" : fmtHumanRate(d.pps)}</td>
                <td className="px-3 py-2 font-mono text-right text-foreground whitespace-nowrap">{d.bps === null ? "-" : fmtHumanRate(d.bps)}</td>
                <td className="px-3 py-2 font-mono text-right text-foreground whitespace-nowrap">{num(d.unique_src_ips)}</td>
                <td className="px-3 py-2 font-mono text-right text-foreground whitespace-nowrap">{d.confidence === null ? "-" : d.confidence.toFixed(2)}</td>
                <td className="px-3 py-2 font-mono text-muted-foreground whitespace-nowrap">{d.severity || "-"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
