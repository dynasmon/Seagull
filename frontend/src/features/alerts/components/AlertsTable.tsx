import { Badge } from "@/shared/components/Badge";
import { cx } from "@/shared/lib/cx";

import type { Alert } from "../types";

function fmtTs(ts: string) {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

function sevVariant(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
}

export default function AlertsTable(props: {
  rows: Alert[];
  selectedId: number | null;
  onSelect: (a: Alert) => void;
  density?: "comfortable" | "compact";
}) {
  const dense = props.density === "compact";
  return (
    <div className="w-full overflow-auto">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
          <tr className="border-b border-border/60 text-muted-foreground">
            <th className="text-left font-medium px-3 py-2 w-[180px]">Time</th>
            <th className="text-left font-medium px-3 py-2 w-[120px]">Severity</th>
            <th className="text-left font-medium px-3 py-2 w-[260px]">Rule</th>
            <th className="text-left font-medium px-3 py-2 w-[180px]">Source</th>
            <th className="text-left font-medium px-3 py-2 w-[220px]">Destination</th>
            <th className="text-left font-medium px-3 py-2">Description</th>
          </tr>
        </thead>

        <tbody>
          {props.rows.map((a) => {
            const selected = props.selectedId !== null && a.id === props.selectedId;
            return (
              <tr
                key={a.id}
                className={cx(
                  "border-b border-border/40 hover:bg-muted/30 cursor-pointer",
                  selected && "bg-muted/40"
                )}
                onClick={() => props.onSelect(a)}
              >
                <td className={cx("px-3 font-mono text-[12px] text-muted-foreground", dense ? "py-1.5" : "py-2")}>
                  {fmtTs(a.created_at)}
                </td>
                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <Badge variant={sevVariant(a.severity)}>{String(a.severity || "unknown")}</Badge>
                </td>
                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>{a.rule_id}</td>
                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>
                  {a.src_ip || <span className="text-muted-foreground">-</span>}
                </td>
                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>
                  {a.dst_ip ? <span>{a.dst_ip}</span> : <span className="text-muted-foreground">-</span>}
                  {typeof a.dst_port === "number" ? <span className="text-muted-foreground">:{a.dst_port}</span> : null}
                </td>
                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <div className="text-[12px] text-muted-foreground line-clamp-2">{a.description || ""}</div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
