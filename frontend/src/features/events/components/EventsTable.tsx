import { Badge } from "@/shared/components/Badge";
import { cx } from "@/shared/lib/cx";
import type { NetEvent } from "../types";

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

function badgeVariantForType(eventType: string) {
  const t = (eventType || "").toLowerCase();
  if (t.includes("ddos")) return "critical" as const;
  if (t.includes("scan")) return "high" as const;
  if (t.includes("ssh") && t.includes("fail")) return "medium" as const;
  if (t.includes("flow") || t.includes("conn")) return "neutral" as const;
  return "info" as const;
}

function shortExtra(e: NetEvent): string {
  const x: any = e.extra || {};
  const keys = ["attack", "vector", "reason", "action", "user", "rule_id", "confidence"];
  for (const k of keys) {
    const v = x[k];
    if (typeof v === "string" && v.trim()) return `${k}:${v}`;
    if (typeof v === "number") return `${k}:${v}`;
  }
  return "";
}

export default function EventsTable({
  rows,
  selectedId,
  compact,
  showExtra,
  onSelect
}: {
  rows: NetEvent[];
  selectedId: number | null;
  compact: boolean;
  showExtra: boolean;
  onSelect: (e: NetEvent) => void;
}) {
  return (
    <div className="border border-border/60 bg-background/30 overflow-auto h-full">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-muted/10 text-left text-[10px] text-muted-foreground font-mono uppercase tracking-widest">
          <tr>
            <th className="px-3 py-2 font-bold whitespace-nowrap">Time</th>
            <th className="px-3 py-2 font-bold whitespace-nowrap">Agent</th>
            <th className="px-3 py-2 font-bold whitespace-nowrap">Type</th>
            <th className="px-3 py-2 font-bold whitespace-nowrap">Src</th>
            <th className="px-3 py-2 font-bold whitespace-nowrap">Dst</th>
            <th className="px-3 py-2 font-bold whitespace-nowrap">Proto</th>
            <th className="px-3 py-2 font-bold whitespace-nowrap">Bytes</th>
            {showExtra && <th className="px-3 py-2 font-bold whitespace-nowrap">Extra</th>}
          </tr>
        </thead>

        <tbody>
          {rows.map((e) => {
            const isSelected = selectedId === e.id;
            const src = e.src_ip ? `${e.src_ip}${e.src_port ? `:${e.src_port}` : ""}` : "-";
            const dst = e.dst_ip ? `${e.dst_ip}${e.dst_port ? `:${e.dst_port}` : ""}` : "-";
            const extra = shortExtra(e);

            return (
              <tr
                key={String(e.id)}
                className={cx(
                  "border-t border-border/40 cursor-pointer",
                  "hover:bg-primary/5",
                  isSelected && "bg-primary/10"
                )}
                onClick={() => onSelect(e)}
              >
                <td
                  className={cx(
                    "px-3",
                    compact ? "py-1.5" : "py-2",
                    "whitespace-nowrap font-mono text-[11px]"
                  )}
                >
                  {fmtTs(e.timestamp)}
                </td>
                <td
                  className={cx(
                    "px-3",
                    compact ? "py-1.5" : "py-2",
                    "whitespace-nowrap font-mono text-[11px]"
                  )}
                >
                  {e.agent_id}
                </td>
                <td className={cx("px-3", compact ? "py-1.5" : "py-2", "whitespace-nowrap")}>
                  <Badge variant={badgeVariantForType(e.event_type)}>{e.event_type}</Badge>
                </td>
                <td
                  className={cx(
                    "px-3",
                    compact ? "py-1.5" : "py-2",
                    "whitespace-nowrap font-mono text-[11px]"
                  )}
                >
                  {src}
                </td>
                <td
                  className={cx(
                    "px-3",
                    compact ? "py-1.5" : "py-2",
                    "whitespace-nowrap font-mono text-[11px]"
                  )}
                >
                  {dst}
                </td>
                <td
                  className={cx(
                    "px-3",
                    compact ? "py-1.5" : "py-2",
                    "whitespace-nowrap font-mono text-[11px]"
                  )}
                >
                  {e.proto || "-"}
                </td>
                <td
                  className={cx(
                    "px-3",
                    compact ? "py-1.5" : "py-2",
                    "whitespace-nowrap font-mono text-[11px]"
                  )}
                >
                  {typeof e.bytes === "number" ? e.bytes.toLocaleString() : "-"}
                </td>
                {showExtra && (
                  <td
                    className={cx(
                      "px-3",
                      compact ? "py-1.5" : "py-2",
                      "whitespace-nowrap font-mono text-[11px] text-muted-foreground"
                    )}
                  >
                    {extra || "-"}
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
