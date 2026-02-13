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

function summarizeExtra(e: NetEvent) {
  const extra = (e.extra || {}) as Record<string, any>;

  const tokens: string[] = [];

  const push = (k: string, v: any) => {
    if (v === undefined || v === null || v === "") return;
    const s = typeof v === "object" ? JSON.stringify(v) : String(v);
    tokens.push(`${k}=${s}`);
  };

  // Priority keys (keep concise but information-dense)
  push("rule", extra.rule_id);
  push("user", extra.user || extra.username);
  push("action", extra.action);
  push("reason", extra.reason);

  // DDoS-specific signals
  push("uniq_src", extra.unique_src_ips);
  push("pps", extra.pps);
  push("bps", extra.bps);
  push("syn_ratio", extra.tcp_syn_ratio);
  push("entropy", extra.src_entropy_norm);
  push("conf", extra.confidence);

  // Scan/SSH common fields
  push("port", extra.port || extra.dst_port);
  push("proto", extra.proto);

  return tokens.slice(0, 6).join(" · ");
}

function srcLabel(e: NetEvent) {
  if (e.src_ip) return e.src_ip;
  const extra = (e.extra || {}) as Record<string, any>;
  if (typeof extra.unique_src_ips === "number" && extra.unique_src_ips > 0) {
    return `many (${extra.unique_src_ips})`;
  }
  return "-";
}

function agentLabel(agent_id: string, agentNameById?: Record<string, string>) {
  const name = agentNameById?.[agent_id];
  if (!name || name === agent_id) return agent_id;
  return `${name} (${agent_id})`;
}

export default function EventsTable(props: {
  rows: NetEvent[];
  selectedId: number | null;
  onSelect?: (ev: NetEvent) => void;
  onEdit?: (ev: NetEvent) => void;
  compact?: boolean;
  showExtra?: boolean;
  agentNameById?: Record<string, string>;
}) {
  const dense = Boolean(props.compact);

  return (
    <div className="w-full overflow-auto">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
          <tr className="border-b border-border/60 text-muted-foreground">
            <th className="text-left font-medium px-3 py-2 w-[180px]">Time</th>
            <th className="text-left font-medium px-3 py-2 w-[220px]">Agent</th>
            <th className="text-left font-medium px-3 py-2 w-[180px]">Type</th>
            <th className="text-left font-medium px-3 py-2 w-[160px]">Source</th>
            <th className="text-left font-medium px-3 py-2 w-[160px]">Dest</th>
            {props.showExtra ? (
              <th className="text-left font-medium px-3 py-2">Details</th>
            ) : null}
            {props.onEdit ? <th className="text-right font-medium px-3 py-2 w-[120px]">Actions</th> : null}
          </tr>
        </thead>

        <tbody>
          {props.rows.map((e) => {
            const selected = props.selectedId !== null && e.id === props.selectedId;

            return (
              <tr
                key={e.id}
                className={cx(
                  "border-b border-border/40 hover:bg-muted/30",
                  selected && "bg-muted/40"
                )}
                onClick={() => props.onSelect?.(e)}
              >
                <td className={cx("px-3 font-mono text-[12px] text-muted-foreground", dense ? "py-1.5" : "py-2")}>
                  {fmtTs(e.timestamp)}
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <div className="font-mono text-[12px]">
                    {agentLabel(e.agent_id, props.agentNameById)}
                  </div>
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <div className="flex items-center gap-2">
                    <Badge>{e.event_type}</Badge>
                    {!props.compact && e.schema_version ? (
                      <span className="text-[11px] text-muted-foreground font-mono opacity-80">
                        v{e.schema_version}
                      </span>
                    ) : null}
                  </div>
                </td>

                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>
                  {srcLabel(e)}
                </td>

                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>
                  {e.dst_ip ? (
                    <span>{e.dst_ip}</span>
                  ) : (
                    <span className="text-muted-foreground">-</span>
                  )}
                  {typeof e.dst_port === "number" ? (
                    <span className="text-muted-foreground">:{e.dst_port}</span>
                  ) : null}
                </td>

                {props.showExtra ? (
                  <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                    <div className="text-[12px] text-muted-foreground">
                      {summarizeExtra(e) || <span className="opacity-60">-</span>}
                    </div>
                  </td>
                ) : null}

                {props.onEdit ? (
                  <td className={cx("px-3 text-right", dense ? "py-1.5" : "py-2")}>
                    <button
                      type="button"
                      onClick={(ev) => {
                        ev.stopPropagation();
                        props.onEdit?.(e);
                      }}
                      className={cx(
                        "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                        "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                        "hover:bg-muted/15 hover:text-foreground",
                        "focus:outline-none focus:ring-2 focus:ring-primary/30"
                      )}
                      title="Open drawer"
                    >
                      Inspect
                    </button>
                  </td>
                ) : null}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
