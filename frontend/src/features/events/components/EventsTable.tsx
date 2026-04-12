import { useMemo } from "react";

import { Badge } from "@/shared/components/Badge";
import { Table, type Column, type TableSortState } from "@/shared/components/Table";
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

  push("rule", extra.rule_id);
  push("user", extra.user || extra.username);
  push("action", extra.action);
  push("reason", extra.reason);

  push("uniq_src", extra.unique_src_ips);
  push("pps", extra.pps);
  push("bps", extra.bps);
  push("syn_ratio", extra.tcp_syn_ratio);
  push("entropy", extra.src_entropy_norm);
  push("conf", extra.confidence);

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

function eventRowKey(e: NetEvent, idx: number): string {
  const idNum = Number((e as any).id);
  const idPart = Number.isFinite(idNum) && idNum > 0 ? `id:${idNum}` : "id:na";
  return `${idPart}-${e.timestamp || "na"}-${e.agent_id || "na"}-${e.event_type || "na"}-${idx}`;
}

export default function EventsTable({
  rows,
  selectedId,
  onSelect,
  onEdit,
  compact,
  showExtra,
  agentNameById,
  sort,
  onSortChange,
}: {
  rows: NetEvent[];
  selectedId: number | null;
  onSelect?: (ev: NetEvent) => void;
  onEdit?: (ev: NetEvent) => void;
  compact?: boolean;
  showExtra?: boolean;
  agentNameById?: Record<string, string>;
  sort?: TableSortState | null;
  onSortChange?: (next: TableSortState) => void;
}) {
  const columns = useMemo<Array<Column<NetEvent>>>(() => {
    const cols: Array<Column<NetEvent>> = [
      {
        key: "timestamp",
        sortKey: "timestamp",
        title: "Time",
        sortable: true,
        width: 180,
        className: "font-mono text-[12px] text-muted-foreground",
        render: (e) => fmtTs(e.timestamp),
      },
      {
        key: "agent_id",
        title: "Agent",
        sortKey: "agent_id",
        sortable: true,
        width: 240,
        render: (e) => <div className="font-mono text-[12px]">{agentLabel(e.agent_id, agentNameById)}</div>,
      },
      {
        key: "event_type",
        title: "Type",
        sortKey: "event_type",
        sortable: true,
        width: 180,
        render: (e) => (
          <div className="flex items-center gap-2">
            <Badge>{e.event_type}</Badge>
            {!compact && e.schema_version ? (
              <span className="text-[11px] text-muted-foreground font-mono opacity-80">v{e.schema_version}</span>
            ) : null}
          </div>
        ),
      },
      {
        key: "src",
        title: "Source",
        sortKey: "src_ip",
        sortable: true,
        width: 160,
        className: "font-mono text-[12px]",
        render: (e) => srcLabel(e),
      },
      {
        key: "dst",
        title: "Dest",
        sortKey: "dst_ip",
        sortable: true,
        width: 160,
        className: "font-mono text-[12px]",
        render: (e) => (
          <>
            {e.dst_ip ? <span>{e.dst_ip}</span> : <span className="text-muted-foreground">-</span>}
            {typeof e.dst_port === "number" ? <span className="text-muted-foreground">:{e.dst_port}</span> : null}
          </>
        ),
      },
    ];

    if (showExtra) {
      cols.push({
        key: "details",
        title: "Details",
        className: "text-[12px] text-muted-foreground",
        render: (e) => summarizeExtra(e) || <span className="opacity-60">-</span>,
      });
    }

    if (onEdit) {
      cols.push({
        key: "actions",
        title: "Actions",
        align: "right",
        width: 120,
        render: (e) => (
          <button
            type="button"
            onClick={(ev) => {
              ev.stopPropagation();
              onEdit?.(e);
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
        ),
      });
    }

    return cols;
  }, [agentNameById, compact, onEdit, showExtra]);

  const selectedRowKey = useMemo(() => {
    if (selectedId === null) return null;
    const idx = rows.findIndex((e) => Number((e as any).id) === selectedId);
    if (idx < 0) return null;
    return eventRowKey(rows[idx], idx);
  }, [rows, selectedId]);

  return (
    <Table
      columns={columns}
      rows={rows}
      rowKey={eventRowKey}
      compact={Boolean(compact)}
      stickyHeader
      selectedRowKey={selectedRowKey}
      onRowClick={(row) => onSelect?.(row)}
      sort={sort}
      onSortChange={onSortChange}
      className="text-sm"
    />
  );
}
