import { useMemo } from "react";

import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { Table, type Column, type TableSortState } from "@/shared/components/Table";

import { formatProtocolLabel, getEventProtocolIntel } from "../lib/protocol";
import type { NetEvent } from "../types";
import { DstEndpoint, SrcEndpoint } from "./SrcDstFlow";

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
  const protocol = getEventProtocolIntel(e);

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
  push("app", protocol.appProto);
  push("hint", protocol.hint);

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
  if (e.src_ip) return <SrcEndpoint event={e} />;
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
        width: 170,
        className: "font-mono text-[12px] text-muted-foreground",
        render: (e) => fmtTs(e.timestamp),
      },
      {
        key: "agent_id",
        title: "Agent",
        sortKey: "agent_id",
        sortable: true,
        width: 220,
        render: (e) => <div className="truncate font-mono text-[12px]">{agentLabel(e.agent_id, agentNameById)}</div>,
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
              <span className="font-mono text-[10.5px] text-muted-foreground/80">v{e.schema_version}</span>
            ) : null}
          </div>
        ),
      },
      {
        key: "protocol",
        title: "Protocol",
        width: 220,
        render: (e) => {
          const protocol = getEventProtocolIntel(e);
          const appLabel = formatProtocolLabel(protocol.appProto);
          const transportLabel = formatProtocolLabel(protocol.transportProto);
          const hasApp = appLabel !== "-";

          return (
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-1.5">
                {hasApp ? <Badge variant="info">{appLabel}</Badge> : null}
                {transportLabel !== "-" ? (
                  hasApp ? (
                    <span className="text-[10.5px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                      over {transportLabel}
                    </span>
                  ) : (
                    <Badge>{transportLabel}</Badge>
                  )
                ) : (
                  <span className="text-[11px] text-muted-foreground">-</span>
                )}
              </div>
              {protocol.hint ? (
                <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">{protocol.hint}</div>
              ) : null}
            </div>
          );
        },
      },
      {
        key: "src",
        title: "Source",
        sortKey: "src_ip",
        sortable: true,
        width: 170,
        className: "text-[12px]",
        render: (e) => srcLabel(e),
      },
      {
        key: "dst",
        title: "Dest",
        sortKey: "dst_ip",
        sortable: true,
        width: 170,
        className: "text-[12px]",
        render: (e) => <DstEndpoint event={e} />,
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
        width: 110,
        render: (e) => (
          <Button
            variant="subtle"
            size="sm"
            onClick={(ev) => {
              ev.stopPropagation();
              onEdit?.(e);
            }}
            title="Open drawer"
          >
            Inspect
          </Button>
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
