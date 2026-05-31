import { useMemo } from "react";

import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { Table, type Column } from "@/shared/components/Table";
import { getFlowIpContext } from "@/shared/lib/ipClassification";

import type { NetEvent } from "../../types";
import { fmtDateTime } from "../../lib/aggregates";
import { extractDdosFields, ddosLabel, fmtHumanRate } from "../../lib/ddos";

function num(v: any): string {
  if (v === null || v === undefined) return "-";
  if (typeof v === "number" && Number.isFinite(v)) return `${Math.round(v)}`;
  return String(v);
}

function ddosRowKey(e: NetEvent, idx: number): string {
  return `${e.id ?? "na"}-${e.timestamp || "na"}-${e.agent_id || "na"}-${idx}`;
}

export default function DdosEventsTable({
  rows,
  selectedId,
  onSelect,
}: {
  rows: NetEvent[];
  selectedId: number | null;
  onSelect: (e: NetEvent) => void;
}) {
  const columns = useMemo<Array<Column<NetEvent>>>(
    () => [
      {
        key: "time",
        title: "Time / kind",
        render: (e) => {
          const d = extractDdosFields(e.extra);
          return (
            <div className="flex min-w-0 items-center gap-1.5 font-mono">
              <span className="shrink-0 text-muted-foreground">{fmtDateTime(new Date(e.timestamp))}</span>
              <span className="min-w-0 truncate text-foreground" title={ddosLabel(d)}>{ddosLabel(d)}</span>
            </div>
          );
        },
      },
      {
        key: "target",
        title: "Target",
        render: (e) => (
          <span className="inline-flex min-w-0 max-w-full flex-nowrap items-center gap-0.5 font-mono">
            <IpAddressPill ip={e.dst_ip} ipContext={getFlowIpContext(e.extra?.ip_context, "dst")} compact />
            <span className="shrink-0 text-muted-foreground">
              :{e.dst_port ?? "-"}/{e.proto || "-"}
            </span>
          </span>
        ),
      },
      {
        key: "traffic",
        title: "Traffic",
        align: "right",
        render: (e) => {
          const d = extractDdosFields(e.extra);
          return (
            <div className="flex items-center justify-end gap-2 whitespace-nowrap font-mono">
              <span className="text-foreground">{d.pps === null ? "-" : fmtHumanRate(d.pps)} pps</span>
              <span className="text-foreground">{d.bps === null ? "-" : fmtHumanRate(d.bps)} bps</span>
              <span className="text-muted-foreground">{num(d.unique_src_ips)} src</span>
            </div>
          );
        },
      },
      {
        key: "assessment",
        title: "Assessment",
        render: (e) => {
          const d = extractDdosFields(e.extra);
          return (
            <div className="flex items-center gap-2 whitespace-nowrap font-mono">
              <span className="text-foreground">{d.confidence === null ? "-" : d.confidence.toFixed(2)} conf</span>
              <span className="text-muted-foreground">{d.severity || "-"}</span>
            </div>
          );
        },
      },
    ],
    [],
  );

  const selectedRowKey = useMemo(() => {
    if (selectedId === null) return null;
    const idx = rows.findIndex((e) => e.id === selectedId);
    if (idx < 0) return null;
    return ddosRowKey(rows[idx], idx);
  }, [rows, selectedId]);

  return (
    <div className="h-full overflow-y-auto">
      <Table
        className="!shadow-none !border-0 !bg-transparent !rounded-none text-xs"
        columns={columns}
        rows={rows}
        rowKey={ddosRowKey}
        stickyHeader
        selectedRowKey={selectedRowKey}
        onRowClick={(e) => onSelect(e)}
      />
    </div>
  );
}
