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
            <div>
              <div className="font-mono text-muted-foreground">{fmtDateTime(new Date(e.timestamp))}</div>
              <div className="font-mono text-foreground">{ddosLabel(d)}</div>
            </div>
          );
        },
      },
      {
        key: "target",
        title: "Target",
        className: "break-all",
        render: (e) => (
          <span className="inline-flex max-w-full flex-wrap items-center gap-0.5 font-mono">
            <IpAddressPill ip={e.dst_ip} ipContext={getFlowIpContext(e.extra?.ip_context, "dst")} compact />
            <span className="text-muted-foreground">
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
            <div className="font-mono">
              <div className="text-foreground">{d.pps === null ? "-" : fmtHumanRate(d.pps)} pps</div>
              <div className="text-foreground">{d.bps === null ? "-" : fmtHumanRate(d.bps)} bps</div>
              <div className="text-muted-foreground">{num(d.unique_src_ips)} src IPs</div>
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
            <div className="font-mono">
              <div className="text-foreground">{d.confidence === null ? "-" : d.confidence.toFixed(2)} conf</div>
              <div className="text-muted-foreground">{d.severity || "-"}</div>
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
