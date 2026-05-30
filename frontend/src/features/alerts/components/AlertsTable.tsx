import { useMemo } from "react";

import { Button } from "@/shared/components/Button";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { Table, type Column } from "@/shared/components/Table";

import type { Density } from "../constants";
import { fmtTs } from "../lib/alertFormatters";
import { alertIpContext } from "../lib/alertPresenters";
import { sevVariant } from "../lib/alertSeverity";
import type { Alert } from "../types";

interface AlertsTableProps {
  rows: Alert[];
  selectedId: number | null;
  onEdit: (a: Alert) => void;
  selectedRowIds: Set<number>;
  onToggleRow: (alertId: number, nextChecked: boolean) => void;
  onToggleAllRows: (nextChecked: boolean) => void;
  density?: Density;
}

export function AlertsTable({
  rows,
  selectedId,
  onEdit,
  selectedRowIds,
  onToggleRow,
  onToggleAllRows,
  density,
}: AlertsTableProps) {
  const columns = useMemo<Array<Column<Alert>>>(
    () => [
      {
        key: "alert",
        title: "Alert",
        render: (a) => (
          <div>
            <div className="flex flex-wrap items-center gap-1.5">
              <SeverityPill variant={sevVariant(String(a.severity || "unknown"))} withDot>
                {String(a.severity || "unknown")}
              </SeverityPill>
              <span className="break-all font-mono text-[12px] text-foreground">{a.rule_id}</span>
            </div>
            <div className="mt-1 font-mono text-[11px] text-muted-foreground">{fmtTs(a.created_at)}</div>
          </div>
        ),
      },
      {
        key: "network",
        title: "Network",
        className: "text-[12px]",
        render: (a) => (
          <div>
            <div>
              <IpAddressPill ip={a.src_ip} ipContext={alertIpContext(a, "src")} compact />
            </div>
            <div className="mt-1 text-muted-foreground">
              <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
                <IpAddressPill ip={a.dst_ip} ipContext={alertIpContext(a, "dst")} compact />
                {typeof a.dst_port === "number" ? <span>:{a.dst_port}</span> : null}
              </span>
            </div>
          </div>
        ),
      },
      {
        key: "description",
        title: "Description",
        render: (a) => (
          <div className="line-clamp-2 text-[12px] text-muted-foreground">{a.description || ""}</div>
        ),
      },
      {
        key: "actions",
        title: "Actions",
        align: "right",
        width: 96,
        render: (a) => (
          <Button
            variant="subtle"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              onEdit(a);
            }}
            title="Open drawer"
          >
            View
          </Button>
        ),
      },
    ],
    [onEdit],
  );

  const selectedRowKeys = useMemo(
    () => new Set(Array.from(selectedRowIds, (id) => String(id))),
    [selectedRowIds],
  );

  return (
    <Table
      className="!shadow-none !border-0 !bg-transparent !rounded-none text-sm"
      columns={columns}
      rows={rows}
      rowKey={(a) => String(a.id)}
      compact={density === "compact"}
      stickyHeader
      selectableRows
      selectedRowKey={selectedId != null ? String(selectedId) : null}
      selectedRowKeys={selectedRowKeys}
      onToggleRow={(row, checked) => onToggleRow(row.id, checked)}
      onToggleAllRows={onToggleAllRows}
      onRowClick={(a) => onEdit(a)}
    />
  );
}
