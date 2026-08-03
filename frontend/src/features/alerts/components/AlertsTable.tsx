import { useMemo } from "react";

import AgentTag from "@/features/agents/components/AgentTag";
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
          <div className="flex min-w-0 items-center gap-2">
            <SeverityPill variant={sevVariant(String(a.severity || "unknown"))} withDot>
              {String(a.severity || "unknown")}
            </SeverityPill>
            <span className="min-w-0 truncate font-mono text-[12px] text-foreground" title={a.rule_id}>
              {a.rule_id}
            </span>
            <span className="shrink-0 font-mono text-[11px] text-muted-foreground">{fmtTs(a.created_at)}</span>
          </div>
        ),
      },
      {
        key: "agent",
        title: "Agent",
        width: 168,
        render: (a) => <AgentTag agentId={a.agent_id ?? (a.details?.agent_id as string | undefined)} />,
      },
      {
        key: "network",
        title: "Network",
        className: "text-[12px]",
        render: (a) => (
          <div className="flex min-w-0 items-center gap-1 text-muted-foreground">
            <IpAddressPill ip={a.src_ip} ipContext={alertIpContext(a, "src")} compact />
            <span className="shrink-0 text-muted-foreground/70">→</span>
            <span className="inline-flex min-w-0 items-center gap-0.5">
              <IpAddressPill ip={a.dst_ip} ipContext={alertIpContext(a, "dst")} compact />
              {typeof a.dst_port === "number" ? <span className="shrink-0">:{a.dst_port}</span> : null}
            </span>
          </div>
        ),
      },
      {
        key: "description",
        title: "Description",
        render: (a) => (
          <div className="truncate text-[12px] text-muted-foreground" title={a.description || ""}>
            {a.description || ""}
          </div>
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
