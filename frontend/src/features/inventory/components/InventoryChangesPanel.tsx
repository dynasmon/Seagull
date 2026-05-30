import { EuiLink } from "@elastic/eui";

import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";
import { Table } from "@/shared/components/Table";

import type { InventoryOverviewSnapshot, InventoryChangeRow, InventoryWarningRow } from "../types";
import { fmtDateTime } from "../lib/inventoryFormatters";
import { InventorySection } from "./primitives/InventorySection";

interface InventoryChangesPanelProps {
  snapshot: InventoryOverviewSnapshot | null;
  changesRows: InventoryChangeRow[];
  warningsRows: InventoryWarningRow[];
  busy: boolean;
  compact: boolean;
  onOpenDrawer: (agentId: string) => void;
}

export function InventoryChangesPanel({
  snapshot,
  changesRows,
  warningsRows,
  busy,
  compact,
  onOpenDrawer,
}: InventoryChangesPanelProps) {
  return (
    <InventorySection id="changes" title="Recent changes & warnings" defaultOpen={false}>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Panel title="Recent inventory changes" scrollY className="min-h-[520px]">
          {snapshot ? (
            changesRows.length === 0 ? (
              <EmptyState title="NO CHANGES" hint="No inventory baselines/changes in the current window." />
            ) : (
              <Table
                compact={compact}
                scrollX={false}
                className="text-xs"
                columns={[
                  {
                    key: "time",
                    title: "TIME",
                    className: "font-mono text-muted-foreground w-40",
                    render: (r: InventoryChangeRow) => fmtDateTime(r.time),
                  },
                  {
                    key: "agent_id",
                    title: "AGENT",
                    className: "font-mono text-foreground w-56",
                    render: (r: InventoryChangeRow) => (
                      <EuiLink onClick={() => onOpenDrawer(r.agent_id)} className="font-mono text-[11px]">
                        {r.agent_id}
                      </EuiLink>
                    ),
                  },
                  {
                    key: "change_type",
                    title: "TYPE",
                    className: "font-mono text-muted-foreground w-24",
                    render: (r: InventoryChangeRow) => r.change_type,
                  },
                  {
                    key: "delta",
                    title: "Δ PKGS",
                    className: "text-right font-mono text-muted-foreground w-20",
                    render: (r: InventoryChangeRow) => {
                      if (r.old_count === null || r.old_count === undefined) return "-";
                      return `${Number(r.new_count ?? 0) - Number(r.old_count ?? 0)}`;
                    },
                  },
                ]}
                rows={changesRows}
                rowKey={(r, i) => `${r.time || "na"}-${r.agent_id}-${i}`}
              />
            )
          ) : busy ? (
            <Loading />
          ) : (
            <EmptyState title="No data" />
          )}
        </Panel>

        <Panel title="Recent inventory warnings" scrollY className="min-h-[520px]">
          {snapshot ? (
            warningsRows.length === 0 ? (
              <EmptyState title="NO WARNINGS" hint="No inventory warnings in the current window." />
            ) : (
              <Table
                compact={compact}
                scrollX={false}
                className="text-xs"
                columns={[
                  {
                    key: "time",
                    title: "TIME",
                    className: "font-mono text-muted-foreground w-40",
                    render: (r: InventoryWarningRow) => fmtDateTime(r.time),
                  },
                  {
                    key: "agent_id",
                    title: "AGENT",
                    className: "font-mono text-foreground w-56",
                    render: (r: InventoryWarningRow) => (
                      <EuiLink onClick={() => onOpenDrawer(r.agent_id)} className="font-mono text-[11px]">
                        {r.agent_id}
                      </EuiLink>
                    ),
                  },
                  {
                    key: "warning",
                    title: "WARNING",
                    className: "font-mono text-muted-foreground",
                    render: (r: InventoryWarningRow) => (
                      <div className="max-w-[520px] whitespace-pre-wrap break-words text-[11px] text-muted-foreground">
                        {r.warning}
                      </div>
                    ),
                  },
                ]}
                rows={warningsRows}
                rowKey={(r, i) => `${r.time || "na"}-${r.agent_id}-${i}`}
              />
            )
          ) : busy ? (
            <Loading />
          ) : (
            <EmptyState title="No data" />
          )}
        </Panel>
      </div>
    </InventorySection>
  );
}
