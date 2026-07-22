import { EuiLink } from "@elastic/eui";

import EmptyState from "@/shared/components/EmptyState";
import { Panel } from "@/shared/components/Panel";
import { Table } from "@/shared/components/Table";

import type { HygieneDomain, InventoryWarningRow, FleetHealthRow } from "../types";
import { HYGIENE_TABS } from "../constants";
import { fmtDateTime } from "../lib/inventoryFormatters";
import { InventoryStatusBadge } from "./primitives/InventoryStatusBadge";

interface InventoryWarningsPanelProps {
  domain: HygieneDomain;
  domainWarnings: InventoryWarningRow[];
  domainPivotRows: FleetHealthRow[];
  compact: boolean;
  onOpenDrawer: (agentId: string) => void;
}

export function InventoryWarningsPanel({ domain, domainWarnings, domainPivotRows, compact, onOpenDrawer }: InventoryWarningsPanelProps) {
  const domainLabel = HYGIENE_TABS.find((x) => x.key === domain)?.label || "Domain";

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <Panel title={`${domainLabel} warning pivots`} scrollY className="min-h-[360px]">
        {domainWarnings.length === 0 ? (
          <EmptyState title="No domain-specific warnings" hint="Try a wider lookback window or scope all agents." />
        ) : (
          <Table
            compact={compact}
            className="text-xs"
            columns={[
              {
                key: "time",
                title: "TIME",
                className: "w-40 font-mono text-muted-foreground",
                render: (r: InventoryWarningRow) => fmtDateTime(r.time),
              },
              {
                key: "agent_id",
                title: "AGENT",
                className: "w-52 font-mono text-foreground",
                render: (r: InventoryWarningRow) => (
                  <EuiLink onClick={() => onOpenDrawer(r.agent_id)} className="font-mono text-[11px]">
                    {r.agent_id}
                  </EuiLink>
                ),
              },
              {
                key: "warning",
                title: "WARNING",
                className: "text-muted-foreground",
                render: (r: InventoryWarningRow) => (
                  <div className="max-w-[540px] truncate" title={r.warning}>
                    {r.warning}
                  </div>
                ),
              },
            ]}
            rows={domainWarnings}
            rowKey={(r, i) => `${r.time || "na"}-${r.agent_id}-${i}`}
          />
        )}
      </Panel>

      <Panel
        title="Asset pivots"
        actions={<span className="text-[10px] font-mono text-muted-foreground">{domainPivotRows.length} agents</span>}
        scrollY
        className="min-h-[360px]"
      >
        {domainPivotRows.length === 0 ? (
          <EmptyState title="No assets" hint="No assets available for this scope." />
        ) : (
          <Table
            compact={compact}
            className="text-xs"
            columns={[
              {
                key: "agent_id",
                title: "AGENT",
                className: "font-mono text-foreground w-56",
                render: (r: FleetHealthRow) => (
                  <EuiLink onClick={() => onOpenDrawer(r.agent_id)} className="font-mono text-[11px]">
                    {r.agent_id}
                  </EuiLink>
                ),
              },
              {
                key: "inventory_status",
                title: "INVENTORY",
                className: "w-28",
                render: (r: FleetHealthRow) => <InventoryStatusBadge status={r.inventory_status} />,
              },
              {
                key: "packages_count",
                title: "PKGS",
                align: "right",
                className: "font-mono text-muted-foreground w-20",
                render: (r: FleetHealthRow) => r.packages_count ?? "-",
              },
              {
                key: "warnings_count",
                title: "WARN",
                align: "right",
                className: "font-mono text-muted-foreground w-20",
                render: (r: FleetHealthRow) => r.warnings_count,
              },
            ]}
            rows={domainPivotRows}
            rowKey={(r) => r.agent_id}
          />
        )}
      </Panel>
    </div>
  );
}
