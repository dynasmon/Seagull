import { EuiLink } from "@elastic/eui";

import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";
import { Table } from "@/shared/components/Table";

import type { InventoryOverviewSnapshot, FleetHealthRow } from "../types";
import { fmtMinutes } from "../lib/inventoryFormatters";
import { InventorySection } from "./primitives/InventorySection";
import { InventoryStatusBadge } from "./primitives/InventoryStatusBadge";

interface InventoryFleetHealthTableProps {
  snapshot: InventoryOverviewSnapshot | null;
  fleetRows: FleetHealthRow[];
  busy: boolean;
  compact: boolean;
  onOpenDrawer: (agentId: string) => void;
}

export function InventoryFleetHealthTable({ snapshot, fleetRows, busy, compact, onOpenDrawer }: InventoryFleetHealthTableProps) {
  return (
    <InventorySection id="fleet" title="Fleet health" defaultOpen>
      <Panel
        title="Fleet health"
        actions={snapshot ? <span className="text-[10px] font-mono text-muted-foreground">{fleetRows.length} agents</span> : undefined}
        scrollY
        className="min-h-[520px]"
      >
        {snapshot ? (
          fleetRows.length === 0 ? (
            <EmptyState title="NO AGENTS" hint="No agent inventory data available for the current scope." />
          ) : (
            <Table
              compact={compact}
              scrollX={false}
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
                  key: "inventory_age_min",
                  title: "INV AGE",
                  align: "right",
                  className: "font-mono text-muted-foreground w-24",
                  render: (r: FleetHealthRow) => fmtMinutes(r.inventory_age_min),
                },
                {
                  key: "last_seen_age_min",
                  title: "SEEN",
                  align: "right",
                  className: "font-mono text-muted-foreground w-24",
                  render: (r: FleetHealthRow) => fmtMinutes(r.last_seen_age_min),
                },
                { key: "os", title: "OS", className: "font-mono text-foreground" },
                { key: "manager", title: "MGR", className: "font-mono text-muted-foreground w-24" },
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
              rows={fleetRows}
              rowKey={(r) => r.agent_id}
            />
          )
        ) : busy ? (
          <Loading />
        ) : (
          <EmptyState title="No data" />
        )}
      </Panel>
    </InventorySection>
  );
}
