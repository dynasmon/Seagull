import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";
import { Table } from "@/shared/components/Table";

import type { InventoryOverviewSnapshot } from "../types";
import { fmtMinutes } from "../lib/inventoryFormatters";
import { InventorySection } from "./primitives/InventorySection";
import { InventoryBarGaugeList } from "./primitives/InventoryBarGaugeList";

interface InventoryDistributionsPanelProps {
  snapshot: InventoryOverviewSnapshot | null;
  osRows: Array<{ os: string; agents: number }>;
  mgrRows: Array<{ manager: string; agents: number }>;
  busy: boolean;
  compact: boolean;
  onOpenDrawer: (agentId: string) => void;
}

export function InventoryDistributionsPanel({
  snapshot,
  osRows,
  mgrRows,
  busy,
  compact,
  onOpenDrawer,
}: InventoryDistributionsPanelProps) {
  const osTable =
    osRows.length === 0 ? (
      <EmptyState title="NO DATA" hint="No OS distribution available in the current window." />
    ) : (
      <Table
        compact={compact}
        columns={[
          { key: "os", title: "OS", className: "font-mono text-foreground" },
          { key: "agents", title: "AGENTS", className: "text-right font-mono text-muted-foreground w-24" },
        ]}
        rows={osRows}
        rowKey={(r) => r.os}
      />
    );

  const mgrTable =
    mgrRows.length === 0 ? (
      <EmptyState title="NO DATA" hint="No package manager distribution available in the current window." />
    ) : (
      <Table
        compact={compact}
        columns={[
          { key: "manager", title: "MANAGER", className: "font-mono text-foreground" },
          { key: "agents", title: "AGENTS", className: "text-right font-mono text-muted-foreground w-24" },
        ]}
        rows={mgrRows}
        rowKey={(r) => r.manager}
      />
    );

  return (
    <InventorySection id="distribution" title="Distributions" defaultOpen>
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <Panel title="OS distribution" scrollY className="min-h-[420px]">
          {snapshot ? osTable : busy ? <Loading /> : <EmptyState title="No data" />}
        </Panel>

        <Panel title="Package manager distribution" scrollY className="min-h-[420px]">
          {snapshot ? mgrTable : busy ? <Loading /> : <EmptyState title="No data" />}
        </Panel>

        <Panel title="Top agents" className="min-h-[420px]">
          {snapshot ? (
            <div className="space-y-6">
              <InventoryBarGaugeList
                title="Inventory age (minutes)"
                items={snapshot.inventory_age_by_agent}
                onPick={onOpenDrawer}
                valueFormatter={fmtMinutes}
              />

              <div className="h-px bg-border/60" />

              <InventoryBarGaugeList
                title="Packages count"
                items={snapshot.packages_count_by_agent}
                onPick={onOpenDrawer}
                valueFormatter={(v) => `${v}`}
              />
            </div>
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
