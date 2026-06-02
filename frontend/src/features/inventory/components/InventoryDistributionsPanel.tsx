import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";
import { BarChart, DonutChart, type DonutDatum } from "@/shared/components/charts";

import type { InventoryOverviewSnapshot } from "../types";
import { fmtMinutes } from "../lib/inventoryFormatters";
import { InventorySection } from "./primitives/InventorySection";

interface InventoryDistributionsPanelProps {
  snapshot: InventoryOverviewSnapshot | null;
  osRows: Array<{ os: string; agents: number }>;
  mgrRows: Array<{ manager: string; agents: number }>;
  busy: boolean;
  compact: boolean;
  onOpenDrawer: (agentId: string) => void;
}

function toTopSlices(rows: DonutDatum[], max = 8): DonutDatum[] {
  const nonEmpty = rows.filter((r) => Number(r.value) > 0);
  if (nonEmpty.length <= max) return nonEmpty;
  const sorted = [...nonEmpty].sort((a, b) => b.value - a.value);
  const head = sorted.slice(0, max - 1);
  const otherValue = sorted.slice(max - 1).reduce((sum, r) => sum + r.value, 0);
  return otherValue > 0 ? [...head, { label: "Other", value: otherValue }] : head;
}

function shortenAgentId(value: string): string {
  return value.length > 16 ? `…${value.slice(-15)}` : value;
}

export function InventoryDistributionsPanel({
  snapshot,
  osRows,
  mgrRows,
  busy,
  onOpenDrawer,
}: InventoryDistributionsPanelProps) {
  const osData = toTopSlices(osRows.map((r) => ({ label: r.os, value: r.agents })));
  const mgrData = toTopSlices(mgrRows.map((r) => ({ label: r.manager, value: r.agents })));

  const ageItems = (snapshot?.inventory_age_by_agent || [])
    .slice(0, 10)
    .map((r) => ({ x: r.metric, y: Number(r.value) || 0 }));
  const packageItems = (snapshot?.packages_count_by_agent || [])
    .slice(0, 10)
    .map((r) => ({ x: r.metric, y: Number(r.value) || 0 }));

  return (
    <InventorySection id="distribution" title="Distributions" defaultOpen>
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <Panel title="OS distribution" className="min-h-[420px]">
          {snapshot ? (
            osData.length === 0 ? (
              <EmptyState title="NO DATA" hint="No OS distribution available in the current window." />
            ) : (
              <DonutChart
                data={osData}
                height={320}
                valueFormatter={(v) => `${v} agents`}
              />
            )
          ) : busy ? (
            <Loading />
          ) : (
            <EmptyState title="No data" />
          )}
        </Panel>

        <Panel title="Package manager distribution" className="min-h-[420px]">
          {snapshot ? (
            mgrData.length === 0 ? (
              <EmptyState title="NO DATA" hint="No package manager distribution available in the current window." />
            ) : (
              <DonutChart
                data={mgrData}
                height={320}
                valueFormatter={(v) => `${v} agents`}
              />
            )
          ) : busy ? (
            <Loading />
          ) : (
            <EmptyState title="No data" />
          )}
        </Panel>

        <Panel title="Top agents" className="min-h-[420px]">
          {snapshot ? (
            <div className="space-y-5">
              <div className="space-y-1.5">
                <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                  Inventory age (minutes)
                </div>
                <BarChart
                  data={ageItems}
                  height={150}
                  horizontal
                  categoryFormatter={shortenAgentId}
                  valueFormatter={(v) => fmtMinutes(v)}
                  onBarClick={onOpenDrawer}
                  emptyLabel="No agents"
                />
              </div>

              <div className="h-px bg-border/60" />

              <div className="space-y-1.5">
                <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                  Packages count
                </div>
                <BarChart
                  data={packageItems}
                  height={150}
                  horizontal
                  categoryFormatter={shortenAgentId}
                  valueFormatter={(v) => `${v}`}
                  onBarClick={onOpenDrawer}
                  emptyLabel="No agents"
                />
              </div>
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
