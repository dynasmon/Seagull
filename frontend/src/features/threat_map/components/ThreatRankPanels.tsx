import { useMemo, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import EmptyState from "@/shared/components/EmptyState";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { Panel } from "@/shared/components/Panel";
import { Table, type Column, type TableSortState } from "@/shared/components/Table";
import { useSeverityChartColors } from "@/shared/components/charts/chartTheme";
import type { SeverityLevel } from "@/shared/lib/severity";

import { CountryLabel } from "../CountryFlag";
import type { ThreatGeoRankCountry, ThreatGeoRankIp } from "../types";

function severityLevel(severity: string | null | undefined): SeverityLevel {
  const value = (severity || "").toLowerCase();
  if (value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info") {
    return value;
  }
  return "neutral";
}

function CountryRankList({ rows, empty }: { rows: ThreatGeoRankCountry[]; empty: string }) {
  const severityColors = useSeverityChartColors();
  const max = rows.reduce((value, row) => Math.max(value, row.count), 0) || 1;

  if (rows.length === 0) {
    return <EmptyState title="No countries" hint={empty} />;
  }

  return (
    <div className="space-y-2">
      {rows.map((row) => {
        const color = severityColors[severityLevel(row.severity)];
        return (
          <div key={row.country} className="space-y-1">
            <div className="flex items-center justify-between gap-2 text-xs">
              <span className="inline-flex min-w-0 items-center gap-2">
                <span className="inline-block h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: color }} />
                <CountryLabel country={row.country} className="font-medium text-foreground" />
                <span className="text-muted-foreground">{row.unique_ips.toLocaleString()} IPs</span>
              </span>
              <span className="font-mono text-foreground">{row.count.toLocaleString()}</span>
            </div>
            <div className="h-1 overflow-hidden rounded bg-muted/40">
              <div className="h-full rounded" style={{ width: `${(row.count / max) * 100}%`, backgroundColor: color }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function IpRankTable({
  rows,
  role,
  empty,
}: {
  rows: ThreatGeoRankIp[];
  role: "source" | "destination";
  empty: string;
}) {
  const [sort, setSort] = useState<TableSortState>({ key: "count", direction: "desc" });
  const sorted = useMemo(() => {
    const factor = sort.direction === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => (a.count - b.count) * factor);
  }, [rows, sort]);

  const columns = useMemo<Array<Column<ThreatGeoRankIp>>>(
    () => [
      {
        key: "count",
        title: "Count",
        width: 56,
        align: "right",
        sortable: true,
        className: "font-mono",
        render: (row) => <span className="font-mono">{row.count.toLocaleString()}</span>,
      },
      {
        key: "ip",
        title: role === "destination" ? "Destination / Org" : "Source / Org",
        render: (row) => {
          const org = (row.asn_org || row.org || "").trim();
          return (
            <div className="min-w-0">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <IpAddressPill ip={row.ip} compact />
                {row.country ? (
                  <Badge variant={severityLevel(row.severity)}>
                    <CountryLabel country={row.country} />
                  </Badge>
                ) : null}
              </div>
              {org ? (
                <div className="mt-0.5 truncate text-[11px] text-muted-foreground" title={org}>
                  {org}
                </div>
              ) : null}
            </div>
          );
        },
      },
    ],
    [role],
  );

  if (rows.length === 0) {
    return <EmptyState title="No IPs" hint={empty} />;
  }

  return (
    <Table
      columns={columns}
      rows={sorted}
      rowKey={(row) => row.ip}
      sort={sort}
      onSortChange={setSort}
      layout="fixed"
      className="text-sm"
    />
  );
}

export function ThreatRankPanels({
  topSourceCountries,
  topSourceIps,
  topDestinationCountries,
  topDestinationIps,
}: {
  topSourceCountries: ThreatGeoRankCountry[];
  topSourceIps: ThreatGeoRankIp[];
  topDestinationCountries: ThreatGeoRankCountry[];
  topDestinationIps: ThreatGeoRankIp[];
}) {
  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
      <Panel title="Top source countries" compact>
        <CountryRankList rows={topSourceCountries} empty="No located source traffic in this window." />
      </Panel>
      <Panel title="Top source IPs" compact>
        <IpRankTable rows={topSourceIps} role="source" empty="No located source IPs in this window." />
      </Panel>
      <Panel title="Top destination countries" compact>
        <CountryRankList rows={topDestinationCountries} empty="No outbound destinations in this window." />
      </Panel>
      <Panel title="Top destination IPs" compact>
        <IpRankTable rows={topDestinationIps} role="destination" empty="No outbound destination IPs in this window." />
      </Panel>
    </div>
  );
}
