import { useEffect, useMemo, useState } from "react";
import { useEuiTheme } from "@elastic/eui";

import Drawer from "@/shared/components/Drawer";
import { Badge } from "@/shared/components/Badge";
import EmptyState from "@/shared/components/EmptyState";
import { FilterBar, FilterButtonMultiSelect, FilterButtonSelect, type FilterOption } from "@/shared/components/FilterBar";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { Panel } from "@/shared/components/Panel";
import { Table, type Column, type TableSortState } from "@/shared/components/Table";
import { TextInput } from "@/shared/components/TextInput";
import { BarChart } from "@/shared/components/charts/BarChart";
import { DonutChart } from "@/shared/components/charts/DonutChart";
import { useSeverityChartColors } from "@/shared/components/charts/chartTheme";
import type { SeverityLevel } from "@/shared/lib/severity";

import { toSeverityLevel } from "./globeTheme";
import { normalizeCountryCode } from "../useCountryAggregations";
import type { ThreatGeoIp, ThreatGeoPoint } from "../types";

export type CountrySelection = {
  code: string;
  name: string;
};

const PROVENANCE_OPTIONS: FilterOption[] = [
  { value: "all", label: "All sources" },
  { value: "alert", label: "Alert" },
  { value: "event", label: "Event" },
  { value: "mixed", label: "Mixed" },
];

const DIRECTION_OPTIONS: FilterOption[] = [
  { value: "all", label: "All directions" },
  { value: "inbound", label: "Inbound" },
  { value: "outbound", label: "Outbound" },
  { value: "internal", label: "Internal" },
  { value: "transit", label: "Transit" },
];

const SEVERITY_LEVELS: SeverityLevel[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_LABELS: Record<SeverityLevel, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Ambient",
  neutral: "Neutral",
};

function placeLabel(point: ThreatGeoPoint): string {
  const place = [point.city, point.region].filter(Boolean)[0];
  return place || point.country || "Unknown location";
}

function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const hasTimezone = /[zZ]|[+-]\d{2}:?\d{2}$/.test(iso);
  const then = Date.parse(hasTimezone ? iso : `${iso}Z`);
  if (!Number.isFinite(then)) return "—";
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

const SORTERS: Record<string, (point: ThreatGeoPoint) => number | string> = {
  location: (point) => placeLabel(point).toLowerCase(),
  unique_ips: (point) => point.unique_ips,
  count: (point) => point.count,
  last_seen: (point) => point.last_seen ?? "",
};

export function CountryDetailDrawer({
  selection,
  points,
  onClose,
  onFocusCity,
}: {
  selection: CountrySelection | null;
  points: ThreatGeoPoint[];
  onClose: () => void;
  onFocusCity?: (lat: number, lon: number) => void;
}) {
  const { euiTheme } = useEuiTheme();
  const severityColors = useSeverityChartColors();

  const [sort, setSort] = useState<TableSortState>({ key: "count", direction: "desc" });
  const [severities, setSeverities] = useState<string[]>([]);
  const [provenance, setProvenance] = useState("all");
  const [direction, setDirection] = useState("all");
  const [search, setSearch] = useState("");

  useEffect(() => {
    setSort({ key: "count", direction: "desc" });
    setSeverities([]);
    setProvenance("all");
    setDirection("all");
    setSearch("");
  }, [selection?.code]);

  const countryPoints = useMemo(() => {
    if (!selection) return [];
    return points.filter((point) => normalizeCountryCode(point.country) === selection.code);
  }, [points, selection]);

  const severityOptions = useMemo<FilterOption[]>(() => {
    const counts: Record<SeverityLevel, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, neutral: 0 };
    for (const point of countryPoints) {
      const level = toSeverityLevel(point.severity);
      if (level in counts) counts[level] += 1;
    }
    return SEVERITY_LEVELS.map((level) => ({
      value: level,
      label: SEVERITY_LABELS[level],
      count: counts[level],
    }));
  }, [countryPoints]);

  const filteredPoints = useMemo(() => {
    const query = search.trim().toLowerCase();
    return countryPoints.filter((point) => {
      if (severities.length && !severities.includes(toSeverityLevel(point.severity))) return false;
      if (provenance !== "all" && point.provenance !== provenance) return false;
      if (direction !== "all" && point.direction !== direction) return false;
      if (query) {
        const haystack = [point.city, point.region, point.org, point.asn_org, ...point.top_ips.map((ip) => ip.ip)]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      return true;
    });
  }, [countryPoints, severities, provenance, direction, search]);

  const totals = useMemo(() => {
    let hits = 0;
    let uniqueIps = 0;
    let lastSeen: string | null = null;
    for (const point of countryPoints) {
      hits += point.count;
      uniqueIps += point.unique_ips;
      if (point.last_seen && (!lastSeen || point.last_seen > lastSeen)) lastSeen = point.last_seen;
    }
    return { hits, uniqueIps, lastSeen };
  }, [countryPoints]);

  const severityDonut = useMemo(() => {
    const counts: Record<SeverityLevel, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, neutral: 0 };
    for (const point of filteredPoints) {
      counts.critical += point.critical;
      counts.high += point.high;
      counts.medium += point.medium;
      counts.low += point.low;
      counts.info += point.info ?? 0;
    }
    return SEVERITY_LEVELS.map((level) => ({
      label: SEVERITY_LABELS[level],
      value: counts[level],
    })).filter((entry) => entry.value > 0);
  }, [filteredPoints]);

  const topRules = useMemo(() => {
    const tally = new Map<string, number>();
    for (const point of filteredPoints) {
      for (const rule of point.top_rules) tally.set(rule.rule_id, (tally.get(rule.rule_id) ?? 0) + rule.count);
    }
    return [...tally.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([rule, count]) => ({ x: rule, y: count }));
  }, [filteredPoints]);

  const topIps = useMemo(() => {
    const tally = new Map<string, ThreatGeoIp>();
    for (const point of filteredPoints) {
      for (const ip of point.top_ips) {
        const existing = tally.get(ip.ip);
        if (existing) existing.count += ip.count;
        else tally.set(ip.ip, { ...ip });
      }
    }
    return [...tally.values()].sort((a, b) => b.count - a.count).slice(0, 12);
  }, [filteredPoints]);

  const sortedPoints = useMemo(() => {
    const sorter = SORTERS[sort.key] ?? SORTERS.count;
    const factor = sort.direction === "asc" ? 1 : -1;
    return [...filteredPoints].sort((a, b) => {
      const av = sorter(a);
      const bv = sorter(b);
      if (av < bv) return -1 * factor;
      if (av > bv) return 1 * factor;
      return 0;
    });
  }, [filteredPoints, sort]);

  const columns = useMemo<Array<Column<ThreatGeoPoint>>>(
    () => [
      {
        key: "location",
        title: "City / Region",
        sortable: true,
        render: (point) => <span className="font-medium text-foreground">{placeLabel(point)}</span>,
      },
      {
        key: "unique_ips",
        title: "IPs",
        align: "right",
        width: 56,
        sortable: true,
        render: (point) => <span className="font-mono">{point.unique_ips.toLocaleString()}</span>,
      },
      {
        key: "count",
        title: "Hits",
        align: "right",
        width: 68,
        sortable: true,
        render: (point) => <span className="font-mono">{point.count.toLocaleString()}</span>,
      },
      {
        key: "severity",
        title: "Severity",
        width: 92,
        render: (point) => <Badge variant={toSeverityLevel(point.severity)}>{toSeverityLevel(point.severity)}</Badge>,
      },
      {
        key: "last_seen",
        title: "Last seen",
        align: "right",
        width: 84,
        sortable: true,
        render: (point) => <span className="text-muted-foreground">{formatRelativeTime(point.last_seen)}</span>,
      },
    ],
    [],
  );

  const ipColumns = useMemo<Array<Column<ThreatGeoIp>>>(
    () => [
      {
        key: "ip",
        title: "Source IP / Org",
        render: (row) => {
          const org = (row.asn_org || row.org || "").trim();
          return (
            <div className="min-w-0">
              <IpAddressPill ip={row.ip} ipContext={{ scope: row.scope, is_public: row.is_public }} compact />
              {org ? (
                <div className="mt-0.5 truncate text-[11px] text-muted-foreground" title={org}>
                  {org}
                </div>
              ) : null}
            </div>
          );
        },
      },
      {
        key: "count",
        title: "Hits",
        align: "right",
        width: 64,
        render: (row) => <span className="font-mono">{row.count.toLocaleString()}</span>,
      },
    ],
    [],
  );

  const description = selection
    ? `${totals.uniqueIps.toLocaleString()} IPs locating · ${totals.hits.toLocaleString()} hits · last seen ${formatRelativeTime(totals.lastSeen)}`
    : "";

  return (
    <Drawer
      open={selection !== null}
      headerLabel="Country"
      title={selection?.name ?? selection?.code ?? "Country"}
      description={description}
      onClose={onClose}
      widthClassName="w-[560px]"
    >
      {countryPoints.length === 0 ? (
        <EmptyState title="No located sources" hint="No geolocated source points for this country in the current window." />
      ) : (
        <div className="space-y-4">
          <div className="space-y-2">
            <FilterBar>
              <FilterButtonMultiSelect label="Severity" selected={severities} options={severityOptions} onChange={setSeverities} />
              <FilterButtonSelect label="Provenance" value={provenance} options={PROVENANCE_OPTIONS} onChange={setProvenance} />
              <FilterButtonSelect label="Direction" value={direction} options={DIRECTION_OPTIONS} onChange={setDirection} />
            </FilterBar>
            <TextInput
              placeholder="Filter by IP, org, or city…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              aria-label="Filter country sources"
            />
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Panel title="Severity mix" compact>
              <DonutChart
                data={severityDonut}
                height={180}
                legendPosition="bottom"
                colorFor={(label) => severityColors[toSeverityLevel(label)]}
                emptyLabel="No matching sources"
              />
            </Panel>
            <Panel title="Top rules" compact>
              <BarChart
                data={topRules}
                height={180}
                horizontal
                color={euiTheme.colors.primary}
                categoryFormatter={(value) => (value.length > 22 ? `${value.slice(0, 21)}…` : value)}
                emptyLabel="No rules"
              />
            </Panel>
          </div>

          <section className="space-y-2">
            <div className="ui-eyebrow">Located sources ({filteredPoints.length.toLocaleString()})</div>
            {filteredPoints.length === 0 ? (
              <EmptyState title="No matches" hint="No sources match the current filters." />
            ) : (
              <Table
                columns={columns}
                rows={sortedPoints}
                rowKey={(point) => `${point.lat},${point.lon},${point.provenance},${point.direction}`}
                sort={sort}
                onSortChange={setSort}
                onRowClick={(point) => onFocusCity?.(point.lat, point.lon)}
                layout="fixed"
                className="text-sm"
              />
            )}
          </section>

          {topIps.length > 0 ? (
            <section className="space-y-2">
              <div className="ui-eyebrow">Top source IPs</div>
              <Table columns={ipColumns} rows={topIps} rowKey={(row) => row.ip} layout="fixed" className="text-sm" />
            </section>
          ) : null}
        </div>
      )}
    </Drawer>
  );
}

export default CountryDetailDrawer;
