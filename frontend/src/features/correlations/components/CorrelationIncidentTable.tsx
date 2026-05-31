import { useMemo } from "react";

import { Table, type TableSortState } from "@/shared/components/Table";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { formatInvestigationTimestamp } from "@/shared/components/investigation";

import type {
  CorrelationDurableIncident,
  CorrelationMitreMetadata,
} from "../types";
import {
  CorrelationConfidenceBadge,
  CorrelationRiskBadge,
  CorrelationStatusBadge,
} from "./CorrelationRiskBadge";
import {
  correlationEntityLabel,
  correlationMitrePreview,
  correlationSeverityVariant,
} from "./correlationUtils";

function chip(items: string[], fallback = "-") {
  if (items.length === 0) return <span className="shrink-0 text-muted-foreground">{fallback}</span>;
  return (
    <div className="flex flex-nowrap items-center gap-1">
      {items.slice(0, 3).map((item) => (
        <span
          key={item}
          className="inline-flex shrink-0 items-center rounded-md border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[11px]"
          title={item}
        >
          {item}
        </span>
      ))}
      {items.length > 3 ? <span className="shrink-0 text-[11px] text-muted-foreground">+{items.length - 3}</span> : null}
    </div>
  );
}

function stageHitPreview(stageHits: Record<string, number>) {
  const pairs = Object.entries(stageHits || {});
  if (pairs.length === 0) return <span className="shrink-0 text-muted-foreground">-</span>;
  return (
    <div className="flex flex-nowrap items-center gap-1">
      {pairs.slice(0, 3).map(([key, value]) => (
        <span
          key={key}
          className="inline-flex shrink-0 items-center rounded-md border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[11px]"
        >
          {key}:{value}
        </span>
      ))}
      {pairs.length > 3 ? <span className="shrink-0 text-[11px] text-muted-foreground">+{pairs.length - 3}</span> : null}
    </div>
  );
}

export default function CorrelationIncidentTable({
  rows,
  selectedId,
  sort,
  mitreByIncidentId,
  onSortChange,
  onSelect,
}: {
  rows: CorrelationDurableIncident[];
  selectedId: number | null;
  sort: TableSortState | null;
  mitreByIncidentId: Record<number, CorrelationMitreMetadata | undefined>;
  onSortChange: (next: TableSortState) => void;
  onSelect: (incident: CorrelationDurableIncident) => void;
}) {
  const columns = useMemo(
    () => [
      {
        key: "risk",
        title: "Risk",
        sortable: true,
        sortKey: "risk_score",
        render: (row: CorrelationDurableIncident) => (
          <div className="flex flex-nowrap items-center gap-1">
            <CorrelationStatusBadge status={row.status} />
            <SeverityPill variant={correlationSeverityVariant(row.severity)}>{row.severity}</SeverityPill>
            <CorrelationRiskBadge score={row.risk_score} />
            <CorrelationConfidenceBadge confidence={row.confidence} />
          </div>
        ),
      },
      {
        key: "rule",
        title: "Rule / Entity",
        sortable: true,
        sortKey: "correlation_rule_name",
        render: (row: CorrelationDurableIncident) => {
          const entity = correlationEntityLabel(row.entity_type, row.entity_value, row.group_by, row.group_value);
          return (
            <div
              className="flex min-w-0 items-center gap-1.5"
              title={`${row.correlation_rule_name}\n#${row.correlation_rule_id ?? "-"} · ${row.dedup_key}\n${entity.value} (${entity.type})`}
            >
              <span className="min-w-0 flex-1 truncate font-medium text-foreground">{row.correlation_rule_name}</span>
              <span className="min-w-0 max-w-[45%] shrink-0 truncate font-mono text-[12px] text-foreground">{entity.value}</span>
              <span className="shrink-0 text-[11px] text-muted-foreground">{entity.type}</span>
            </div>
          );
        },
      },
      {
        key: "timeline",
        title: "Timeline",
        sortable: true,
        sortKey: "last_seen_at",
        className: "font-mono text-[12px] text-muted-foreground",
        render: (row: CorrelationDurableIncident) => (
          <div className="flex items-center gap-1.5 whitespace-nowrap">
            <span className="text-foreground">{formatInvestigationTimestamp(row.last_seen_at)}</span>
            <span className="text-[11px]">started {formatInvestigationTimestamp(row.started_at)}</span>
            <span className="text-[11px]">· {row.alert_count} alerts</span>
          </div>
        ),
      },
      {
        key: "intelligence",
        title: "Intelligence",
        render: (row: CorrelationDurableIncident) => {
          const mitrePreview = correlationMitrePreview(mitreByIncidentId[row.id] || { tactics: [], techniques: [] }, 1);
          return (
            <div className="flex min-w-0 flex-nowrap items-center gap-1.5 overflow-hidden">
              {chip(row.unique_rules, "No rule refs")}
              {stageHitPreview(row.stage_hits)}
              {chip(mitrePreview, "-")}
            </div>
          );
        },
      },
    ],
    [mitreByIncidentId],
  );

  return (
    <Table
      columns={columns}
      rows={rows}
      rowKey={(row) => String(row.id)}
      selectedRowKey={selectedId === null ? null : String(selectedId)}
      onRowClick={(row) => onSelect(row)}
      sort={sort}
      onSortChange={onSortChange}
      rowClassName={(row) => (String(row.status) === "suppressed" ? "opacity-80" : undefined)}
    />
  );
}
