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
  if (items.length === 0) return <span className="text-muted-foreground">{fallback}</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.slice(0, 3).map((item) => (
        <span
          key={item}
          className="inline-flex items-center rounded-md border border-border/60 bg-background/35 px-1.5 py-0.5 font-mono text-[11px]"
          title={item}
        >
          {item}
        </span>
      ))}
      {items.length > 3 ? <span className="text-[11px] text-muted-foreground">+{items.length - 3}</span> : null}
    </div>
  );
}

function stageHitPreview(stageHits: Record<string, number>) {
  const pairs = Object.entries(stageHits || {});
  if (pairs.length === 0) return <span className="text-muted-foreground">-</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {pairs.slice(0, 3).map(([key, value]) => (
        <span
          key={key}
          className="inline-flex items-center rounded-md border border-border/60 bg-background/35 px-1.5 py-0.5 font-mono text-[11px]"
        >
          {key}:{value}
        </span>
      ))}
      {pairs.length > 3 ? <span className="text-[11px] text-muted-foreground">+{pairs.length - 3}</span> : null}
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
        key: "status",
        title: "Status",
        sortable: true,
        render: (row: CorrelationDurableIncident) => <CorrelationStatusBadge status={row.status} />,
      },
      {
        key: "severity",
        title: "Severity",
        sortable: true,
        render: (row: CorrelationDurableIncident) => (
          <SeverityPill variant={correlationSeverityVariant(row.severity)}>{row.severity}</SeverityPill>
        ),
      },
      {
        key: "risk_score",
        title: "Risk score",
        sortable: true,
        render: (row: CorrelationDurableIncident) => <CorrelationRiskBadge score={row.risk_score} />,
      },
      {
        key: "confidence",
        title: "Confidence",
        sortable: true,
        render: (row: CorrelationDurableIncident) => <CorrelationConfidenceBadge confidence={row.confidence} />,
      },
      {
        key: "rule",
        title: "Rule",
        sortKey: "correlation_rule_name",
        sortable: true,
        className: "min-w-[220px]",
        render: (row: CorrelationDurableIncident) => (
          <div className="space-y-1">
            <div className="font-medium text-foreground">{row.correlation_rule_name}</div>
            <div className="font-mono text-[11px] text-muted-foreground">
              #{row.correlation_rule_id ?? "-"} · {row.dedup_key}
            </div>
          </div>
        ),
      },
      {
        key: "entity",
        title: "Entity",
        sortable: true,
        className: "min-w-[180px]",
        render: (row: CorrelationDurableIncident) => {
          const entity = correlationEntityLabel(row.entity_type, row.entity_value, row.group_by, row.group_value);
          return (
            <div className="space-y-1">
              <div className="font-mono text-[12px] text-foreground">{entity.value}</div>
              <div className="text-[11px] text-muted-foreground">{entity.type}</div>
            </div>
          );
        },
      },
      {
        key: "started_at",
        title: "Started",
        sortable: true,
        className: "font-mono text-[12px] text-muted-foreground min-w-[150px]",
        render: (row: CorrelationDurableIncident) => formatInvestigationTimestamp(row.started_at),
      },
      {
        key: "last_seen_at",
        title: "Last seen",
        sortable: true,
        className: "font-mono text-[12px] text-muted-foreground min-w-[150px]",
        render: (row: CorrelationDurableIncident) => formatInvestigationTimestamp(row.last_seen_at),
      },
      {
        key: "alert_count",
        title: "Alerts",
        sortable: true,
        className: "font-mono text-[12px]",
      },
      {
        key: "unique_rules",
        title: "Unique rules",
        sortKey: "unique_rules_count",
        sortable: true,
        className: "min-w-[170px]",
        render: (row: CorrelationDurableIncident) => chip(row.unique_rules, "No rule refs"),
      },
      {
        key: "stage_hits",
        title: "Stage hits",
        sortKey: "stage_hits_count",
        sortable: true,
        className: "min-w-[170px]",
        render: (row: CorrelationDurableIncident) => stageHitPreview(row.stage_hits),
      },
      {
        key: "mitre",
        title: "MITRE",
        className: "min-w-[170px]",
        render: (row: CorrelationDurableIncident) => {
          const preview = correlationMitrePreview(mitreByIncidentId[row.id] || { tactics: [], techniques: [] }, 1);
          return chip(preview, "-");
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
