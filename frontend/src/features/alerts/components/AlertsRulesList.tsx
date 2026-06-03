import { useMemo, useState } from "react";

import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { StatusPill } from "@/shared/components/StatusPill";
import { Table, type Column, type TableSortState } from "@/shared/components/Table";

import { sevVariant } from "../lib/alertSeverity";
import type { RuleOut } from "../types";

interface AlertsRulesListProps {
  loading: boolean;
  filtered: RuleOut[];
  selectedId: string | null;
  onEdit: (rule: RuleOut) => void;
}

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

function statusRank(rule: RuleOut): number {
  if (!rule.enabled) return 0;
  if (rule.has_override) return 1;
  return 2;
}

function RuleStatus({ rule }: { rule: RuleOut }) {
  if (!rule.enabled) return <StatusPill variant="neutral">disabled</StatusPill>;
  if (rule.has_override) return <StatusPill variant="info">override</StatusPill>;
  return <StatusPill variant="active">active</StatusPill>;
}

function compareRules(a: RuleOut, b: RuleOut, key: string): number {
  switch (key) {
    case "severity":
      return (
        (SEVERITY_RANK[String(a.severity || "").toLowerCase()] ?? 0) -
        (SEVERITY_RANK[String(b.severity || "").toLowerCase()] ?? 0)
      );
    case "status":
      return statusRank(a) - statusRank(b);
    case "type":
      return String(a.type || "").localeCompare(String(b.type || ""));
    case "version":
      return Number(a.rule_version || 0) - Number(b.rule_version || 0);
    case "rule":
    default:
      return String(a.id || "").localeCompare(String(b.id || ""));
  }
}

export function AlertsRulesList({ loading, filtered, selectedId, onEdit }: AlertsRulesListProps) {
  const [sort, setSort] = useState<TableSortState | null>(null);

  const columns = useMemo<Array<Column<RuleOut>>>(
    () => [
      {
        key: "rule",
        title: "Rule",
        width: 300,
        sortable: true,
        render: (r) => {
          const context = r.name || r.description || "";
          return (
            <div className="flex min-w-0 items-center gap-2">
              <span className="shrink-0 truncate font-mono text-[12px] text-foreground" title={r.id}>
                {r.id}
              </span>
              {context ? (
                <span className="min-w-0 truncate text-[11px] text-muted-foreground" title={context}>
                  {context}
                </span>
              ) : null}
            </div>
          );
        },
      },
      {
        key: "severity",
        title: "Severity",
        width: 116,
        sortable: true,
        render: (r) => (
          <SeverityPill variant={sevVariant(String(r.severity || "unknown"))} withDot>
            {String(r.severity || "unknown")}
          </SeverityPill>
        ),
      },
      {
        key: "status",
        title: "Status",
        width: 116,
        sortable: true,
        render: (r) => <RuleStatus rule={r} />,
      },
      {
        key: "type",
        title: "Type",
        width: 150,
        sortable: true,
        render: (r) => (
          <span className="truncate font-mono text-[11.5px] text-muted-foreground" title={r.type || ""}>
            {r.type || "-"}
          </span>
        ),
      },
      {
        key: "pack",
        title: "Pack / Category",
        width: 200,
        render: (r) => (
          <span
            className="truncate font-mono text-[11px] text-muted-foreground"
            title={`${r.pack || "-"} / ${r.category || "-"}`}
          >
            {r.pack || "-"} / {r.category || "-"}
          </span>
        ),
      },
      {
        key: "window",
        title: "Window · Cooldown",
        width: 156,
        render: (r) => (
          <span className="font-mono text-[11px] text-muted-foreground">
            {r.window || "-"} · cd {r.cooldown || "-"}
          </span>
        ),
      },
      {
        key: "version",
        title: "Ver",
        width: 72,
        align: "right",
        sortable: true,
        render: (r) => <span className="font-mono text-[11px] text-muted-foreground">v{Number(r.rule_version || 1)}</span>,
      },
      {
        key: "actions",
        title: "Actions",
        align: "right",
        width: 90,
        render: (r) => (
          <Button
            variant="subtle"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              onEdit(r);
            }}
            title="Open rule editor"
          >
            Edit
          </Button>
        ),
      },
    ],
    [onEdit],
  );

  const rows = useMemo(() => {
    if (!sort) return filtered;
    const dir = sort.direction === "asc" ? 1 : -1;
    return [...filtered].sort((a, b) => dir * compareRules(a, b, sort.key));
  }, [filtered, sort]);

  if (loading) {
    return (
      <div className="p-4">
        <Loading label="Loading rules…" />
      </div>
    );
  }

  if (filtered.length === 0) {
    return (
      <div className="p-4">
        <EmptyState title="No rules" description="No rules match your current search." />
      </div>
    );
  }

  return (
    <Table
      className="!shadow-none !border-0 !bg-transparent !rounded-none text-sm"
      columns={columns}
      rows={rows}
      rowKey={(r) => r.id}
      scrollX
      stickyHeader
      compact
      selectedRowKey={selectedId}
      sort={sort}
      onSortChange={setSort}
      onRowClick={(r) => onEdit(r)}
    />
  );
}
