import { useMemo } from "react";

import { fmtDuration, fmtMaybeIso } from "@/features/agents/lib/agentUtils";
import type { AgentPublic } from "@/features/agents/types";
import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { FilterBar, FilterButtonMultiSelect, FilterButtonSelect } from "@/shared/components/FilterBar";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { Panel } from "@/shared/components/Panel";
import { StatusPill } from "@/shared/components/StatusPill";
import { Table, type Column } from "@/shared/components/Table";
import type { UrlQueryUpdater } from "@/shared/hooks/useUrlQueryState";
import type { LiveRefreshState } from "@/shared/realtime/useLiveRefresh";

import { riskVariant, statusVariant } from "./lib";
import type { ActionTypeOut, ExecutionFilters, ResponseActionOut } from "./types";

interface ActiveExecutionsTableProps {
  executions: ResponseActionOut[];
  agents: AgentPublic[];
  catalog: ActionTypeOut[];
  filters: ExecutionFilters;
  setFilters: (next: UrlQueryUpdater<ExecutionFilters>) => void;
  refreshState: LiveRefreshState;
  error: string | null;
  onRowClick: (actionId: number) => void;
  onDispatch: () => void;
}

const STATUS_OPTIONS = ["pending", "delivered", "running", "success", "failed", "cancelled", "expired"].map((value) => ({
  value,
  label: value,
}));

const CATEGORY_OPTIONS = [
  { value: "", label: "All categories" },
  { value: "forensics", label: "Forensics" },
  { value: "diagnostics", label: "Diagnostics" },
  { value: "containment", label: "Containment" },
];

const SINCE_OPTIONS = [
  { value: "", label: "Any time" },
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "Last 24h" },
  { value: "7d", label: "Last 7 days" },
];

export default function ActiveExecutionsTable({
  executions,
  agents,
  catalog,
  filters,
  setFilters,
  refreshState,
  error,
  onRowClick,
  onDispatch,
}: ActiveExecutionsTableProps) {
  const riskByType = useMemo(() => {
    const map = new Map<string, string>();
    for (const d of catalog) map.set(d.key, d.risk_level);
    return map;
  }, [catalog]);

  const agentName = useMemo(() => {
    const map = new Map<string, string>();
    for (const a of agents) map.set(a.agent_id, a.display_name || a.agent_id);
    return map;
  }, [agents]);

  const agentOptions = useMemo(
    () => [{ value: "", label: "All agents" }, ...agents.map((a) => ({ value: a.agent_id, label: a.display_name || a.agent_id }))],
    [agents],
  );

  const columns: Array<Column<ResponseActionOut>> = [
    { key: "id", title: "#ID", width: 70, render: (row) => <span className="font-mono text-[11px]">#{row.id}</span> },
    { key: "action_type", title: "Type", render: (row) => <span className="font-mono text-[11px]">{row.action_type}</span> },
    {
      key: "agent_id",
      title: "Agent",
      render: (row) => <span className="truncate text-[11.5px]">{agentName.get(row.agent_id) || row.agent_id}</span>,
    },
    { key: "status", title: "Status", render: (row) => <StatusPill variant={statusVariant(row.status)}>{row.status}</StatusPill> },
    {
      key: "risk",
      title: "Risk",
      render: (row) => {
        const risk = riskByType.get(row.action_type);
        return risk ? <Badge variant={riskVariant(risk)}>{risk}</Badge> : <span className="text-muted-foreground">—</span>;
      },
    },
    { key: "requested_by", title: "Requested by", render: (row) => <span className="text-[11.5px]">{row.requested_by}</span> },
    {
      key: "requested_at",
      title: "Requested",
      render: (row) => <span className="font-mono text-[11px] text-muted-foreground">{fmtMaybeIso(row.requested_at)}</span>,
    },
    {
      key: "duration",
      title: "Duration",
      render: (row) => <span className="font-mono text-[11px]">{fmtDuration(row.started_at, row.finished_at)}</span>,
    },
    {
      key: "actions",
      title: "Actions",
      align: "right",
      render: (row) => (
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            onRowClick(row.id);
          }}
          className="rounded border border-border/60 px-2 py-0.5 text-[11px] text-muted-foreground hover:border-primary/40 hover:text-foreground"
        >
          Details
        </button>
      ),
    },
  ];

  return (
    <Panel
      title="Executions"
      subtitle="Recent and in-flight response actions"
      actions={
        <span className="text-[10px] font-mono uppercase tracking-[0.08em] text-muted-foreground">
          {refreshState.isRefreshing ? "Refreshing" : refreshState.isLive ? "Live" : refreshState.isReconnecting ? "Reconnecting" : "Polling"}
          {" · "}
          {executions.length}
        </span>
      }
    >
      <div className="mb-3">
        <FilterBar>
          <FilterButtonMultiSelect
            label="Status"
            selected={filters.statuses}
            options={STATUS_OPTIONS}
            onChange={(next) => setFilters((prev) => ({ ...prev, statuses: next }))}
          />
          <FilterButtonSelect
            label="Category"
            value={filters.category}
            options={CATEGORY_OPTIONS}
            onChange={(next) => setFilters((prev) => ({ ...prev, category: next }))}
          />
          <FilterButtonSelect
            label="Agent"
            value={filters.agentId}
            options={agentOptions}
            searchable
            onChange={(next) => setFilters((prev) => ({ ...prev, agentId: next }))}
          />
          <FilterButtonSelect
            label="Window"
            value={filters.since}
            options={SINCE_OPTIONS}
            onChange={(next) => setFilters((prev) => ({ ...prev, since: next }))}
          />
        </FilterBar>
      </div>

      {error ? (
        <div className="mb-3">
          <InlineAlert tone="danger">{error}</InlineAlert>
        </div>
      ) : null}

      {executions.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-12 text-center">
          <div className="text-[13px] font-semibold text-foreground">No executions yet</div>
          <div className="max-w-sm text-[12px] text-muted-foreground">
            Dispatch a response action to a target agent, or adjust the filters above.
          </div>
          <Button variant="primary" size="sm" onClick={onDispatch}>
            Dispatch action
          </Button>
        </div>
      ) : (
        <Table<ResponseActionOut>
          columns={columns}
          rows={executions}
          rowKey={(row) => String(row.id)}
          onRowClick={(row) => onRowClick(row.id)}
          compact
        />
      )}

      <div className="mt-2 text-[10.5px] text-muted-foreground">Last updated {fmtMaybeIso(refreshState.lastUpdatedAt?.toISOString() ?? null)}</div>
    </Panel>
  );
}
