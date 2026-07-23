import { memo, useEffect, useMemo, useState } from "react";
import { EuiFieldSearch, EuiFilterButton, EuiFilterGroup, EuiSelect } from "@elastic/eui";

import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";
import { Panel } from "@/shared/components/Panel";
import useDebouncedValue from "@/shared/hooks/useDebouncedValue";

import AgentFleetList from "./AgentFleetList";
import type { AgentPublic } from "../types";
import {
  countFleet,
  selectFleet,
  FLEET_SORTS,
  FLEET_STATUS_FILTERS,
  type FleetSort,
  type FleetStatusFilter,
} from "../lib/fleet";

interface AgentFleetPanelProps {
  agents: AgentPublic[];
  selectedAgentId: string;
  onSelectAgent: (agentId: string) => void;
  onOpenConfig?: () => void;
  compact?: boolean;
  showConfigButton?: boolean;
  maxHeight: number;
}

export default memo(function AgentFleetPanel({
  agents,
  selectedAgentId,
  onSelectAgent,
  onOpenConfig,
  compact = true,
  showConfigButton = false,
  maxHeight,
}: AgentFleetPanelProps) {
  const [draftQuery, setDraftQuery] = useState("");
  const [status, setStatus] = useState<FleetStatusFilter>("all");
  const [sort, setSort] = useState<FleetSort>("status");
  const query = useDebouncedValue(draftQuery, 200);

  const counts = useMemo(() => countFleet(agents), [agents]);
  const rows = useMemo(() => selectFleet(agents, query, status, sort), [agents, query, status, sort]);

  useEffect(() => {
    if (status !== "all" && counts[status] === 0) setStatus("all");
  }, [counts, status]);

  const filtered = query.trim().length > 0 || status !== "all";

  return (
    <Panel
      title="Fleet overview"
      actions={
        <span className="font-mono text-[10.5px] tabular-nums text-muted-foreground">
          {filtered ? `${rows.length} / ${counts.all}` : `${counts.all} agents`}
        </span>
      }
      padded={false}
      className="min-h-0"
      style={{ maxHeight }}
      bodyClassName="flex flex-col"
    >
      <div className="shrink-0 space-y-2 border-b border-border/60 px-3 py-3">
        <div className="flex items-center gap-2">
          <div className="min-w-0 flex-1">
            <EuiFieldSearch
              value={draftQuery}
              onChange={(event) => setDraftQuery(event.target.value)}
              placeholder="Search name, id or tag"
              aria-label="Search agents"
              isClearable
              compressed
              fullWidth
            />
          </div>
          <div className="w-[122px] shrink-0">
            <EuiSelect
              value={sort}
              onChange={(event) => setSort(event.target.value as FleetSort)}
              options={FLEET_SORTS.map((option) => ({ value: option.value, text: `Sort: ${option.label}` }))}
              aria-label="Sort agents"
              compressed
            />
          </div>
        </div>

        <EuiFilterGroup fullWidth>
          {FLEET_STATUS_FILTERS.map((option, index) => (
            <EuiFilterButton
              key={option.id}
              withNext={index < FLEET_STATUS_FILTERS.length - 1}
              hasActiveFilters={status === option.id}
              isDisabled={option.id !== "all" && counts[option.id] === 0}
              numFilters={counts[option.id]}
              onClick={() => setStatus(option.id)}
            >
              {option.label}
            </EuiFilterButton>
          ))}
        </EuiFilterGroup>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {rows.length === 0 ? (
          <div className="px-3 py-6">
            {counts.all === 0 ? (
              <EmptyState title="No agents enrolled" hint="Agents appear here once they check in." />
            ) : (
              <EmptyState title="No matching agents" hint="Adjust the search or status filter." />
            )}
          </div>
        ) : (
          <AgentFleetList
            agents={rows}
            selectedAgentId={selectedAgentId}
            compact={compact}
            onSelectAgent={onSelectAgent}
          />
        )}
      </div>

      {showConfigButton && onOpenConfig ? (
        <div className="shrink-0 border-t border-border/60 px-3 py-2.5">
          <Button
            variant="subtle"
            size="md"
            onClick={onOpenConfig}
            disabled={!selectedAgentId}
            className="w-full"
          >
            Configure selected agent
          </Button>
        </div>
      ) : null}
    </Panel>
  );
});
