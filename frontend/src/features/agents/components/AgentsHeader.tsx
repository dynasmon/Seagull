import { Button } from "@/shared/components/Button";
import { ToggleSwitch } from "@/shared/components/ToggleSwitch";

import type { AgentsController } from "../hooks/useAgents";
import { fmtDateTime } from "../lib/agentUtils";

interface AgentsHeaderProps {
  agents: AgentsController;
  compact: boolean;
  setCompact: (next: boolean) => void;
  isAdmin: boolean;
  onEnroll: () => void;
}

export default function AgentsHeader({ agents, compact, setCompact, isAdmin, onEnroll }: AgentsHeaderProps) {
  const { selectedAgentId, agent, autoRefresh, setAutoRefresh, lastUpdatedAt, refreshSelectedAgent } = agents;

  return (
    <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
      <div className="space-y-1">
        <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-primary/90">Agents</div>
        <h1 className="text-lg font-semibold tracking-tight">
          <span className="text-muted-foreground">Agent / </span>
          <span>{agent?.display_name || selectedAgentId}</span>
        </h1>
        <div className="font-mono text-[11px] text-muted-foreground/80">id: {selectedAgentId}</div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {isAdmin && (
          <Button variant="primary" size="md" onClick={onEnroll}>
            Enroll agent
          </Button>
        )}
        <Button variant={compact ? "secondary" : "subtle"} size="md" onClick={() => setCompact(!compact)}>
          {compact ? "Compact rows" : "Comfortable rows"}
        </Button>
        <Button variant="subtle" size="md" onClick={() => void refreshSelectedAgent()}>
          Refresh
        </Button>

        <div className="inline-flex h-8 items-center gap-2 rounded-md border border-border bg-card px-3">
          <ToggleSwitch checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} label="Auto refresh" />
        </div>

        <div className="inline-flex h-8 items-center rounded-md border border-border bg-surface-2 px-3 text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
          Shared hot cadence
        </div>

        {lastUpdatedAt && (
          <div className="text-[10.5px] uppercase tracking-[0.1em] text-muted-foreground">
            Updated {fmtDateTime(lastUpdatedAt)}
          </div>
        )}
      </div>
    </div>
  );
}
