import { Button } from "@/shared/components/Button";
import { ToggleSwitch } from "@/shared/components/ToggleSwitch";

import type { AgentsController } from "../hooks/useAgents";
import { fmtDateTime } from "../lib/agentUtils";

interface AgentsHeaderProps {
  agents: AgentsController;
  compact: boolean;
  setCompact: (next: boolean) => void;
}

export default function AgentsHeader({ agents, compact, setCompact }: AgentsHeaderProps) {
  const { selectedAgentId, agent, autoRefresh, setAutoRefresh, lastUpdatedAt, refreshSelectedAgent } = agents;

  return (
    <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
      <div className="space-y-1">
        <h1 className="text-xl font-semibold flex items-center gap-2">
          <span className="text-muted-foreground font-normal">Agent /</span>
          <span>{agent?.display_name || selectedAgentId}</span>
        </h1>
        <div className="text-sm text-muted-foreground font-mono text-[11px] opacity-70">ID: {selectedAgentId}</div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Button
          variant={compact ? "secondary" : "subtle"}
          size="lg"
          onClick={() => setCompact(!compact)}
        >
          {compact ? "Compact rows" : "Comfortable rows"}
        </Button>
        <Button
          variant="subtle"
          size="lg"
          onClick={() => {
            void refreshSelectedAgent();
          }}
        >
          Refresh
        </Button>

        <div className="border border-border/60 bg-background/40 px-3 py-2 flex items-center gap-3">
          <ToggleSwitch checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} label="Auto refresh" />
        </div>

        <div className="border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest text-muted-foreground">
          Shared hot cadence
        </div>

        {lastUpdatedAt && (
          <div className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">
            Updated {fmtDateTime(lastUpdatedAt)}
          </div>
        )}
      </div>
    </div>
  );
}
