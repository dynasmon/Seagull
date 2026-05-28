import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";

import AgentFleetPanel from "./AgentFleetPanel";
import type { AgentsController } from "../hooks/useAgents";
import { H_PANEL_TALL } from "../lib/agentUtils";

interface AgentsEmptySelectionProps {
  agents: AgentsController;
  compact: boolean;
}

export default function AgentsEmptySelection({ agents, compact }: AgentsEmptySelectionProps) {
  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div className="space-y-1">
          <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-primary/90">Agents</div>
          <h1 className="text-lg font-semibold tracking-tight">Agents</h1>
          <div className="text-[12px] text-muted-foreground">
            Select an agent to inspect telemetry and configure settings.
          </div>
        </div>
        <Button variant="subtle" size="md" onClick={agents.refresh}>
          Refresh catalog
        </Button>
      </div>
      <div className="grid min-w-0 gap-4 xl:grid-cols-12">
        <div className="min-w-0 xl:col-span-4">
          <AgentFleetPanel
            agentsFiltered={agents.agentsFiltered}
            agentsSorted={agents.agentsSorted}
            selectedAgentId={agents.selectedAgentId}
            agentQuery={agents.agentQuery}
            onAgentQueryChange={agents.setAgentQuery}
            onSelectAgent={agents.selectAgent}
            compact={compact}
            height={H_PANEL_TALL}
          />
        </div>
        <div className="min-w-0 xl:col-span-8">
          <div className="flex min-h-[60vh] flex-col items-center justify-center rounded-lg border border-dashed border-border bg-surface-2/30">
            <EmptyState
              title="Select an agent"
              hint="Pick an agent from the list on the left. You can configure it using the drawer once selected."
            />
          </div>
        </div>
      </div>
    </div>
  );
}
