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
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold">Agents</h1>
          <div className="text-sm text-muted-foreground">Select an agent to inspect telemetry and configure settings.</div>
        </div>
        <Button variant="subtle" size="lg" onClick={agents.refresh}>Refresh catalog</Button>
      </div>
      <div className="grid gap-6 xl:grid-cols-12 min-w-0">
        <div className="xl:col-span-4 min-w-0">
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
        <div className="xl:col-span-8 min-w-0">
          <div className="min-h-[60vh] flex flex-col items-center justify-center border border-dashed border-border/60 bg-background/20 rounded-lg">
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
