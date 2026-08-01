import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";

import AgentFleetPanel from "./AgentFleetPanel";
import AgentsDrawers from "./AgentsDrawers";
import type { AgentsPageModel } from "../hooks/useAgentsPageModel";
import { H_PANEL_TALL } from "../lib/agentUtils";

interface AgentsEmptySelectionProps {
  model: AgentsPageModel;
}

export default function AgentsEmptySelection({ model }: AgentsEmptySelectionProps) {
  const { agents, compact, isAdmin, openEnroll } = model;
  const fleetIsEmpty = agents.agents.length === 0;

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
        <div className="flex flex-wrap items-center gap-2">
          {isAdmin && (
            <Button variant="primary" size="md" onClick={openEnroll}>
              Deploy agent
            </Button>
          )}
          <Button variant="subtle" size="md" onClick={agents.refresh}>
            Refresh catalog
          </Button>
        </div>
      </div>
      <div className="grid min-w-0 gap-4 xl:grid-cols-12">
        <div className="min-w-0 xl:col-span-4">
          <AgentFleetPanel
            agents={agents.agents}
            selectedAgentId={agents.selectedAgentId}
            onSelectAgent={agents.selectAgent}
            compact={compact}
            maxHeight={H_PANEL_TALL}
          />
        </div>
        <div className="min-w-0 xl:col-span-8">
          <div className="flex min-h-[60vh] flex-col items-center justify-center rounded-lg border border-dashed border-border bg-surface-2/30">
            {fleetIsEmpty ? (
              <EmptyState
                title="No endpoint is reporting yet"
                hint="Describe the endpoint here, download the installer this server builds for it, and run a single command on the machine you want to monitor."
                action={
                  isAdmin ? (
                    <Button variant="primary" size="md" onClick={openEnroll}>
                      Deploy the first agent
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <EmptyState
                title="Select an agent"
                hint="Pick an agent from the list on the left. You can configure it using the drawer once selected."
              />
            )}
          </div>
        </div>
      </div>

      <AgentsDrawers model={model} />
    </div>
  );
}
