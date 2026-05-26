import AgentDrawer from "./AgentDrawer";
import ResponseActionDrawer from "./ResponseActionDrawer";
import type { AgentsPageModel } from "../hooks/useAgentsPageModel";

interface AgentsDrawersProps {
  model: AgentsPageModel;
}

export default function AgentsDrawers({ model }: AgentsDrawersProps) {
  const { agents, config, actions, user, isAdmin, selectedAgentId, configOpen, closeConfig } = model;

  return (
    <>
      <ResponseActionDrawer
        controller={actions}
        user={user}
        isAdmin={isAdmin}
        agentsSorted={agents.agentsSorted}
      />

      <AgentDrawer
        open={configOpen}
        onClose={closeConfig}
        selectedAgentId={selectedAgentId}
        agent={agents.agent}
        controller={config}
      />
    </>
  );
}
