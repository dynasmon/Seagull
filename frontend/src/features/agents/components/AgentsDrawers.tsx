import AgentDrawer from "./AgentDrawer";
import type { AgentsPageModel } from "../hooks/useAgentsPageModel";

interface AgentsDrawersProps {
  model: AgentsPageModel;
}

export default function AgentsDrawers({ model }: AgentsDrawersProps) {
  const { agents, config, selectedAgentId, configOpen, closeConfig } = model;

  return (
    <AgentDrawer
      open={configOpen}
      onClose={closeConfig}
      selectedAgentId={selectedAgentId}
      agent={agents.agent}
      controller={config}
    />
  );
}
