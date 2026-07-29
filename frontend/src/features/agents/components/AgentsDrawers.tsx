import AgentDrawer from "./AgentDrawer";
import AgentEnrollDrawer from "./AgentEnrollDrawer";
import type { AgentsPageModel } from "../hooks/useAgentsPageModel";

interface AgentsDrawersProps {
  model: AgentsPageModel;
}

export default function AgentsDrawers({ model }: AgentsDrawersProps) {
  const {
    agents,
    config,
    selectedAgentId,
    configOpen,
    closeConfig,
    enrollment,
    enrollOpen,
    closeEnroll,
    isAdmin,
  } = model;

  return (
    <>
      <AgentDrawer
        open={configOpen}
        onClose={closeConfig}
        selectedAgentId={selectedAgentId}
        agent={agents.agent}
        controller={config}
      />
      <AgentEnrollDrawer open={enrollOpen} onClose={closeEnroll} isAdmin={isAdmin} controller={enrollment} />
    </>
  );
}
