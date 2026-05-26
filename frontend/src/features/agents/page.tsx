import { useAgentsPageModel } from "./hooks/useAgentsPageModel";
import AgentsEmptySelection from "./components/AgentsEmptySelection";
import AgentsWorkspace from "./components/AgentsWorkspace";

export default function AgentsPage() {
  const model = useAgentsPageModel();

  if (!model.selectedAgentId) {
    return <AgentsEmptySelection agents={model.agents} compact={model.compact} />;
  }

  return <AgentsWorkspace model={model} />;
}
