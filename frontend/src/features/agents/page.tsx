import { useAgentsPageModel } from "./hooks/useAgentsPageModel";
import AgentsEmptySelection from "./components/AgentsEmptySelection";
import AgentsWorkspace from "./components/AgentsWorkspace";

export default function AgentsPage() {
  const model = useAgentsPageModel();

  if (!model.selectedAgentId) {
    return <AgentsEmptySelection model={model} />;
  }

  return <AgentsWorkspace model={model} />;
}
