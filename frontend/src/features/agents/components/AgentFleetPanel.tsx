import type { AgentPublic } from "@/features/agents/types";
import { Button } from "@/shared/components/Button";
import { Panel } from "@/shared/components/Panel";
import { TextInput } from "@/shared/components/TextInput";

import AgentsTable from "./AgentsTable";

export default function AgentFleetPanel({
  agentsFiltered,
  agentsSorted,
  selectedAgentId,
  agentQuery,
  onAgentQueryChange,
  onSelectAgent,
  onOpenConfig,
  compact = true,
  showConfigButton = false,
  height,
}: {
  agentsFiltered: AgentPublic[];
  agentsSorted: AgentPublic[];
  selectedAgentId: string;
  agentQuery: string;
  onAgentQueryChange: (next: string) => void;
  onSelectAgent: (agentId: string) => void;
  onOpenConfig?: () => void;
  compact?: boolean;
  showConfigButton?: boolean;
  height: number;
}) {
  return (
    <Panel
      title="Fleet overview"
      actions={
        <span className="text-[10.5px] text-muted-foreground">
          {agentsFiltered.length}/{agentsSorted.length}
        </span>
      }
      scrollY
      style={{ height }}
    >
      <div className="space-y-3">
        <TextInput
          value={agentQuery}
          onChange={(e) => onAgentQueryChange(e.target.value)}
          placeholder="Search agents (name, id, tags)..."
          className="font-mono text-[11.5px]"
        />

        {showConfigButton && onOpenConfig ? (
          <Button variant="subtle" size="md" onClick={onOpenConfig} className="w-full">
            Configure selected agent
          </Button>
        ) : null}

        <AgentsTable
          agentsFiltered={agentsFiltered}
          selectedAgentId={selectedAgentId}
          compact={compact}
          onSelectAgent={onSelectAgent}
        />
      </div>
    </Panel>
  );
}
