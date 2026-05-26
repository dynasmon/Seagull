import AgentFleetPanel from "./AgentFleetPanel";
import AgentActionsPanel from "./AgentActionsPanel";
import AgentAtGlancePanel from "./AgentAtGlancePanel";
import AgentTelemetrySnapshot from "./AgentTelemetrySnapshot";
import type { AgentsPageModel } from "../hooks/useAgentsPageModel";
import { H_PANEL_MD, H_PANEL_TALL } from "../lib/agentUtils";

interface AgentsMainLayoutProps {
  model: AgentsPageModel;
}

export default function AgentsMainLayout({ model }: AgentsMainLayoutProps) {
  const { agents, config, actions, telemetry, isAdmin, compact, openConfig } = model;

  return (
    <div className="grid gap-6 xl:grid-cols-12 min-w-0">
      <div className="xl:col-span-4 space-y-6 min-w-0">
        <AgentFleetPanel
          agentsFiltered={agents.agentsFiltered}
          agentsSorted={agents.agentsSorted}
          selectedAgentId={agents.selectedAgentId}
          agentQuery={agents.agentQuery}
          onAgentQueryChange={agents.setAgentQuery}
          onSelectAgent={agents.selectAgent}
          onOpenConfig={openConfig}
          compact={compact}
          showConfigButton
          height={H_PANEL_TALL}
        />
        <AgentActionsPanel
          agent={agents.agent}
          isAdmin={isAdmin}
          toggleBusy={config.toggleBusy}
          agentError={config.agentError}
          onOpenConfig={openConfig}
          onOpenResponseAction={actions.openResponseActionDrawer}
          onToggleRevoked={config.onToggleRevoked}
        />
      </div>

      <div className="xl:col-span-8 space-y-6 min-w-0">
        <AgentAtGlancePanel
          topStats={telemetry.topStats}
          eventsRate={telemetry.eventsRate}
          alerts60m={telemetry.alerts60m}
          lastEventAge={telemetry.lastEventAge}
          disabled={Boolean(agents.selectedAgentRow?.is_revoked)}
        />

        {agents.snapshotError && (
          <div className="border border-border/60 bg-background/40 p-3 text-[11px] text-danger">
            Overview: {agents.snapshotError}
          </div>
        )}

        <AgentTelemetrySnapshot height={H_PANEL_MD} charts={telemetry.charts} />
      </div>
    </div>
  );
}
