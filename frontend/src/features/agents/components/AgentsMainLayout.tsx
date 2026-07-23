import ResponseActionMiniWidget from "@/features/response_center/ResponseActionMiniWidget";
import { InlineAlert } from "@/shared/components/InlineAlert";

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
  const { agents, config, telemetry, isAdmin, compact, openConfig } = model;

  return (
    <div className="grid min-w-0 gap-4 xl:grid-cols-12">
      <div className="space-y-4 xl:col-span-4 min-w-0">
        <AgentFleetPanel
          agents={agents.agents}
          selectedAgentId={agents.selectedAgentId}
          onSelectAgent={agents.selectAgent}
          onOpenConfig={openConfig}
          compact={compact}
          showConfigButton
          maxHeight={H_PANEL_TALL}
        />
        <AgentActionsPanel
          agent={agents.agent}
          isAdmin={isAdmin}
          toggleBusy={config.toggleBusy}
          agentError={config.agentError}
          onOpenConfig={openConfig}
          onToggleRevoked={config.onToggleRevoked}
        />
      </div>

      <div className="space-y-4 xl:col-span-8 min-w-0">
        <AgentAtGlancePanel
          topStats={telemetry.topStats}
          eventsRate={telemetry.eventsRate}
          alerts60m={telemetry.alerts60m}
          lastEventAge={telemetry.lastEventAge}
          disabled={Boolean(agents.selectedAgentRow?.is_revoked)}
        />

        <ResponseActionMiniWidget agentId={agents.selectedAgentId || null} enabled={isAdmin} />

        {agents.snapshotError && (
          <InlineAlert tone="danger" className="text-xs">
            Overview: {agents.snapshotError}
          </InlineAlert>
        )}

        <AgentTelemetrySnapshot height={H_PANEL_MD} charts={telemetry.charts} />
      </div>
    </div>
  );
}
