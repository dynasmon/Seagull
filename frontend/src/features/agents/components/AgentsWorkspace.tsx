import AgentsHeader from "./AgentsHeader";
import AgentsMainLayout from "./AgentsMainLayout";
import AgentEventsWorkbench from "./AgentEventsWorkbench";
import AgentsDrawers from "./AgentsDrawers";
import type { AgentsPageModel } from "../hooks/useAgentsPageModel";
import { DEFAULT_WINDOW_MINUTES, DEFAULT_EVENTS_LIMIT, H_PANEL_TALL } from "../lib/agentUtils";

interface AgentsWorkspaceProps {
  model: AgentsPageModel;
}

export default function AgentsWorkspace({ model }: AgentsWorkspaceProps) {
  const { agents, events, compact, setCompact } = model;

  return (
    <div className="space-y-6">
      <AgentsHeader agents={agents} compact={compact} setCompact={setCompact} />

      <AgentsMainLayout model={model} />

      <AgentEventsWorkbench
        selectedAgentId={agents.selectedAgentId}
        eventsCfg={agents.eventsCfg}
        setEventsCfg={agents.setEventsCfg}
        availableTypes={events.availableTypes}
        topTypes={events.topTypes}
        explorerBaseCount={events.explorerBase.length}
        filteredEvents={events.filteredEvents}
        selectedEvent={agents.selectedEvent}
        onSelectEvent={agents.setSelectedEvent}
        eventsLoading={agents.eventsLoading}
        eventsError={agents.eventsError}
        onReload={agents.reloadSelectedTelemetry}
        defaultWindowMinutes={DEFAULT_WINDOW_MINUTES}
        defaultEventsLimit={DEFAULT_EVENTS_LIMIT}
        ddosMode={events.ddosMode}
        ddosEvents={events.ddosEvents}
        panelHeight={H_PANEL_TALL}
        streamHeight={H_PANEL_TALL}
        compact={compact}
      />

      <AgentsDrawers model={model} />
    </div>
  );
}
