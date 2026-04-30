import { useMemo, useState } from "react";
import { useAuth } from "@/features/auth/context";
import { useDataTablePreferences } from "@/shared/hooks/useDataTablePreferences";
import { ToggleSwitch } from "@/shared/components/ToggleSwitch";
import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";

import { isDdosEvent, isDdosEventType } from "@/features/events/lib/ddos";

import { useAgents } from "./hooks/useAgents";
import { useAgentConfig } from "./hooks/useAgentConfig";
import { useAgentActions } from "./hooks/useAgentActions";

import AgentFleetPanel from "./components/AgentFleetPanel";
import AgentActionsPanel from "./components/AgentActionsPanel";
import AgentAtGlancePanel from "./components/AgentAtGlancePanel";
import AgentTelemetrySnapshot from "./components/AgentTelemetrySnapshot";
import AgentEventsWorkbench from "./components/AgentEventsWorkbench";
import AgentDrawer from "./components/AgentDrawer";
import ResponseActionDrawer from "./components/ResponseActionDrawer";

import {
  H_PANEL_MD,
  H_PANEL_TALL,
  DEFAULT_WINDOW_MINUTES,
  DEFAULT_EVENTS_LIMIT,
  fmtDateTime,
  safeNumber,
  buildTopCounts,
  eventMatchesSearch,
} from "./lib/agentUtils";

export default function AgentsPage() {
  const { user } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  const [configOpen, setConfigOpen] = useState(false);

  const agentTablePrefs = useDataTablePreferences({
    storageKey: "nw_agents_tables_v2",
    defaultPageSize: 100,
    minPageSize: 25,
    maxPageSize: 200,
    defaultCompact: true,
  });
  const compactRows = agentTablePrefs.compact;

  const agentsHook = useAgents();
  const configHook = useAgentConfig({
    agent: agentsHook.agent,
    onAgentUpdate: agentsHook.setAgent,
    onRefreshCatalog: agentsHook.refresh,
  });
  const actionsHook = useAgentActions({
    selectedAgentId: agentsHook.selectedAgentId,
    agents: agentsHook.agents,
    agentsSorted: agentsHook.agentsSorted,
    isAdmin,
    user,
    onRefreshCatalog: agentsHook.refresh,
    urlResponseActionTrigger: agentsHook.urlResponseActionTrigger,
  });

  const { snapshot, events, eventsCfg } = agentsHook;

  const charts = useMemo(() => {
    if (!snapshot) {
      return {
        traffic: null as null | { series: string[]; data: Array<Record<string, any>> },
        ssh: null as null | { series: string[]; data: Array<Record<string, any>> },
        ddos: null as null | { series: string[]; data: Array<Record<string, any>> },
        sev: null as null | { series: string[]; data: Array<Record<string, any>> },
      };
    }
    return {
      traffic: snapshot.traffic,
      ssh: snapshot.ssh_failures,
      ddos: snapshot.ddos,
      sev: snapshot.alert_severity,
    };
  }, [snapshot]);

  const eventsRate = useMemo(() => {
    if (!snapshot) return "-";
    return String(snapshot.kpis.events_5m);
  }, [snapshot]);

  const alerts60m = useMemo(() => {
    if (!snapshot) return "-";
    return String(snapshot.kpis.alerts_60m);
  }, [snapshot]);

  const lastEventAge = useMemo(() => {
    if (!snapshot) return "-";
    const v = snapshot.kpis.last_event_age_m;
    if (v === null || v === undefined) return "-";
    if (typeof v !== "number" || !Number.isFinite(v)) return "-";
    return `${Math.round(v)}m`;
  }, [snapshot]);

  const topStats = useMemo(() => {
    const row = agentsHook.selectedAgentRow;
    const last = row?.last_seen_at ? new Date(row.last_seen_at) : null;
    const online = !row?.is_revoked && Boolean(row?.last_seen_at) && Date.now() - new Date(row!.last_seen_at!).getTime() <= 5 * 60_000;
    const status = row?.is_revoked ? "Disabled" : online ? "Online" : "Offline";
    return {
      status,
      online,
      lastSeen: last ? fmtDateTime(last) : "-",
    };
  }, [agentsHook.selectedAgentRow]);

  const windowedEvents = useMemo(() => {
    const mins = Math.max(1, safeNumber(eventsCfg.window_minutes, DEFAULT_WINDOW_MINUTES));
    const cutoff = Date.now() - mins * 60_000;

    return (events || []).filter((e) => {
      const t = new Date(e.timestamp).getTime();
      if (!Number.isFinite(t)) return true;
      return t >= cutoff;
    });
  }, [events, eventsCfg.window_minutes]);

  const availableTypes = useMemo(() => {
    const set = new Set<string>();
    for (const e of windowedEvents) set.add(e.event_type);
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [windowedEvents]);

  const explorerBase = useMemo(() => {
    const q = (eventsCfg.search || "").trim();
    if (!q) return windowedEvents;
    return windowedEvents.filter((e) => eventMatchesSearch(e, q));
  }, [windowedEvents, eventsCfg.search]);

  const topTypes = useMemo(() => {
    return buildTopCounts(explorerBase.map((e) => e.event_type), 12);
  }, [explorerBase]);

  const filteredEvents = useMemo(() => {
    const type = (eventsCfg.event_type || "").trim();
    const q = (eventsCfg.search || "").trim();
    return windowedEvents.filter((e) => {
      if (type && e.event_type !== type) return false;
      if (q && !eventMatchesSearch(e, q)) return false;
      return true;
    });
  }, [windowedEvents, eventsCfg.event_type, eventsCfg.search]);

  const ddosEvents = useMemo(() => filteredEvents.filter((e) => isDdosEvent(e)), [filteredEvents]);
  const ddosMode = ddosEvents.length > 0 || isDdosEventType((eventsCfg.event_type || "").trim());

  const { selectedAgentId } = agentsHook;

  if (!selectedAgentId) {
    return (
      <div className="space-y-6">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-1">
            <h1 className="text-xl font-semibold">Agents</h1>
            <div className="text-sm text-muted-foreground">Select an agent to inspect telemetry and configure settings.</div>
          </div>
          <Button variant="subtle" size="lg" onClick={agentsHook.refresh}>Refresh catalog</Button>
        </div>
        <div className="grid gap-6 xl:grid-cols-12 min-w-0">
          <div className="xl:col-span-4 min-w-0">
            <AgentFleetPanel
              agentsFiltered={agentsHook.agentsFiltered}
              agentsSorted={agentsHook.agentsSorted}
              selectedAgentId={selectedAgentId}
              agentQuery={agentsHook.agentQuery}
              onAgentQueryChange={agentsHook.setAgentQuery}
              onSelectAgent={agentsHook.selectAgent}
              compact={compactRows}
              height={H_PANEL_TALL}
            />
          </div>
          <div className="xl:col-span-8 min-w-0">
            <div className="min-h-[60vh] flex flex-col items-center justify-center border border-dashed border-border/60 bg-background/20 rounded-lg">
              <EmptyState
                title="Select an agent"
                hint="Pick an agent from the list on the left. You can configure it using the drawer once selected."
              />
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <span className="text-muted-foreground font-normal">Agent /</span>
            <span>{agentsHook.agent?.display_name || selectedAgentId}</span>
          </h1>
          <div className="text-sm text-muted-foreground font-mono text-[11px] opacity-70">ID: {selectedAgentId}</div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button
            variant={compactRows ? "secondary" : "subtle"}
            size="lg"
            onClick={() => agentTablePrefs.setCompact(!compactRows)}
          >
            {compactRows ? "Compact rows" : "Comfortable rows"}
          </Button>
          <Button
            variant="subtle"
            size="lg"
            onClick={() => {
              void agentsHook.refreshSelectedAgent();
            }}
          >
            Refresh
          </Button>

          <div className="border border-border/60 bg-background/40 px-3 py-2 flex items-center gap-3">
            <ToggleSwitch checked={agentsHook.autoRefresh} onChange={(e) => agentsHook.setAutoRefresh(e.target.checked)} label="Auto refresh" />
          </div>

          <div className="border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest text-muted-foreground">
            Shared hot cadence
          </div>

          {agentsHook.lastUpdatedAt && (
            <div className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">
              Updated {fmtDateTime(agentsHook.lastUpdatedAt)}
            </div>
          )}
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-12 min-w-0">
        <div className="xl:col-span-4 space-y-6 min-w-0">
          <AgentFleetPanel
            agentsFiltered={agentsHook.agentsFiltered}
            agentsSorted={agentsHook.agentsSorted}
            selectedAgentId={selectedAgentId}
            agentQuery={agentsHook.agentQuery}
            onAgentQueryChange={agentsHook.setAgentQuery}
            onSelectAgent={agentsHook.selectAgent}
            onOpenConfig={() => setConfigOpen(true)}
            compact={compactRows}
            showConfigButton
            height={H_PANEL_TALL}
          />
          <AgentActionsPanel
            agent={agentsHook.agent}
            isAdmin={isAdmin}
            toggleBusy={configHook.toggleBusy}
            agentError={configHook.agentError}
            onOpenConfig={() => setConfigOpen(true)}
            onOpenResponseAction={actionsHook.openResponseActionDrawer}
            onToggleRevoked={configHook.onToggleRevoked}
          />
        </div>

        <div className="xl:col-span-8 space-y-6 min-w-0">
          <AgentAtGlancePanel
            topStats={topStats}
            eventsRate={eventsRate}
            alerts60m={alerts60m}
            lastEventAge={lastEventAge}
            disabled={Boolean(agentsHook.selectedAgentRow?.is_revoked)}
          />

          {agentsHook.snapshotError && (
            <div className="border border-border/60 bg-background/40 p-3 text-[11px] text-danger">
              Overview: {agentsHook.snapshotError}
            </div>
          )}

          <AgentTelemetrySnapshot height={H_PANEL_MD} charts={charts} />
        </div>
      </div>

      <AgentEventsWorkbench
        selectedAgentId={selectedAgentId}
        eventsCfg={eventsCfg}
        setEventsCfg={agentsHook.setEventsCfg}
        availableTypes={availableTypes}
        topTypes={topTypes}
        explorerBaseCount={explorerBase.length}
        filteredEvents={filteredEvents}
        selectedEvent={agentsHook.selectedEvent}
        onSelectEvent={agentsHook.setSelectedEvent}
        eventsLoading={agentsHook.eventsLoading}
        eventsError={agentsHook.eventsError}
        onReload={() => {
          const cfg = agentsHook.eventsCfgRef.current;
          agentsHook.loadSnapshot(selectedAgentId, cfg);
          agentsHook.loadEvents(selectedAgentId, cfg);
        }}
        defaultWindowMinutes={DEFAULT_WINDOW_MINUTES}
        defaultEventsLimit={DEFAULT_EVENTS_LIMIT}
        ddosMode={ddosMode}
        ddosEvents={ddosEvents}
        panelHeight={H_PANEL_TALL}
        streamHeight={H_PANEL_TALL}
        compact={compactRows}
      />

      <ResponseActionDrawer
        responseActionOpen={actionsHook.responseActionOpen}
        closeResponseActionDrawer={actionsHook.closeResponseActionDrawer}
        user={user}
        isAdmin={isAdmin}
        agentsSorted={agentsHook.agentsSorted}
        responseActionAgentId={actionsHook.responseActionAgentId}
        setResponseActionAgentId={actionsHook.setResponseActionAgentId}
        responseActionType={actionsHook.responseActionType}
        setResponseActionType={actionsHook.setResponseActionType}
        responseActionPayloadText={actionsHook.responseActionPayloadText}
        setResponseActionPayloadText={actionsHook.setResponseActionPayloadText}
        responseActionAdvancedOpen={actionsHook.responseActionAdvancedOpen}
        setResponseActionAdvancedOpen={actionsHook.setResponseActionAdvancedOpen}
        responseActionExpiresAt={actionsHook.responseActionExpiresAt}
        setResponseActionExpiresAt={actionsHook.setResponseActionExpiresAt}
        responseActionError={actionsHook.responseActionError}
        setResponseActionError={actionsHook.setResponseActionError}
        responseActionCreated={actionsHook.responseActionCreated}
        setResponseActionCreated={actionsHook.setResponseActionCreated}
        responseActionMode={actionsHook.responseActionMode}
        setResponseActionMode={actionsHook.setResponseActionMode}
        responseActionTab={actionsHook.responseActionTab}
        setResponseActionTab={actionsHook.setResponseActionTab}
        responseActionSelectedId={actionsHook.responseActionSelectedId}
        setResponseActionSelectedId={actionsHook.setResponseActionSelectedId}
        responseActionHistory={actionsHook.responseActionHistory}
        responseActionHistoryLoading={actionsHook.responseActionHistoryLoading}
        responseActionHistoryError={actionsHook.responseActionHistoryError}
        responseActionLive={actionsHook.responseActionLive}
        responseActionLiveLoading={actionsHook.responseActionLiveLoading}
        responseActionLiveError={actionsHook.responseActionLiveError}
        responseActionResult={actionsHook.responseActionResult}
        responseActionResultLoading={actionsHook.responseActionResultLoading}
        responseActionResultError={actionsHook.responseActionResultError}
        responseActionResultRawOpen={actionsHook.responseActionResultRawOpen}
        setResponseActionResultRawOpen={actionsHook.setResponseActionResultRawOpen}
        pinResponseResultId={actionsHook.pinResponseResultId}
        setPinResponseResultId={actionsHook.setPinResponseResultId}
        responseActionBusy={actionsHook.responseActionBusy}
        responseActionDefinition={actionsHook.responseActionDefinition}
        responseActionAgentRow={actionsHook.responseActionAgentRow}
        responseActionPayload={actionsHook.responseActionPayload}
        responseActionPayloadError={actionsHook.responseActionPayloadError}
        responseActionExpiresIso={actionsHook.responseActionExpiresIso}
        responseActionExpirationInvalid={actionsHook.responseActionExpirationInvalid}
        responseActionExpirationInPast={actionsHook.responseActionExpirationInPast}
        responseActionAgentStatus={actionsHook.responseActionAgentStatus}
        responseActionExpiresLabel={actionsHook.responseActionExpiresLabel}
        canSubmitResponseAction={actionsHook.canSubmitResponseAction}
        responseActionSelected={actionsHook.responseActionSelected}
        responseActionLiveView={actionsHook.responseActionLiveView}
        responseActionCanCancel={actionsHook.responseActionCanCancel}
        loadResponseActionHistory={actionsHook.loadResponseActionHistory}
        loadResponseActionLive={actionsHook.loadResponseActionLive}
        loadResponseActionResult={actionsHook.loadResponseActionResult}
        setResponseActionExpiryOffset={actionsHook.setResponseActionExpiryOffset}
        onSelectResponseAction={actionsHook.onSelectResponseAction}
        onCancelSelectedResponseAction={actionsHook.onCancelSelectedResponseAction}
        onCopyResponseResultJson={actionsHook.onCopyResponseResultJson}
        onDownloadResponseResultJson={actionsHook.onDownloadResponseResultJson}
        onSubmitResponseAction={actionsHook.onSubmitResponseAction}
        fmtLastSeen={actionsHook.fmtLastSeen}
      />

      <AgentDrawer
        open={configOpen}
        onClose={() => setConfigOpen(false)}
        selectedAgentId={selectedAgentId}
        agent={agentsHook.agent}
        agentError={configHook.agentError}
        draftName={configHook.draftName}
        setDraftName={configHook.setDraftName}
        draftDesc={configHook.draftDesc}
        setDraftDesc={configHook.setDraftDesc}
        draftTags={configHook.draftTags}
        setDraftTags={configHook.setDraftTags}
        draftMetaText={configHook.draftMetaText}
        setDraftMetaText={configHook.setDraftMetaText}
        saveBusy={configHook.saveBusy}
        canSaveAgent={configHook.canSaveAgent}
        toggleBusy={configHook.toggleBusy}
        onSaveAgent={configHook.onSaveAgent}
        onToggleRevoked={configHook.onToggleRevoked}
        configObj={configHook.configObj}
        configText={configHook.configText}
        setConfigText={configHook.setConfigText}
        configParseError={configHook.configParseError}
        ddosDraft={configHook.ddosDraft}
        timingKeys={configHook.timingKeys}
        configBusy={configHook.configBusy}
        onConfigTextChange={configHook.onConfigTextChange}
        onUpdateTiming={configHook.onUpdateTiming}
        onApplyDdosConfig={configHook.onApplyDdosConfig}
        onApplyConfig={configHook.onApplyConfig}
        setDdosDraft={configHook.setDdosDraft}
      />
    </div>
  );
}
