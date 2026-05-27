import type { InventoryPageModel } from "../hooks/useInventoryPageModel";
import { normAgentId } from "../lib/inventoryParsers";

import { InventoryHeader } from "./InventoryHeader";
import { InventoryDomainTabs } from "./InventoryDomainTabs";
import { InventoryDomainView } from "./InventoryDomainView";
import { InventoryScopePanel } from "./InventoryScopePanel";
import { InventoryKpiPanel } from "./InventoryKpiPanel";
import { InventoryWarningsPanel } from "./InventoryWarningsPanel";
import { InventorySnapshotsPanel } from "./InventorySnapshotsPanel";
import { InventoryDistributionsPanel } from "./InventoryDistributionsPanel";
import { InventoryFleetHealthTable } from "./InventoryFleetHealthTable";
import { InventoryChangesPanel } from "./InventoryChangesPanel";
import { InventoryDrawer } from "./drawer/InventoryDrawer";

interface InventoryWorkspaceProps {
  model: InventoryPageModel;
}

export function InventoryWorkspace({ model }: InventoryWorkspaceProps) {
  const { urlState, overview, derived, drawer, compact, setCompact } = model;
  const { agentScope, domain, windowMinutes, setAgentScope, setDomain, setWindowMinutes, pushUrl } = urlState;

  const refreshIntervalSeconds = Math.round(overview.live.state.profile.fallbackMs / 1000);

  function handleAgentChange(agentId: string) {
    const v = normAgentId(agentId);
    setAgentScope(v);
    pushUrl(v);
  }

  function handleWindowChange(mins: number) {
    setWindowMinutes(mins);
    pushUrl(agentScope, mins);
  }

  function handleDomainChange(next: typeof domain) {
    setDomain(next);
    pushUrl(agentScope, windowMinutes, next);
  }

  const showPivots = domain === "processes" || domain === "network" || domain === "identity" || domain === "services";
  const showTimeSeries = domain === "dashboard" || domain === "system" || domain === "software";
  const showFleet = domain === "dashboard" || domain === "system" || domain === "network" || domain === "identity" || domain === "services";
  const showChanges = domain === "dashboard" || domain === "software" || domain === "processes" || domain === "network" || domain === "services";

  return (
    <div className="space-y-6">
      <InventoryHeader
        compact={compact}
        onToggleCompact={() => setCompact(!compact)}
        lastUpdatedAt={overview.live.state.lastUpdatedAt}
        busy={overview.busy}
        onRefresh={overview.live.refreshNow}
      />

      <InventoryDomainTabs domain={domain} onChange={handleDomainChange} />

      <InventoryDomainView domain={domain} scopeLabel={derived.scopeLabel} windowMinutes={windowMinutes} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <InventoryScopePanel
          agentScope={agentScope}
          agentsOptions={derived.agentsOptions}
          scopeLabel={derived.scopeLabel}
          windowMinutes={windowMinutes}
          refreshIntervalSeconds={refreshIntervalSeconds}
          error={overview.error}
          onAgentChange={handleAgentChange}
          onWindowChange={handleWindowChange}
        />
        <InventoryKpiPanel snapshot={overview.snapshot} busy={overview.busy} />
      </div>

      {showPivots ? (
        <InventoryWarningsPanel
          domain={domain}
          domainWarnings={derived.domainWarnings}
          domainPivotRows={derived.domainPivotRows}
          compact={compact}
          onOpenDrawer={drawer.openDrawer}
        />
      ) : null}

      {showTimeSeries ? (
        <InventorySnapshotsPanel snapshot={overview.snapshot} busy={overview.busy} windowMinutes={windowMinutes} />
      ) : null}

      {showTimeSeries ? (
        <InventoryDistributionsPanel
          snapshot={overview.snapshot}
          osRows={derived.osRows}
          mgrRows={derived.mgrRows}
          busy={overview.busy}
          compact={compact}
          onOpenDrawer={drawer.openDrawer}
        />
      ) : null}

      {showFleet ? (
        <InventoryFleetHealthTable
          snapshot={overview.snapshot}
          fleetRows={derived.fleetRows}
          busy={overview.busy}
          compact={compact}
          onOpenDrawer={drawer.openDrawer}
        />
      ) : null}

      {showChanges ? (
        <InventoryChangesPanel
          snapshot={overview.snapshot}
          changesRows={derived.changesRows}
          warningsRows={derived.warningsRows}
          busy={overview.busy}
          compact={compact}
          onOpenDrawer={drawer.openDrawer}
        />
      ) : null}

      <InventoryDrawer model={model} />
    </div>
  );
}
