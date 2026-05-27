import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import Drawer from "@/shared/components/Drawer";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationMetaStrip,
  InvestigationShell,
  InvestigationTabs,
  copyTextToClipboard,
  safeJson,
} from "@/shared/components/investigation";

import PinToWorkspaceDrawer from "@/features/investigations/PinToWorkspaceDrawer";
import { pinInventorySnapshotToWorkspace } from "@/features/investigations/api";

import type { InventoryPageModel } from "../../hooks/useInventoryPageModel";
import { fmtDateTime } from "../../lib/inventoryFormatters";

import { InventoryDrawerOverviewTab } from "./InventoryDrawerOverviewTab";
import { InventoryDrawerSnapshotTab } from "./InventoryDrawerSnapshotTab";
import { InventoryDrawerHistoryTab } from "./InventoryDrawerHistoryTab";
import { InventoryDrawerPackagesTab } from "./InventoryDrawerPackagesTab";
import { InventoryDrawerConfigurationTab } from "./InventoryDrawerConfigurationTab";

interface InventoryDrawerProps {
  model: InventoryPageModel;
}

export function InventoryDrawer({ model }: InventoryDrawerProps) {
  const { drawer, urlState, compact } = model;
  const { domain, windowMinutes, setSp } = urlState;

  return (
    <>
      <Drawer
        open={drawer.drawerOpen}
        title={drawer.drawerAgentId ? `Agent inventory · ${drawer.drawerAgentId}` : "Agent inventory"}
        description="Investigation-first inventory context with configuration controls."
        onClose={drawer.closeDrawer}
        widthClassName="w-[1140px]"
        headerLabel="Inventory"
      >
        <InvestigationShell>
          {drawer.drawerBusy ? <Loading label="Loading agent..." /> : null}

          {drawer.drawerErr ? (
            <div className="rounded-md border border-danger/50 bg-danger/10 px-4 py-3 text-sm text-danger">
              {drawer.drawerErr}
            </div>
          ) : null}

          {drawer.drawerAgent ? (
            <>
              <InvestigationMetaStrip
                items={[
                  { label: "Agent", value: drawer.drawerAgent.display_name || drawer.drawerAgent.agent_id, variant: "info" },
                  { label: "Agent ID", value: drawer.drawerAgent.agent_id },
                  { label: "Last seen", value: fmtDateTime(drawer.drawerAgent.last_seen_at) },
                  {
                    label: "State",
                    value: drawer.drawerAgent.is_revoked ? "disabled" : "active",
                    variant: drawer.drawerAgent.is_revoked ? "neutral" : "low",
                  },
                  { label: "Latest snapshot", value: drawer.drawerLatest ? fmtDateTime(drawer.drawerLatest.collected_at) : "none" },
                ]}
              />

              <InvestigationActionBar>
                <InvestigationActionButton
                  onClick={() => {
                    if (!drawer.drawerLatest) return;
                    drawer.setPinSnapshotId(drawer.drawerLatest.id);
                  }}
                  disabled={!drawer.drawerLatest}
                  tone="primary"
                >
                  Pin latest snapshot
                </InvestigationActionButton>
                <InvestigationActionButton
                  onClick={async () => {
                    const payload = {
                      agent: drawer.drawerAgent,
                      latest_snapshot: drawer.drawerLatest,
                      recent_history: drawer.drawerHistory.slice(0, 20),
                    };
                    const ok = await copyTextToClipboard(safeJson(payload));
                    drawer.setDrawerCopied(ok ? "ok" : "fail");
                    window.setTimeout(() => drawer.setDrawerCopied(null), 1200);
                  }}
                >
                  {drawer.drawerCopied === "ok" ? "Copied" : drawer.drawerCopied === "fail" ? "Copy failed" : "Copy context JSON"}
                </InvestigationActionButton>
                <InvestigationActionButton
                  onClick={() => {
                    const next = new URLSearchParams();
                    next.set("agent_id", drawer.drawerAgent!.agent_id);
                    next.set("window_minutes", String(windowMinutes));
                    if (domain !== "dashboard") next.set("view", domain);
                    setSp(next, { replace: false });
                  }}
                >
                  Scope inventory view
                </InvestigationActionButton>
              </InvestigationActionBar>

              <InvestigationTabs
                value={drawer.drawerTab}
                onChange={drawer.setDrawerTab}
                tabs={[
                  { key: "overview", label: "Dashboard" },
                  { key: "snapshot", label: "System" },
                  { key: "history", label: "Software timeline" },
                  { key: "packages", label: "Software packages" },
                  { key: "configuration", label: "Identity & controls" },
                ]}
              />

              {drawer.drawerTab === "overview" ? (
                <InventoryDrawerOverviewTab drawerAgent={drawer.drawerAgent} drawerLatest={drawer.drawerLatest} />
              ) : null}

              {drawer.drawerTab === "snapshot" ? (
                <InventoryDrawerSnapshotTab drawerLatest={drawer.drawerLatest} />
              ) : null}

              {drawer.drawerTab === "history" ? (
                <InventoryDrawerHistoryTab
                  drawerHistory={drawer.drawerHistory}
                  focusedSnapshotId={drawer.focusedSnapshotId}
                  setFocusedSnapshotId={drawer.setFocusedSnapshotId}
                  setPinSnapshotId={drawer.setPinSnapshotId}
                  compact={compact}
                />
              ) : null}

              {drawer.drawerTab === "packages" ? (
                <InventoryDrawerPackagesTab
                  drawerLatest={drawer.drawerLatest}
                  pkgQuery={drawer.pkgQuery}
                  setPkgQuery={drawer.setPkgQuery}
                  compact={compact}
                />
              ) : null}

              {drawer.drawerTab === "configuration" ? (
                <InventoryDrawerConfigurationTab
                  drawerAgent={drawer.drawerAgent}
                  editName={drawer.editName}
                  setEditName={drawer.setEditName}
                  editDesc={drawer.editDesc}
                  setEditDesc={drawer.setEditDesc}
                  editTags={drawer.editTags}
                  setEditTags={drawer.setEditTags}
                  editConfig={drawer.editConfig}
                  setEditConfig={drawer.setEditConfig}
                  editMsg={drawer.editMsg}
                  onSaveMetadata={drawer.saveMetadata}
                  onToggleAgentState={drawer.toggleAgentState}
                  onSaveConfig={drawer.saveConfig}
                  onResetConfig={drawer.resetConfig}
                />
              ) : null}
            </>
          ) : (
            !drawer.drawerBusy && <EmptyState title="No agent selected" hint="Open an agent from the inventory tables." />
          )}
        </InvestigationShell>
      </Drawer>

      {drawer.pinSnapshotId ? (
        <PinToWorkspaceDrawer
          open={Boolean(drawer.pinSnapshotId)}
          onClose={() => drawer.setPinSnapshotId(null)}
          title={`inventory snapshot #${drawer.pinSnapshotId}`}
          defaultWorkspaceTitle={`Inventory investigation · ${drawer.drawerAgentId || "agent"}`}
          workspaceDefaults={{ primary_agent_id: drawer.drawerAgentId || undefined }}
          onPin={(workspaceId, options) =>
            pinInventorySnapshotToWorkspace(workspaceId, drawer.pinSnapshotId!, {
              ...options,
              source_module: "inventory",
            })
          }
        />
      ) : null}
    </>
  );
}
