import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";
import Drawer from "@/shared/components/Drawer";
import { Panel } from "@/shared/components/Panel";
import { StatusPill } from "@/shared/components/StatusPill";
import { TextInput } from "@/shared/components/TextInput";
import { TextArea } from "@/shared/components/TextArea";

import { Dot, FieldLabel } from "./AgentsPageShared";
import AgentConfigPanel from "./AgentConfigPanel";
import type { AgentDetail } from "../types";
import { isOnline, fmtLastSeen } from "../lib/agentUtils";
import type { AgentConfigController } from "../hooks/useAgentConfig";

interface AgentDrawerProps {
  open: boolean;
  onClose: () => void;
  selectedAgentId: string;
  agent: AgentDetail | null;
  controller: AgentConfigController;
}

export default function AgentDrawer({ open, onClose, selectedAgentId, agent, controller }: AgentDrawerProps) {
  const {
    agentError,
    draftName,
    setDraftName,
    draftDesc,
    setDraftDesc,
    draftTags,
    setDraftTags,
    draftMetaText,
    setDraftMetaText,
    saveBusy,
    canSaveAgent,
    toggleBusy,
    onSaveAgent,
    onToggleRevoked,
    configObj,
    configText,
    setConfigText,
    configParseError,
    ddosDraft,
    timingKeys,
    configBusy,
    onConfigTextChange,
    onUpdateTiming,
    onApplyDdosConfig,
    onApplyConfig,
    setDdosDraft,
  } = controller;

  const statusVariant = agent
    ? agent.is_revoked
      ? "neutral"
      : isOnline(agent.last_seen_at)
        ? "active"
        : "warning"
    : "neutral";
  const statusLabel = agent
    ? agent.is_revoked
      ? "Disabled"
      : isOnline(agent.last_seen_at)
        ? "Online"
        : "Offline"
    : "—";

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={`Agent settings • ${agent?.display_name || selectedAgentId}`}
      description="Identity + configuration. Capture-module tuning is applied on next agent restart."
      widthClassName="w-[1200px]"
      headerLabel="Agent settings"
    >
      {!agent ? (
        <EmptyState title="Agent not loaded" hint="Try refresh or check API connectivity." />
      ) : (
        <div className="space-y-5">
          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="Identity">
              <div className="space-y-3">
                <div>
                  <FieldLabel>Display name</FieldLabel>
                  <TextInput
                    className="mt-1 font-mono text-[11.5px]"
                    value={draftName}
                    onChange={(e) => setDraftName(e.target.value)}
                    placeholder="e.g., Web Server - PROD"
                    disabled={saveBusy}
                  />
                </div>

                <div>
                  <FieldLabel>Description</FieldLabel>
                  <TextInput
                    className="mt-1 font-mono text-[11.5px]"
                    value={draftDesc}
                    onChange={(e) => setDraftDesc(e.target.value)}
                    placeholder="Short context about what this agent protects"
                    disabled={saveBusy}
                  />
                </div>

                <div>
                  <FieldLabel>Tags</FieldLabel>
                  <TextInput
                    className="mt-1 font-mono text-[11.5px]"
                    value={draftTags}
                    onChange={(e) => setDraftTags(e.target.value)}
                    placeholder="prod, web, ssh, dmz"
                    disabled={saveBusy}
                  />
                  <div className="mt-1 text-[11px] text-muted-foreground">Comma-separated.</div>
                </div>

                <div>
                  <FieldLabel>Metadata (JSON)</FieldLabel>
                  <TextArea
                    className="mt-1 font-mono text-[11.5px]"
                    rows={6}
                    value={draftMetaText}
                    onChange={(e) => setDraftMetaText(e.target.value)}
                    disabled={saveBusy}
                  />
                </div>

                <div className="flex items-center gap-2 pt-1">
                  <Button variant="primary" size="md" onClick={onSaveAgent} disabled={!canSaveAgent || saveBusy}>
                    {saveBusy ? "Saving…" : "Save"}
                  </Button>
                </div>
              </div>
            </Panel>

            <Panel
              title="State"
              actions={
                <StatusPill variant={statusVariant} withDot>
                  {statusLabel}
                </StatusPill>
              }
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 space-y-1">
                    <FieldLabel>Agent</FieldLabel>
                    <div className="truncate text-[13px] font-semibold text-foreground">
                      {agent.display_name || agent.agent_id}
                    </div>
                    <div className="truncate font-mono text-[10.5px] text-muted-foreground">{agent.agent_id}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Dot state={agent.is_revoked ? "disabled" : isOnline(agent.last_seen_at) ? "online" : "offline"} />
                    <div className="whitespace-nowrap font-mono text-[10.5px] text-muted-foreground">
                      {fmtLastSeen(agent.last_seen_at)}
                    </div>
                  </div>
                </div>

                <div className="rounded-md border border-border bg-surface-2/50 p-3">
                  <FieldLabel>Actions</FieldLabel>
                  <div className="mt-2 flex flex-col gap-2">
                    <Button
                      variant={agent.is_revoked ? "success" : "danger"}
                      size="md"
                      onClick={onToggleRevoked}
                      disabled={toggleBusy}
                      className="w-full"
                    >
                      {toggleBusy ? "Working…" : agent.is_revoked ? "Enable agent" : "Disable agent"}
                    </Button>
                  </div>
                </div>

                {agentError && <div className="text-[11px] text-danger">{agentError}</div>}
              </div>
            </Panel>
          </div>

          <AgentConfigPanel
            configObj={configObj}
            configText={configText}
            setConfigText={setConfigText}
            configParseError={configParseError}
            ddosDraft={ddosDraft}
            timingKeys={timingKeys}
            configBusy={configBusy}
            onConfigTextChange={onConfigTextChange}
            onUpdateTiming={onUpdateTiming}
            onApplyDdosConfig={onApplyDdosConfig}
            onApplyConfig={onApplyConfig}
            setDdosDraft={setDdosDraft}
          />
        </div>
      )}
    </Drawer>
  );
}
