import EmptyState from "@/shared/components/EmptyState";
import Drawer from "@/shared/components/Drawer";
import { Panel } from "@/shared/components/Panel";
import { TextInput } from "@/shared/components/TextInput";
import { TextArea } from "@/shared/components/TextArea";
import { cx } from "@/shared/lib/cx";

import { Dot, FieldLabel } from "./AgentsPageShared";
import AgentConfigPanel from "./AgentConfigPanel";
import type { AgentDetail } from "../types";
import type { DdosConfigDraft } from "../lib/agentUtils";
import { isOnline, fmtLastSeen } from "../lib/agentUtils";

interface AgentDrawerProps {
  open: boolean;
  onClose: () => void;
  selectedAgentId: string;
  agent: AgentDetail | null;
  agentError: string | null;
  // from useAgentConfig:
  draftName: string;
  setDraftName: (v: string) => void;
  draftDesc: string;
  setDraftDesc: (v: string) => void;
  draftTags: string;
  setDraftTags: (v: string) => void;
  draftMetaText: string;
  setDraftMetaText: (v: string) => void;
  saveBusy: boolean;
  canSaveAgent: boolean;
  toggleBusy: boolean;
  onSaveAgent: () => Promise<void>;
  onToggleRevoked: () => Promise<void>;
  configObj: Record<string, any>;
  configText: string;
  setConfigText: (v: string) => void;
  configParseError: string | null;
  ddosDraft: DdosConfigDraft;
  timingKeys: string[];
  configBusy: boolean;
  onConfigTextChange: (v: string) => void;
  onUpdateTiming: (key: string, value: number) => void;
  onApplyDdosConfig: () => Promise<void>;
  onApplyConfig: () => Promise<void>;
  setDdosDraft: (updater: (prev: DdosConfigDraft) => DdosConfigDraft) => void;
}

export default function AgentDrawer({
  open,
  onClose,
  selectedAgentId,
  agent,
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
}: AgentDrawerProps) {
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
        <div className="space-y-4">
          <EmptyState title="Agent not loaded" hint="Try refresh or check API connectivity." />
        </div>
      ) : (
        <div className="space-y-6">
          <div className="grid gap-6 lg:grid-cols-2">
            <Panel title="Identity">
              <div className="space-y-4">
                <div>
                  <FieldLabel>Display name</FieldLabel>
                  <TextInput
                    className="mt-1 font-mono text-[11px]"
                    value={draftName}
                    onChange={(e) => setDraftName(e.target.value)}
                    placeholder="e.g., Web Server - PROD"
                    disabled={saveBusy}
                  />
                </div>

                <div>
                  <FieldLabel>Description</FieldLabel>
                  <TextInput
                    className="mt-1 font-mono text-[11px]"
                    value={draftDesc}
                    onChange={(e) => setDraftDesc(e.target.value)}
                    placeholder="Short context about what this agent protects"
                    disabled={saveBusy}
                  />
                </div>

                <div>
                  <FieldLabel>Tags</FieldLabel>
                  <TextInput
                    className="mt-1 font-mono text-[11px]"
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
                    className="mt-1 font-mono text-[11px]"
                    rows={6}
                    value={draftMetaText}
                    onChange={(e) => setDraftMetaText(e.target.value)}
                    disabled={saveBusy}
                  />
                </div>

                <div className="flex flex-wrap items-center gap-3 pt-1">
                  <button
                    type="button"
                    onClick={onSaveAgent}
                    disabled={!canSaveAgent}
                    className={cx(
                      "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                      "hover:bg-primary/5",
                      (!canSaveAgent || saveBusy) && "opacity-60 cursor-not-allowed"
                    )}
                  >
                    {saveBusy ? "Saving..." : "Save"}
                  </button>
                </div>
              </div>
            </Panel>

            <Panel title="State" actions={<span className="text-[10px] font-mono text-muted-foreground">{agent.is_revoked ? "Disabled" : isOnline(agent.last_seen_at) ? "Online" : "Offline"}</span>}>
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="space-y-1 min-w-0">
                    <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Agent</div>
                    <div className="text-sm font-mono truncate">{agent.display_name || agent.agent_id}</div>
                    <div className="text-[10px] font-mono text-muted-foreground truncate">{agent.agent_id}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Dot state={agent.is_revoked ? "disabled" : isOnline(agent.last_seen_at) ? "online" : "offline"} />
                    <div className="text-[10px] font-mono text-muted-foreground whitespace-nowrap">{fmtLastSeen(agent.last_seen_at)}</div>
                  </div>
                </div>

                <div className="border border-border/60 bg-background/20 p-3 rounded-md">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Actions</div>
                  <div className="mt-3 flex flex-col gap-2">
                    <button
                      type="button"
                      onClick={onToggleRevoked}
                      disabled={toggleBusy}
                      className={cx(
                        "w-full min-w-0 border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest text-center break-words",
                        "hover:bg-primary/5",
                        toggleBusy && "opacity-60 cursor-not-allowed"
                      )}
                    >
                      {toggleBusy ? "Working..." : agent.is_revoked ? "Enable agent" : "Disable agent"}
                    </button>
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
