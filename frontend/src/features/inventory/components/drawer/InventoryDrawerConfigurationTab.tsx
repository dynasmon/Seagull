import { Button } from "@/shared/components/Button";
import { TextArea } from "@/shared/components/TextArea";
import { TextInput } from "@/shared/components/TextInput";
import { InvestigationSection } from "@/shared/components/investigation";

import type { AgentDetail } from "@/features/agents/types";

interface InventoryDrawerConfigurationTabProps {
  drawerAgent: AgentDetail;
  editName: string;
  setEditName: (v: string) => void;
  editDesc: string;
  setEditDesc: (v: string) => void;
  editTags: string;
  setEditTags: (v: string) => void;
  editConfig: string;
  setEditConfig: (v: string) => void;
  editMsg: string | null;
  onSaveMetadata: () => void;
  onToggleAgentState: () => void;
  onSaveConfig: () => void;
  onResetConfig: () => void;
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{children}</div>
  );
}

export function InventoryDrawerConfigurationTab({
  drawerAgent,
  editName,
  setEditName,
  editDesc,
  setEditDesc,
  editTags,
  setEditTags,
  editConfig,
  setEditConfig,
  editMsg,
  onSaveMetadata,
  onToggleAgentState,
  onSaveConfig,
  onResetConfig,
}: InventoryDrawerConfigurationTabProps) {
  return (
    <div className="space-y-4">
      <InvestigationSection title="Metadata controls" subtitle="Editable identity fields for this endpoint.">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="space-y-3">
            <div>
              <FieldLabel>Display name</FieldLabel>
              <TextInput
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                className="mt-1 font-mono text-[11.5px]"
              />
            </div>
            <div>
              <FieldLabel>Description</FieldLabel>
              <TextInput
                value={editDesc}
                onChange={(e) => setEditDesc(e.target.value)}
                className="mt-1 font-mono text-[11.5px]"
              />
            </div>
            <div>
              <FieldLabel>Tags (comma)</FieldLabel>
              <TextInput
                value={editTags}
                onChange={(e) => setEditTags(e.target.value)}
                placeholder="prod, linux, web"
                className="mt-1 font-mono text-[11.5px]"
              />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button variant={drawerAgent.is_revoked ? "success" : "danger"} size="md" onClick={onToggleAgentState}>
                {drawerAgent.is_revoked ? "Enable agent" : "Disable agent"}
              </Button>

              <Button variant="primary" size="md" onClick={onSaveMetadata}>
                Save metadata
              </Button>
            </div>
          </div>

          <div className="space-y-3">
            <div>
              <FieldLabel>Agent config (JSON)</FieldLabel>
              <TextArea
                value={editConfig}
                onChange={(e) => setEditConfig(e.target.value)}
                rows={14}
                className="mt-1 font-mono text-[11.5px]"
              />
            </div>
            <div className="flex items-center gap-2">
              <Button variant="primary" size="md" onClick={onSaveConfig}>
                Save config
              </Button>
              <Button variant="subtle" size="md" onClick={onResetConfig}>
                Reset
              </Button>
            </div>
          </div>
        </div>

        {editMsg ? <div className="font-mono text-[11px] text-muted-foreground">{editMsg}</div> : null}
      </InvestigationSection>
    </div>
  );
}
