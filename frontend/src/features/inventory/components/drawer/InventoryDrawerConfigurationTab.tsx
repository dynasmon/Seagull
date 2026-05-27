import { InvestigationSection } from "@/shared/components/investigation";
import { cx } from "@/shared/lib/cx";

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
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Display name</div>
              <input
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                className={cx(
                  "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                  "text-[11px] text-foreground outline-none font-mono",
                  "focus:ring-2 focus:ring-primary/30"
                )}
              />
            </div>
            <div>
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Description</div>
              <input
                value={editDesc}
                onChange={(e) => setEditDesc(e.target.value)}
                className={cx(
                  "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                  "text-[11px] text-foreground outline-none font-mono",
                  "focus:ring-2 focus:ring-primary/30"
                )}
              />
            </div>
            <div>
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Tags (comma)</div>
              <input
                value={editTags}
                onChange={(e) => setEditTags(e.target.value)}
                placeholder="prod, linux, web"
                className={cx(
                  "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                  "text-[11px] text-foreground outline-none font-mono",
                  "placeholder:text-muted-foreground/60 focus:ring-2 focus:ring-primary/30"
                )}
              />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={onToggleAgentState}
                className={cx(
                  "rounded-md border border-border/60 bg-background/40 px-3 py-2",
                  "text-xs font-mono uppercase tracking-widest",
                  drawerAgent.is_revoked ? "text-success" : "text-warning",
                  "hover:bg-muted/15 focus:outline-none focus:ring-2 focus:ring-primary/30"
                )}
              >
                {drawerAgent.is_revoked ? "Enable agent" : "Disable agent"}
              </button>

              <button
                type="button"
                onClick={onSaveMetadata}
                className={cx(
                  "rounded-md border border-border/60 bg-primary/20 px-3 py-2",
                  "text-xs font-mono uppercase tracking-widest text-foreground",
                  "hover:bg-primary/25 focus:outline-none focus:ring-2 focus:ring-primary/30"
                )}
              >
                Save metadata
              </button>
            </div>
          </div>

          <div className="space-y-3">
            <div>
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Agent config (JSON)</div>
              <textarea
                value={editConfig}
                onChange={(e) => setEditConfig(e.target.value)}
                rows={14}
                className={cx(
                  "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                  "text-[11px] text-foreground outline-none font-mono",
                  "focus:ring-2 focus:ring-primary/30"
                )}
              />
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onSaveConfig}
                className={cx(
                  "rounded-md border border-border/60 bg-primary/20 px-3 py-2",
                  "text-xs font-mono uppercase tracking-widest text-foreground",
                  "hover:bg-primary/25 focus:outline-none focus:ring-2 focus:ring-primary/30"
                )}
              >
                Save config
              </button>
              <button
                type="button"
                onClick={onResetConfig}
                className={cx(
                  "rounded-md border border-border/60 bg-background/40 px-3 py-2",
                  "text-xs font-mono uppercase tracking-widest text-muted-foreground",
                  "hover:bg-muted/15 hover:text-foreground",
                  "focus:outline-none focus:ring-2 focus:ring-primary/30"
                )}
              >
                Reset
              </button>
            </div>
          </div>
        </div>

        {editMsg ? <div className="text-[11px] text-muted-foreground font-mono">{editMsg}</div> : null}
      </InvestigationSection>
    </div>
  );
}
