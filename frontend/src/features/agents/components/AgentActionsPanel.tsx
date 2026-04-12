import type { AgentDetail } from "@/features/agents/types";
import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";

import { Panel } from "./AgentsPageShared";

export default function AgentActionsPanel({
  agent,
  isAdmin,
  toggleBusy,
  agentError,
  onOpenConfig,
  onOpenResponseAction,
  onToggleRevoked,
}: {
  agent: AgentDetail | null;
  isAdmin: boolean;
  toggleBusy: boolean;
  agentError: string | null;
  onOpenConfig: () => void;
  onOpenResponseAction: () => void;
  onToggleRevoked: () => void;
}) {
  return (
    <Panel title="Response actions" right={agent?.is_revoked ? "Disabled" : "Enabled"} style={{ minHeight: 220 }}>
      {!agent ? (
        <EmptyState title="Agent not loaded" hint="Try refresh or check API connectivity." />
      ) : (
        <div className="flex flex-col gap-4">
          <div className="space-y-1">
            <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Selected</div>
            <div className="text-sm font-mono truncate">{agent.display_name || agent.agent_id}</div>
            <div className="text-[10px] font-mono text-muted-foreground truncate">{agent.agent_id}</div>
          </div>

          <div className="flex flex-col gap-2">
            <button
              type="button"
              onClick={onOpenConfig}
              className={cx(
                "w-full min-w-0 border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest text-center break-words",
                "hover:bg-primary/5"
              )}
            >
              Open configuration
            </button>

            {isAdmin && (
              <button
                type="button"
                onClick={onOpenResponseAction}
                className={cx(
                  "w-full min-w-0 border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest text-center break-words",
                  "hover:bg-primary/5"
                )}
              >
                Queue response action
              </button>
            )}

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

          {agentError && <div className="text-[11px] text-red-400">{agentError}</div>}
        </div>
      )}
    </Panel>
  );
}
