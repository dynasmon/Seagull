import type { AgentDetail } from "@/features/agents/types";
import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";
import { Panel } from "@/shared/components/Panel";

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
    <Panel
      title="Response actions"
      actions={<span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">{agent?.is_revoked ? "Disabled" : "Enabled"}</span>}
      style={{ minHeight: 220 }}
    >
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
            <Button variant="subtle" size="sm" onClick={onOpenConfig} className="w-full font-mono uppercase tracking-widest">
              Open configuration
            </Button>

            {isAdmin && (
              <Button variant="subtle" size="sm" onClick={onOpenResponseAction} className="w-full font-mono uppercase tracking-widest">
                Queue response action
              </Button>
            )}

            <Button
              variant="subtle"
              size="sm"
              onClick={onToggleRevoked}
              disabled={toggleBusy}
              className="w-full font-mono uppercase tracking-widest"
            >
              {toggleBusy ? "Working..." : agent.is_revoked ? "Enable agent" : "Disable agent"}
            </Button>
          </div>

          {agentError && <div className="text-[11px] text-danger">{agentError}</div>}
        </div>
      )}
    </Panel>
  );
}
