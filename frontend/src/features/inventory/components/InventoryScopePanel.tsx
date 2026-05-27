import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import { cx } from "@/shared/lib/cx";

import type { AgentPublic } from "@/features/agents/types";

interface InventoryScopePanelProps {
  agentScope: string;
  agentsOptions: AgentPublic[];
  scopeLabel: string;
  windowMinutes: number;
  refreshIntervalSeconds: number;
  error: string | null;
  onAgentChange: (agentId: string) => void;
  onWindowChange: (windowMinutes: number) => void;
}

export function InventoryScopePanel({
  agentScope,
  agentsOptions,
  scopeLabel,
  windowMinutes,
  refreshIntervalSeconds,
  error,
  onAgentChange,
  onWindowChange,
}: InventoryScopePanelProps) {
  return (
    <Panel title="Scope" className="lg:col-span-1">
      <div className="space-y-4">
        <div>
          <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Agent</div>
          <SelectInput
            value={agentScope}
            onChange={(e) => onAgentChange(e.target.value)}
            className="mt-1 w-full text-[11px] font-mono"
          >
            <option value="__all">All agents</option>
            {agentsOptions.map((a) => (
              <option key={a.agent_id} value={a.agent_id}>
                {a.display_name ? a.display_name : a.agent_id}
              </option>
            ))}
          </SelectInput>
          <div className="mt-2 text-[11px] font-mono text-muted-foreground">
            Current scope: <span className="text-foreground/90">{scopeLabel}</span>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Window (min)</div>
            <DraftNumberInput
              value={windowMinutes}
              min={30}
              max={10080}
              fallback={360}
              onCommit={onWindowChange}
              className={cx(
                "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                "text-[11px] text-foreground outline-none font-mono",
                "focus:ring-2 focus:ring-primary/30"
              )}
              title="Lookback window (minutes)"
            />
          </div>

          <div>
            <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Auto-refresh</div>
            <div className="mt-1 rounded-md border border-border/60 bg-background/30 px-3 py-2 text-[11px] font-mono text-muted-foreground">
              {refreshIntervalSeconds}s shared fallback
            </div>
          </div>
        </div>

        {error ? (
          <div className="rounded-md border border-border/60 bg-background/20 px-3 py-2 text-[11px] text-muted-foreground">
            {error}
          </div>
        ) : null}
      </div>
    </Panel>
  );
}
