import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import DraftNumberInput from "@/shared/components/DraftNumberInput";

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

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
      {children}
    </div>
  );
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
          <FieldLabel>Agent</FieldLabel>
          <SelectInput
            value={agentScope}
            onChange={(e) => onAgentChange(e.target.value)}
            className="mt-1 font-mono text-[11.5px]"
          >
            <option value="__all">All agents</option>
            {agentsOptions.map((a) => (
              <option key={a.agent_id} value={a.agent_id}>
                {a.display_name ? a.display_name : a.agent_id}
              </option>
            ))}
          </SelectInput>
          <div className="mt-2 font-mono text-[11px] text-muted-foreground">
            Current scope: <span className="text-foreground/90">{scopeLabel}</span>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <FieldLabel>Window (min)</FieldLabel>
            <DraftNumberInput
              value={windowMinutes}
              min={30}
              max={10080}
              fallback={360}
              onCommit={onWindowChange}
              className="ui-input mt-1 font-mono text-[11.5px]"
              title="Lookback window (minutes)"
            />
          </div>

          <div>
            <FieldLabel>Auto-refresh</FieldLabel>
            <div className="mt-1 inline-flex h-9 w-full items-center rounded-md border border-border bg-surface-2 px-3 font-mono text-[11px] text-muted-foreground">
              {refreshIntervalSeconds}s shared fallback
            </div>
          </div>
        </div>

        {error ? (
          <div className="rounded-md border border-danger/45 bg-danger/10 px-3 py-2 text-[11px] text-danger">
            {error}
          </div>
        ) : null}
      </div>
    </Panel>
  );
}
