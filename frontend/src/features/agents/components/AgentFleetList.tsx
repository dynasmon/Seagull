import { memo, useCallback, useRef } from "react";
import { EuiBadge } from "@elastic/eui";

import { cx } from "@/shared/lib/cx";

import type { AgentPublic } from "../types";
import { AGENT_HEALTH_LABEL, agentAddress, agentDisplayName, agentHealth, type AgentHealth } from "../lib/identity";
import { fmtLastSeen } from "../lib/agentUtils";

const HEALTH_DOT: Record<AgentHealth, string> = {
  online: "bg-success shadow-[0_0_0_3px_rgb(var(--success)/0.18)]",
  offline: "bg-warning",
  disabled: "bg-muted-foreground/55",
};

interface AgentFleetRowProps {
  agent: AgentPublic;
  selected: boolean;
  compact: boolean;
  onSelect: (agentId: string) => void;
}

const AgentFleetRow = memo(function AgentFleetRow({ agent, selected, compact, onSelect }: AgentFleetRowProps) {
  const health = agentHealth(agent);
  const address = agentAddress(agent);
  const tags = agent.tags || [];
  const maxTags = compact ? 2 : 4;
  const overflow = tags.length - maxTags;

  return (
    <li>
      <button
        type="button"
        role="option"
        aria-selected={selected}
        data-agent-id={agent.agent_id}
        onClick={() => onSelect(agent.agent_id)}
        className={cx(
          "group relative flex w-full items-start gap-2.5 border-l-2 pr-3 text-left transition-colors",
          compact ? "py-2 pl-3" : "py-2.5 pl-3.5",
          selected
            ? "border-l-primary bg-primary/[0.08]"
            : "border-l-transparent hover:border-l-border hover:bg-surface-2/70"
        )}
      >
        <span
          className={cx("mt-[5px] inline-block h-2 w-2 shrink-0 rounded-full", HEALTH_DOT[health])}
          aria-hidden="true"
        />

        <span className="min-w-0 flex-1">
          <span className="flex items-baseline justify-between gap-2">
            <span
              className={cx(
                "truncate text-[12.5px] font-semibold",
                selected ? "text-primary" : "text-foreground"
              )}
            >
              {agentDisplayName(agent)}
            </span>
            <span className="shrink-0 whitespace-nowrap text-[10px] tabular-nums text-muted-foreground">
              {fmtLastSeen(agent.last_seen_at)}
            </span>
          </span>

          <span className="mt-0.5 flex items-baseline justify-between gap-2">
            <span className="truncate font-mono text-[10.5px] text-muted-foreground/85">{agent.agent_id}</span>
            {address ? (
              <span
                className="shrink-0 whitespace-nowrap font-mono text-[10px] tabular-nums text-muted-foreground/85"
                title={`Last seen connecting from ${address}`}
              >
                {address}
              </span>
            ) : null}
            <span className="sr-only">{AGENT_HEALTH_LABEL[health]}</span>
          </span>

          {tags.length > 0 ? (
            <span className="mt-1.5 flex flex-wrap gap-1">
              {tags.slice(0, maxTags).map((tag) => (
                <EuiBadge key={tag} color="hollow">
                  {tag}
                </EuiBadge>
              ))}
              {overflow > 0 ? <EuiBadge color="hollow">{`+${overflow}`}</EuiBadge> : null}
            </span>
          ) : null}
        </span>
      </button>
    </li>
  );
});

interface AgentFleetListProps {
  agents: AgentPublic[];
  selectedAgentId: string;
  compact: boolean;
  onSelectAgent: (agentId: string) => void;
}

export default memo(function AgentFleetList({
  agents,
  selectedAgentId,
  compact,
  onSelectAgent,
}: AgentFleetListProps) {
  const listRef = useRef<HTMLUListElement>(null);

  const onKeyDown = useCallback((event: React.KeyboardEvent<HTMLUListElement>) => {
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    const options = Array.from(listRef.current?.querySelectorAll<HTMLButtonElement>("[data-agent-id]") || []);
    if (options.length === 0) return;

    event.preventDefault();
    const current = options.indexOf(document.activeElement as HTMLButtonElement);
    const step = event.key === "ArrowDown" ? 1 : -1;
    const next = current < 0 ? 0 : (current + step + options.length) % options.length;
    options[next].focus();
  }, []);

  return (
    <ul
      ref={listRef}
      role="listbox"
      aria-label="Fleet agents"
      onKeyDown={onKeyDown}
      className="divide-y divide-border/50"
    >
      {agents.map((agent) => (
        <AgentFleetRow
          key={agent.agent_id}
          agent={agent}
          selected={agent.agent_id === selectedAgentId}
          compact={compact}
          onSelect={onSelectAgent}
        />
      ))}
    </ul>
  );
});
