import { useCallback, useMemo } from "react";
import { EuiComboBox, EuiHighlight } from "@elastic/eui";
import type { EuiComboBoxOptionMatcher, EuiComboBoxOptionOption } from "@elastic/eui";

import { useAgentsDirectory } from "@/app/providers";
import { cx } from "@/shared/lib/cx";

import type { AgentPublic } from "../types";
import {
  AGENT_HEALTH_LABEL,
  agentAddress,
  agentDisplayName,
  agentHealth,
  agentHostname,
  agentSearchText,
  sortAgentsForPicker,
  type AgentHealth,
} from "../lib/identity";

const HEALTH_DOT: Record<AgentHealth, string> = {
  online: "bg-success",
  offline: "bg-warning",
  disabled: "bg-muted-foreground/55",
};

type AgentOption = EuiComboBoxOptionOption<AgentPublic>;

export interface AgentFilterProps {
  value: string;
  onChange: (agentId: string) => void;
  agents?: AgentPublic[];
  label?: string;
  allLabel?: string;
  compressed?: boolean;
  fullWidth?: boolean;
  isDisabled?: boolean;
  className?: string;
}

function optionFor(agent: AgentPublic): AgentOption {
  return {
    key: agent.agent_id,
    label: agentDisplayName(agent),
    value: agent,
  };
}

const matchAgentOption: EuiComboBoxOptionMatcher<AgentPublic> = ({ option, normalizedSearchValue }) => {
  if (!normalizedSearchValue) return true;
  const agent = option.value;
  const haystack = agent ? agentSearchText(agent) : String(option.label || "").toLowerCase();
  return haystack.includes(normalizedSearchValue);
};

function OptionRow({ option, searchValue }: { option: AgentOption; searchValue: string }) {
  const agent = option.value;
  if (!agent) {
    return <span className="font-mono text-[11.5px]">{option.label}</span>;
  }

  const health = agentHealth(agent);
  const address = agentAddress(agent);
  const hostname = agentHostname(agent);
  const identity = [agent.agent_id, hostname && hostname !== option.label ? hostname : ""].filter(Boolean).join(" · ");

  return (
    <span className="flex min-w-0 flex-1 items-center gap-2">
      <span
        className={cx("inline-block h-1.5 w-1.5 shrink-0 rounded-full", HEALTH_DOT[health])}
        title={AGENT_HEALTH_LABEL[health]}
        aria-hidden="true"
      />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[12.5px] font-medium">
          <EuiHighlight search={searchValue}>{String(option.label)}</EuiHighlight>
        </span>
        <span className="block truncate font-mono text-[10.5px] text-muted-foreground">{identity}</span>
      </span>
      {address ? (
        <span className="shrink-0 font-mono text-[10.5px] tabular-nums text-muted-foreground">{address}</span>
      ) : null}
    </span>
  );
}

export default function AgentFilter({
  value,
  onChange,
  agents,
  label = "Agent",
  allLabel = "All agents",
  compressed = true,
  fullWidth = false,
  isDisabled = false,
  className,
}: AgentFilterProps) {
  const catalog = useAgentsDirectory();
  const rows = agents ?? catalog.agents;

  const options = useMemo(() => sortAgentsForPicker(rows).map(optionFor), [rows]);

  const selectedOptions = useMemo<AgentOption[]>(() => {
    const id = (value || "").trim();
    if (!id) return [];
    const known = options.find((option) => option.key === id);
    return known ? [known] : [{ key: id, label: id }];
  }, [options, value]);

  const handleChange = useCallback(
    (selected: AgentOption[]) => onChange(String(selected[0]?.key || "")),
    [onChange]
  );

  return (
    <EuiComboBox
      aria-label={label}
      prepend={label}
      placeholder={allLabel}
      options={options}
      selectedOptions={selectedOptions}
      onChange={handleChange}
      optionMatcher={matchAgentOption}
      renderOption={(option, searchValue) => <OptionRow option={option} searchValue={searchValue} />}
      singleSelection={{ asPlainText: true }}
      isDisabled={isDisabled}
      isLoading={catalog.isLoading && rows.length === 0}
      compressed={compressed}
      fullWidth={fullWidth}
      rowHeight={44}
      className={cx("seagullAgentFilter", className)}
    />
  );
}
