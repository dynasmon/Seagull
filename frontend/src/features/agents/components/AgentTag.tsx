import { useAgentsDirectory } from "@/app/providers";
import { cx } from "@/shared/lib/cx";

import {
  AGENT_HEALTH_LABEL,
  agentAddress,
  agentDisplayName,
  agentHealth,
  agentHostname,
  findAgent,
} from "../lib/identity";

const HEALTH_DOT = {
  online: "bg-success",
  offline: "bg-warning",
  disabled: "bg-muted-foreground/55",
} as const;

export default function AgentTag({
  agentId,
  className,
  showDot = true,
}: {
  agentId?: string | null;
  className?: string;
  showDot?: boolean;
}) {
  const { agents } = useAgentsDirectory();
  const id = (agentId || "").trim();

  if (!id) return <span className="text-muted-foreground">-</span>;

  const agent = findAgent(agents, id);
  if (!agent) {
    return <span className={cx("truncate font-mono text-[11.5px]", className)}>{id}</span>;
  }

  const health = agentHealth(agent);
  const title = [id, agentHostname(agent), agentAddress(agent), AGENT_HEALTH_LABEL[health]]
    .filter(Boolean)
    .join(" · ");

  return (
    <span className={cx("inline-flex min-w-0 items-center gap-1.5 align-middle", className)} title={title}>
      {showDot ? (
        <span className={cx("inline-block h-1.5 w-1.5 shrink-0 rounded-full", HEALTH_DOT[health])} aria-hidden="true" />
      ) : null}
      <span className="truncate text-[12px]">{agentDisplayName(agent)}</span>
    </span>
  );
}
