import type { AgentPublic } from "../types";
import { isOnline } from "./agentUtils";

export type AgentHealth = "online" | "offline" | "disabled";

export const AGENT_HEALTH_RANK: Record<AgentHealth, number> = { online: 0, offline: 1, disabled: 2 };

export const AGENT_HEALTH_LABEL: Record<AgentHealth, string> = {
  online: "Online",
  offline: "Offline",
  disabled: "Disabled",
};

export function agentHealth(agent: AgentPublic): AgentHealth {
  if (agent.is_revoked) return "disabled";
  return isOnline(agent.last_seen_at) ? "online" : "offline";
}

function metadataText(agent: AgentPublic, key: string): string {
  const raw = (agent.metadata || {})[key];
  return typeof raw === "string" ? raw.trim() : "";
}

export function agentHostname(agent: AgentPublic): string {
  return metadataText(agent, "hostname");
}

export function agentProfile(agent: AgentPublic): string {
  return metadataText(agent, "profile");
}

export function agentPlatform(agent: AgentPublic): string {
  const os = metadataText(agent, "os");
  const arch = metadataText(agent, "arch");
  if (os && arch) return `${os}/${arch}`;
  return os || arch;
}

export function agentAddress(agent: AgentPublic): string {
  return (agent.observed_address || "").trim();
}

export function agentDisplayName(agent: AgentPublic): string {
  return (agent.display_name || "").trim() || agentHostname(agent) || agent.agent_id;
}

export function agentIdentityLine(agent: AgentPublic): string {
  const parts = [agent.agent_id];
  const hostname = agentHostname(agent);
  if (hostname && hostname !== agentDisplayName(agent)) parts.push(hostname);
  return parts.join(" · ");
}

export function agentSearchText(agent: AgentPublic): string {
  return [
    agent.agent_id,
    agentDisplayName(agent),
    agentHostname(agent),
    agentAddress(agent),
    agentProfile(agent),
    ...(agent.tags || []),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

export function agentMatchesQuery(agent: AgentPublic, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return agentSearchText(agent).includes(needle);
}

export function findAgent(agents: AgentPublic[], agentId: string): AgentPublic | null {
  const id = (agentId || "").trim();
  if (!id) return null;
  return agents.find((agent) => agent.agent_id === id) || null;
}

export function agentScopeLabel(
  agents: AgentPublic[],
  agentId: string | null | undefined,
  allLabel = "All agents"
): string {
  const id = (agentId || "").trim();
  if (!id) return allLabel;
  const agent = findAgent(agents, id);
  return agent ? agentDisplayName(agent) : id;
}

export function sortAgentsForPicker(agents: AgentPublic[]): AgentPublic[] {
  return [...agents].sort((a, b) => {
    const rank = AGENT_HEALTH_RANK[agentHealth(a)] - AGENT_HEALTH_RANK[agentHealth(b)];
    if (rank !== 0) return rank;
    return agentDisplayName(a).localeCompare(agentDisplayName(b), undefined, { numeric: true });
  });
}
