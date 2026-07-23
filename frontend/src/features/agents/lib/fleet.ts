import type { AgentPublic } from "../types";
import { isOnline, parseIso } from "./agentUtils";

export type FleetHealth = "online" | "offline" | "disabled";

export type FleetStatusFilter = "all" | FleetHealth;

export type FleetSort = "status" | "name" | "last_seen";

export type FleetCounts = Record<FleetStatusFilter, number>;

export const FLEET_STATUS_FILTERS: Array<{ id: FleetStatusFilter; label: string }> = [
  { id: "all", label: "All" },
  { id: "online", label: "Online" },
  { id: "offline", label: "Offline" },
  { id: "disabled", label: "Disabled" },
];

export const FLEET_SORTS: Array<{ value: FleetSort; label: string }> = [
  { value: "status", label: "Status" },
  { value: "name", label: "Name" },
  { value: "last_seen", label: "Last seen" },
];

const HEALTH_RANK: Record<FleetHealth, number> = { online: 0, offline: 1, disabled: 2 };

export function agentHealth(agent: AgentPublic): FleetHealth {
  if (agent.is_revoked) return "disabled";
  return isOnline(agent.last_seen_at) ? "online" : "offline";
}

export function countFleet(agents: AgentPublic[]): FleetCounts {
  const counts: FleetCounts = { all: agents.length, online: 0, offline: 0, disabled: 0 };
  for (const agent of agents) counts[agentHealth(agent)] += 1;
  return counts;
}

export function agentDisplayName(agent: AgentPublic): string {
  return agent.display_name || agent.agent_id;
}

function matchesQuery(agent: AgentPublic, query: string): boolean {
  if (!query) return true;
  if (agent.agent_id.toLowerCase().includes(query)) return true;
  if ((agent.display_name || "").toLowerCase().includes(query)) return true;
  return (agent.tags || []).some((tag) => tag.toLowerCase().includes(query));
}

export function selectFleet(
  agents: AgentPublic[],
  query: string,
  status: FleetStatusFilter,
  sort: FleetSort
): AgentPublic[] {
  const needle = query.trim().toLowerCase();
  const rows = agents.filter(
    (agent) => (status === "all" || agentHealth(agent) === status) && matchesQuery(agent, needle)
  );

  const byName = (a: AgentPublic, b: AgentPublic) =>
    agentDisplayName(a).localeCompare(agentDisplayName(b), undefined, { numeric: true });

  return rows.sort((a, b) => {
    if (sort === "name") return byName(a, b);
    if (sort === "last_seen") {
      const delta = (parseIso(b.last_seen_at) ?? 0) - (parseIso(a.last_seen_at) ?? 0);
      return delta !== 0 ? delta : byName(a, b);
    }
    const rank = HEALTH_RANK[agentHealth(a)] - HEALTH_RANK[agentHealth(b)];
    return rank !== 0 ? rank : byName(a, b);
  });
}
