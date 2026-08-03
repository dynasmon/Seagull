import type { AgentPublic } from "../types";
import { parseIso } from "./agentUtils";
import { AGENT_HEALTH_RANK, agentDisplayName, agentHealth, agentMatchesQuery, type AgentHealth } from "./identity";

export type FleetStatusFilter = "all" | AgentHealth;

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

export function countFleet(agents: AgentPublic[]): FleetCounts {
  const counts: FleetCounts = { all: agents.length, online: 0, offline: 0, disabled: 0 };
  for (const agent of agents) counts[agentHealth(agent)] += 1;
  return counts;
}

export function selectFleet(
  agents: AgentPublic[],
  query: string,
  status: FleetStatusFilter,
  sort: FleetSort
): AgentPublic[] {
  const rows = agents.filter(
    (agent) => (status === "all" || agentHealth(agent) === status) && agentMatchesQuery(agent, query)
  );

  const byName = (a: AgentPublic, b: AgentPublic) =>
    agentDisplayName(a).localeCompare(agentDisplayName(b), undefined, { numeric: true });

  return rows.sort((a, b) => {
    if (sort === "name") return byName(a, b);
    if (sort === "last_seen") {
      const delta = (parseIso(b.last_seen_at) ?? 0) - (parseIso(a.last_seen_at) ?? 0);
      return delta !== 0 ? delta : byName(a, b);
    }
    const rank = AGENT_HEALTH_RANK[agentHealth(a)] - AGENT_HEALTH_RANK[agentHealth(b)];
    return rank !== 0 ? rank : byName(a, b);
  });
}
