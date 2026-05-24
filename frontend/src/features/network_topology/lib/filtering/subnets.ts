import type { TopologyFilters, TopologyGroup } from "../../types";

function text(value: unknown): string {
  return String(value ?? "").trim();
}

export function subnetCidrForGroup(group: TopologyGroup | null | undefined): string | null {
  if (!group || group.group_type !== "subnet") return null;
  const direct = text(group.cidr);
  if (direct) return direct;
  const prefix = "subnet:";
  if (!group.group_key.startsWith(prefix)) return null;
  const raw = text(group.group_key.slice(prefix.length));
  if (!raw || raw.startsWith("topo:") || !raw.includes("/")) return null;
  return raw;
}

export function canExploreSubnetGroup(group: TopologyGroup | null | undefined): boolean {
  return Boolean(group && group.group_type === "subnet" && (subnetCidrForGroup(group) || group.group_key.startsWith("subnet:")));
}

export function focusedGroupDisplayLabel(group: TopologyGroup | null | undefined): string | null {
  if (!group) return null;
  const cidr = subnetCidrForGroup(group);
  if (group.group_type === "subnet" && cidr) return `Subnet ${cidr}`;
  return group.label || null;
}

export function filtersForSubnetExplore(filters: TopologyFilters): TopologyFilters {
  return { ...filters, view_mode: "connection" };
}
