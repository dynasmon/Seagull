import type { TopologyGroup } from "../../types";

export type GroupTypeMeta = {
  label: string;
  color: string;
  description: string;
};

const GROUP_TYPE_META: Record<string, GroupTypeMeta> = {
  agent: {
    label: "Sensor",
    color: "#22D3EE",
    description: "Assets reported by a Seagull agent on that host",
  },
  subnet: {
    label: "Subnet",
    color: "#2DD4BF",
    description: "Addresses that share an observed CIDR block",
  },
  scope: {
    label: "Scope",
    color: "#94A3B8",
    description: "Addresses grouped by IP classification",
  },
  ip_scope: {
    label: "Scope",
    color: "#94A3B8",
    description: "Addresses grouped by IP classification",
  },
  ungrouped: {
    label: "Unassigned",
    color: "#64748B",
    description: "Nodes with no agent, subnet, or scope evidence yet",
  },
};

const SCOPE_GROUP_META: Record<string, GroupTypeMeta> = {
  "scope:public_internet": {
    label: "Internet",
    color: "#94A3B8",
    description: "Endpoints outside your networks, seen in observed traffic",
  },
  "scope:private_address": {
    label: "Private",
    color: "#4ADE80",
    description: "RFC1918 addresses seen in traffic but not tied to an agent",
  },
  "scope:internal_network": {
    label: "Internal",
    color: "#4ADE80",
    description: "Addresses inside your configured internal CIDRs",
  },
  "scope:link_local": {
    label: "Link-local",
    color: "#A3E635",
    description: "Local-segment addressing, normally not routed",
  },
  "scope:loopback": {
    label: "Loopback",
    color: "#A3E635",
    description: "Traffic that stays on the local host",
  },
  "scope:cgnat": {
    label: "CGNAT",
    color: "#5EEAD4",
    description: "Carrier-grade NAT space between you and the internet",
  },
};

export function groupTypeMeta(groupType: string, groupKey?: string): GroupTypeMeta {
  if (groupKey && SCOPE_GROUP_META[groupKey]) return SCOPE_GROUP_META[groupKey];
  return GROUP_TYPE_META[groupType] ?? GROUP_TYPE_META.ungrouped;
}

export function groupMeta(group: Pick<TopologyGroup, "group_type" | "group_key">): GroupTypeMeta {
  return groupTypeMeta(group.group_type, group.group_key);
}

export function isSensorGroup(group: Pick<TopologyGroup, "group_type">): boolean {
  return group.group_type === "agent";
}
