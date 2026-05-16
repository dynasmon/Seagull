import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  NetworkTopologyGroupDetailContent,
  NetworkTopologySubnetDetailContent,
} from "@/features/network_topology/components/NetworkTopologyDetailDrawer";
import TopologyStatusStrip from "@/features/network_topology/components/TopologyStatusStrip";
import TopologyTooltip from "@/features/network_topology/components/TopologyTooltip";
import { DEFAULT_TOPOLOGY_FILTERS, resolveTopologyGraphParams } from "@/features/network_topology/lib/filters";
import {
  canExploreSubnetGroup,
  filtersForSubnetExplore,
  focusedGroupDisplayLabel,
  subnetCidrForGroup,
} from "@/features/network_topology/lib/subnets";
import type {
  TopologyEdge,
  TopologyGroup,
  TopologyNode,
  TopologySubnetDetail,
} from "@/features/network_topology/types";

const now = "2026-05-16T12:00:00.000Z";

function node(overrides: Partial<TopologyNode> = {}): TopologyNode {
  return {
    node_key: "topo:host:10.0.0.5",
    node_type: "host",
    agent_id: null,
    label: "host-1",
    ip: "10.0.0.5",
    cidr: null,
    port: null,
    protocol: null,
    severity: "high",
    risk_score: 72,
    confidence: 88,
    is_stale: false,
    event_count: 8,
    alert_count: 2,
    observation_count: 4,
    first_seen_at: now,
    last_seen_at: now,
    updated_at: now,
    metadata: {},
    ...overrides,
  };
}

function edge(overrides: Partial<TopologyEdge> = {}): TopologyEdge {
  return {
    edge_key: "edge-1",
    source_node_key: "topo:host:10.0.0.5",
    target_node_key: "topo:external_ip:1.1.1.1",
    edge_type: "observed_flow",
    agent_id: null,
    weight: 1,
    confidence: 80,
    severity: "medium",
    port: 443,
    protocol: "tcp",
    event_count: 3,
    alert_count: 1,
    first_seen_at: now,
    last_seen_at: now,
    updated_at: now,
    metadata: {},
    ...overrides,
  };
}

function group(overrides: Partial<TopologyGroup> = {}): TopologyGroup {
  return {
    group_key: "subnet:10.0.0.0/24",
    group_type: "subnet",
    label: "10.0.0.0/24",
    node_keys: ["topo:host:10.0.0.5"],
    node_count: 1,
    alert_count: 2,
    highest_severity: "high",
    risk_score: 72,
    is_stale: false,
    agent_id: null,
    cidr: "10.0.0.0/24",
    gateway_candidate_count: 1,
    ...overrides,
  };
}

function detail(overrides: Partial<TopologySubnetDetail> = {}): TopologySubnetDetail {
  return {
    cidr: "10.0.0.0/24",
    label: "10.0.0.0/24",
    ip_scope: "private_address",
    node_count: 2,
    active_node_count: 2,
    stale_node_count: 0,
    alert_count: 2,
    highest_severity: "high",
    risk_score: 72,
    confidence: 88,
    first_seen: now,
    last_seen: now,
    gateway_candidates: [node({ node_key: "topo:gateway:10.0.0.1", node_type: "gateway", label: "10.0.0.1", ip: "10.0.0.1" })],
    member_nodes: [node()],
    exposed_or_public_nodes: [],
    listening_services: [node({ node_key: "topo:service:10.0.0.5:443", node_type: "service", label: "HTTPS", port: 443, protocol: "tcp" })],
    external_destinations: [node({ node_key: "topo:external_ip:1.1.1.1", node_type: "external_ip", label: "1.1.1.1", ip: "1.1.1.1" })],
    related_edges: [edge()],
    recent_observations: [],
    metadata: {},
    truncation: {
      member_nodes: { limit: 30, total: 2, omitted: 1 },
      gateway_candidates: { limit: 10, total: 1, omitted: 0 },
      exposed_or_public_nodes: { limit: 20, total: 0, omitted: 0 },
      listening_services: { limit: 20, total: 1, omitted: 0 },
      external_destinations: { limit: 20, total: 1, omitted: 0 },
      related_edges: { limit: 50, total: 1, omitted: 0 },
      recent_observations: { limit: 20, total: 0, omitted: 0 },
    },
    ...overrides,
  };
}

describe("subnet drawer behavior", () => {
  it("derives detail CIDRs only for subnet groups so detail loading stays lazy", () => {
    expect(subnetCidrForGroup(group())).toBe("10.0.0.0/24");
    expect(subnetCidrForGroup(group({ cidr: null, group_key: "subnet:10.0.1.0/24" }))).toBe("10.0.1.0/24");
    expect(subnetCidrForGroup(group({ group_key: "agent:a1", group_type: "agent", cidr: null }))).toBeNull();
    expect(canExploreSubnetGroup(group())).toBe(true);
    expect(canExploreSubnetGroup(group({ group_key: "agent:a1", group_type: "agent", cidr: null }))).toBe(false);
  });

  it("keeps the group summary visible when subnet detail is unavailable", () => {
    const markup = renderToStaticMarkup(
      <NetworkTopologyGroupDetailContent
        group={group()}
        memberNodes={[node()]}
        backendDetail={null}
        backendDetailLoading={false}
        backendDetailError={null}
        subnetCidr="10.0.0.0/24"
        subnetDetail={null}
        subnetDetailLoading={false}
        subnetDetailError="failed"
        onExploreInConnection={() => {}}
      />,
    );
    expect(markup).toContain("10.0.0.0/24");
    expect(markup).toContain("Subnet detail unavailable");
  });

  it("renders subnet CIDR, gateway candidates, member nodes, services, and related edges", () => {
    const markup = renderToStaticMarkup(<NetworkTopologySubnetDetailContent detail={detail()} />);
    expect(markup).toContain("10.0.0.0/24");
    expect(markup).toContain("Gateway candidates");
    expect(markup).toContain("10.0.0.1");
    expect(markup).toContain("host-1");
    expect(markup).toContain("HTTPS");
    expect(markup).toContain("Related edges");
    expect(markup).toContain("1 additional member node");
  });

  it("moves subnet exploration into Connection mode while preserving active filters", () => {
    const active = {
      ...DEFAULT_TOPOLOGY_FILTERS,
      agent_id: "agent-1",
      node_types: ["host"],
      has_alerts: true,
      view_mode: "location" as const,
    };
    const explored = filtersForSubnetExplore(active);
    const params = resolveTopologyGraphParams(explored, new Date(now), { focused_group_key: group().group_key });
    expect(explored).toMatchObject({
      agent_id: "agent-1",
      node_types: ["host"],
      has_alerts: true,
      view_mode: "connection",
    });
    expect(params.focused_group_key).toBe("subnet:10.0.0.0/24");
    expect(params.exclusive_focus).toBe(true);
  });

  it("clearing subnet focus preserves the same backend filter envelope", () => {
    const filters = {
      ...DEFAULT_TOPOLOGY_FILTERS,
      agent_id: "agent-1",
      node_types: ["host"],
      severities: ["high"],
      view_mode: "connection" as const,
    };
    const focused = resolveTopologyGraphParams(filters, new Date(now), { focused_group_key: "subnet:10.0.0.0/24" });
    const cleared = resolveTopologyGraphParams(filters, new Date(now));
    expect(cleared.agent_id).toBe(focused.agent_id);
    expect(cleared.node_types).toEqual(focused.node_types);
    expect(cleared.min_confidence).toBe(focused.min_confidence);
    expect(cleared.focused_group_key).toBeUndefined();
    expect(cleared.exclusive_focus).toBeUndefined();
  });
});

describe("subnet tooltip and status integration", () => {
  it("shows CIDR and gateway counts in subnet tooltips when available", () => {
    const markup = renderToStaticMarkup(
      <TopologyTooltip info={{ kind: "group", group: group(), x: 10, y: 10 }} />,
    );
    expect(markup).toContain("CIDR");
    expect(markup).toContain("10.0.0.0/24");
    expect(markup).toContain("Gateways");
  });

  it("shows focused subnet labels in the status strip", () => {
    const focusedLabel = focusedGroupDisplayLabel(group());
    const markup = renderToStaticMarkup(
      <TopologyStatusStrip
        viewMode="connection"
        nodeCount={2}
        edgeCount={1}
        groupCount={1}
        filters={{ ...DEFAULT_TOPOLOGY_FILTERS, view_mode: "connection" }}
        searchQuery=""
        searchTotal={0}
        focusedGroupLabel={focusedLabel}
        graph={null}
        summary={null}
        realtimeStatus="connected"
        isRefreshing={false}
      />,
    );
    expect(focusedLabel).toBe("Subnet 10.0.0.0/24");
    expect(markup).toContain("Subnet 10.0.0.0/24");
  });
});
