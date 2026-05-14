import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  NetworkTopologyEdgeDetailContent,
  NetworkTopologyNodeDetailContent,
} from "@/features/network_topology/components/NetworkTopologyDetailDrawer";
import type { TopologyEdgeDetail, TopologyNode, TopologyNodeDetail } from "@/features/network_topology/types";

const now = "2026-05-13T12:00:00.000Z";

function node(overrides: Partial<TopologyNode> = {}): TopologyNode {
  return {
    node_key: "topo:host:agent-1:10.0.0.5",
    node_type: "host",
    agent_id: "agent-1",
    label: "host-1",
    ip: "10.0.0.5",
    cidr: null,
    port: null,
    protocol: null,
    severity: "high",
    risk_score: 70,
    confidence: 82,
    is_stale: false,
    event_count: 7,
    alert_count: 1,
    observation_count: 25,
    first_seen_at: now,
    last_seen_at: now,
    updated_at: now,
    metadata: {},
    ...overrides,
  };
}

function nodeDetail(overrides: Partial<TopologyNodeDetail> = {}): TopologyNodeDetail {
  return {
    node: node(),
    observations: [],
    evidence_meta: { limit: 20, total: 0, omitted: 0 },
    evidence_sources: [],
    connected_nodes: [],
    edges: [],
    related_alerts: [],
    related_flows: [],
    related_services: [],
    related_exposure_findings: [],
    related_attack_chain_cases: [],
    ...overrides,
  };
}

function edgeDetail(overrides: Partial<TopologyEdgeDetail> = {}): TopologyEdgeDetail {
  return {
    edge: {
      edge_key: "topo:edge:observed_flow:agent-1:10.0.0.5:10.0.0.1:443",
      source_node_key: "topo:host:agent-1:10.0.0.5",
      target_node_key: "topo:host:agent-1:10.0.0.1",
      edge_type: "observed_flow",
      agent_id: "agent-1",
      weight: 1.0,
      confidence: 75,
      severity: "medium",
      port: 443,
      protocol: "tcp",
      event_count: 12,
      alert_count: 0,
      first_seen_at: now,
      last_seen_at: now,
      updated_at: now,
      metadata: {},
    },
    observations: [],
    evidence_meta: { limit: 20, total: 0, omitted: 0 },
    evidence_sources: [],
    source_node: node(),
    target_node: node({ node_key: "topo:host:agent-1:10.0.0.1", ip: "10.0.0.1", label: "host-2" }),
    related_alerts: [],
    related_flows: [],
    related_exposure_findings: [],
    related_attack_chain_cases: [],
    application_protocols: [],
    total_bytes: 0,
    ...overrides,
  };
}

describe("NetworkTopologyNodeDetailContent", () => {
  it("renders node label and IP", () => {
    const markup = renderToStaticMarkup(<NetworkTopologyNodeDetailContent detail={nodeDetail()} />);
    expect(markup).toContain("host-1");
    expect(markup).toContain("10.0.0.5");
  });

  it("renders node type badge", () => {
    const markup = renderToStaticMarkup(<NetworkTopologyNodeDetailContent detail={nodeDetail()} />);
    expect(markup.toLowerCase()).toContain("host");
  });

  it("renders severity", () => {
    const markup = renderToStaticMarkup(<NetworkTopologyNodeDetailContent detail={nodeDetail()} />);
    expect(markup.toLowerCase()).toContain("high");
  });

  it("shows stale indicator for stale nodes", () => {
    const detail = nodeDetail({ node: node({ is_stale: true }) });
    const markup = renderToStaticMarkup(<NetworkTopologyNodeDetailContent detail={detail} />);
    expect(markup.toLowerCase()).toContain("stale");
  });

  it("renders event and alert counts", () => {
    const markup = renderToStaticMarkup(<NetworkTopologyNodeDetailContent detail={nodeDetail()} />);
    expect(markup).toContain("7");
    expect(markup).toContain("1");
  });

  it("renders related flows when present", () => {
    const detail = nodeDetail({
      related_flows: [
        {
          id: 42,
          timestamp: now,
          agent_id: "agent-1",
          event_type: "flow",
          src_ip: "10.0.0.5",
          dst_ip: "1.2.3.4",
          src_port: 55000,
          dst_port: 443,
          protocol: "tcp",
          bytes: 1024,
          app_proto: "tls",
        },
      ],
    });
    const markup = renderToStaticMarkup(<NetworkTopologyNodeDetailContent detail={detail} />);
    expect(markup).toContain("10.0.0.5");
    expect(markup).toContain("1.2.3.4");
  });

  it("renders related alerts when present", () => {
    const detail = nodeDetail({
      related_alerts: [
        {
          id: 99,
          created_at: now,
          rule_id: "rule-brute-force",
          severity: "critical",
          status: "open",
          confidence: 90,
          description: "Brute force detected",
          src_ip: "10.0.0.5",
          dst_ip: null,
          dst_port: null,
        },
      ],
    });
    const markup = renderToStaticMarkup(<NetworkTopologyNodeDetailContent detail={detail} />);
    expect(markup).toContain("Brute force detected");
  });
});

describe("NetworkTopologyEdgeDetailContent", () => {
  it("renders edge type", () => {
    const markup = renderToStaticMarkup(<NetworkTopologyEdgeDetailContent detail={edgeDetail()} />);
    expect(markup.toLowerCase()).toContain("flow");
  });

  it("renders source and target node IPs", () => {
    const markup = renderToStaticMarkup(<NetworkTopologyEdgeDetailContent detail={edgeDetail()} />);
    expect(markup).toContain("10.0.0.5");
    expect(markup).toContain("10.0.0.1");
  });

  it("renders port and protocol", () => {
    const markup = renderToStaticMarkup(<NetworkTopologyEdgeDetailContent detail={edgeDetail()} />);
    expect(markup).toContain("443");
    expect(markup.toLowerCase()).toContain("tcp");
  });

  it("renders event count", () => {
    const markup = renderToStaticMarkup(<NetworkTopologyEdgeDetailContent detail={edgeDetail()} />);
    expect(markup).toContain("12");
  });
});
