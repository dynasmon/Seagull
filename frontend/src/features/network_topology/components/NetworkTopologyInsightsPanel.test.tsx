import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { TopologyInsight, TopologyVisibility } from "../types";
import { NetworkTopologyInsightsPanel } from "./NetworkTopologyInsightsPanel";

function makeInsight(overrides: Partial<TopologyInsight>): TopologyInsight {
  return {
    id: "test_insight",
    group: "normal_activity",
    severity: "ok",
    title: "Test insight",
    detail: "Test detail",
    count: null,
    ...overrides,
  };
}

function makeVisibility(overrides: Partial<TopologyVisibility> = {}): TopologyVisibility {
  return {
    inventory_coverage: 1.0,
    flow_coverage: true,
    alert_coverage: false,
    protocol_coverage: false,
    exposure_coverage: false,
    last_inventory_at: null,
    last_event_at: null,
    last_alert_at: null,
    known_limitations: [],
    ...overrides,
  };
}

describe("NetworkTopologyInsightsPanel", () => {
  it("renders loading skeleton when loading=true", () => {
    const { container } = render(
      <NetworkTopologyInsightsPanel insights={[]} visibility={null} loading={true} />,
    );
    expect(container.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
  });

  it("renders needs_attention group when attention items are present", () => {
    const insight = makeInsight({
      id: "nodes_with_alerts",
      group: "needs_attention",
      severity: "high",
      title: "3 hosts with active alerts",
      count: 3,
    });
    render(<NetworkTopologyInsightsPanel insights={[insight]} visibility={null} />);
    expect(screen.getByText("Needs Attention")).toBeInTheDocument();
    expect(screen.getByText("3 hosts with active alerts")).toBeInTheDocument();
  });

  it("renders exposure findings insight in needs_attention group", () => {
    const insight = makeInsight({
      id: "nodes_with_exposure_findings",
      group: "needs_attention",
      severity: "medium",
      title: "2 hosts with exposure findings",
      count: 2,
    });
    render(<NetworkTopologyInsightsPanel insights={[insight]} visibility={null} />);
    expect(screen.getByText("2 hosts with exposure findings")).toBeInTheDocument();
  });

  it("renders isolated_nodes insight in visibility_gaps group", () => {
    const insight = makeInsight({
      id: "isolated_nodes",
      group: "visibility_gaps",
      severity: "info",
      title: "4 isolated nodes with no connections",
      count: 4,
    });
    render(<NetworkTopologyInsightsPanel insights={[insight]} visibility={null} />);
    expect(screen.getByText("Visibility Gaps")).toBeInTheDocument();
    expect(screen.getByText("4 isolated nodes with no connections")).toBeInTheDocument();
  });

  it("renders normal_activity group", () => {
    const insight = makeInsight({
      id: "internal_flows",
      group: "normal_activity",
      severity: "ok",
      title: "100 internal-to-internal flows",
      count: 100,
    });
    render(<NetworkTopologyInsightsPanel insights={[insight]} visibility={null} />);
    expect(screen.getByText("Normal Activity")).toBeInTheDocument();
    expect(screen.getByText("100 internal-to-internal flows")).toBeInTheDocument();
  });

  it("shows count badge when count is non-zero", () => {
    const insight = makeInsight({ id: "public_to_internal", count: 7, title: "7 inbound flows" });
    render(<NetworkTopologyInsightsPanel insights={[insight]} visibility={null} />);
    expect(screen.getByText("7")).toBeInTheDocument();
  });

  it("hides count badge when count is null", () => {
    const insight = makeInsight({ count: null, title: "No count insight" });
    render(<NetworkTopologyInsightsPanel insights={[insight]} visibility={null} />);
    expect(screen.queryByText(/^\d+$/)).toBeNull();
  });

  it("renders all three groups when all are present", () => {
    const insights = [
      makeInsight({ id: "a", group: "needs_attention", severity: "high", title: "Attention item" }),
      makeInsight({ id: "b", group: "normal_activity", severity: "ok", title: "Normal item" }),
      makeInsight({ id: "c", group: "visibility_gaps", severity: "info", title: "Gap item" }),
    ];
    render(<NetworkTopologyInsightsPanel insights={insights} visibility={null} />);
    expect(screen.getByText("Needs Attention")).toBeInTheDocument();
    expect(screen.getByText("Normal Activity")).toBeInTheDocument();
    expect(screen.getByText("Visibility Gaps")).toBeInTheDocument();
  });

  it("renders known_limitations when visibility has them", () => {
    const insight = makeInsight({ id: "no_physical_topology", group: "visibility_gaps", severity: "info", title: "No physical topology" });
    const visibility = makeVisibility({
      known_limitations: ["Physical switch topology is unavailable."],
    });
    render(<NetworkTopologyInsightsPanel insights={[insight]} visibility={visibility} />);
    expect(screen.getByText(/Physical switch topology is unavailable/)).toBeInTheDocument();
  });

  it("renders data source pills from visibility object", () => {
    const visibility = makeVisibility({
      inventory_coverage: 0.8,
      flow_coverage: true,
      alert_coverage: false,
    });
    render(<NetworkTopologyInsightsPanel insights={[]} visibility={visibility} />);
    expect(screen.getByText("Agent Inventory")).toBeInTheDocument();
    expect(screen.getByText("Network Flows")).toBeInTheDocument();
    expect(screen.getByText("Alerts")).toBeInTheDocument();
  });

  it("shows inventory coverage percentage", () => {
    const visibility = makeVisibility({ inventory_coverage: 0.75 });
    render(<NetworkTopologyInsightsPanel insights={[]} visibility={visibility} />);
    expect(screen.getByText("75%")).toBeInTheDocument();
  });

  it("renders IP address types glossary", () => {
    render(<NetworkTopologyInsightsPanel insights={[]} visibility={null} />);
    expect(screen.getByText("IP Address Types")).toBeInTheDocument();
    expect(screen.getByText("Public internet")).toBeInTheDocument();
    expect(screen.getByText("Loopback")).toBeInTheDocument();
    expect(screen.getByText("Docker/container")).toBeInTheDocument();
  });

  it("stale data: renders stale_agents and stale_topology_segments insights", () => {
    const insights = [
      makeInsight({ id: "stale_agents", group: "needs_attention", severity: "medium", title: "2 agents marked stale", count: 2 }),
      makeInsight({ id: "stale_topology_segments", group: "visibility_gaps", severity: "low", title: "5 stale topology nodes", count: 5 }),
    ];
    render(<NetworkTopologyInsightsPanel insights={insights} visibility={null} />);
    expect(screen.getByText("2 agents marked stale")).toBeInTheDocument();
    expect(screen.getByText("5 stale topology nodes")).toBeInTheDocument();
  });

  it("partial data: renders no_flow_data gap when flow coverage is false", () => {
    const insight = makeInsight({
      id: "no_flow_data",
      group: "visibility_gaps",
      severity: "medium",
      title: "No network flow data available",
    });
    const visibility = makeVisibility({ flow_coverage: false });
    render(<NetworkTopologyInsightsPanel insights={[insight]} visibility={visibility} />);
    expect(screen.getByText("No network flow data available")).toBeInTheDocument();
  });
});
