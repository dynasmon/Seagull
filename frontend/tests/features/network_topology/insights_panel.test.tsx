import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { NetworkTopologyInsightsPanel } from "@/features/network_topology/components/NetworkTopologyInsightsPanel";
import type { TopologyInsight, TopologyVisibility } from "@/features/network_topology/types";

function insight(overrides: Partial<TopologyInsight> = {}): TopologyInsight {
  return {
    id: "test_insight",
    group: "normal_activity",
    severity: "ok",
    title: "Test insight",
    detail: "Detail text here.",
    count: 5,
    ...overrides,
  };
}

function visibility(overrides: Partial<TopologyVisibility> = {}): TopologyVisibility {
  return {
    inventory_coverage: 0.75,
    flow_coverage: true,
    alert_coverage: true,
    protocol_coverage: false,
    exposure_coverage: false,
    last_inventory_at: "2026-05-13T10:00:00Z",
    last_event_at: "2026-05-13T11:00:00Z",
    last_alert_at: null,
    known_limitations: [
      "Physical switch topology is unavailable.",
      "VLAN segmentation is unknown.",
    ],
    ...overrides,
  };
}

function render(element: React.ReactElement): string {
  return renderToStaticMarkup(element);
}

describe("NetworkTopologyInsightsPanel", () => {
  it("renders loading skeleton when loading=true", () => {
    const html = render(
      <NetworkTopologyInsightsPanel insights={[]} visibility={null} loading={true} />,
    );
    expect(html).toContain("animate-pulse");
    expect(html).not.toContain("Needs Attention");
  });

  it("renders no-content state gracefully with empty insights", () => {
    const html = render(
      <NetworkTopologyInsightsPanel insights={[]} visibility={null} loading={false} />,
    );
    expect(html).toContain("Network Situation");
  });

  it("renders needs_attention group when items present", () => {
    const items = [
      insight({ id: "nodes_with_alerts", group: "needs_attention", severity: "high", title: "3 hosts with alerts", count: 3 }),
    ];
    const html = render(
      <NetworkTopologyInsightsPanel insights={items} visibility={null} loading={false} />,
    );
    expect(html).toContain("Needs Attention");
    expect(html).toContain("3 hosts with alerts");
  });

  it("renders normal_activity group", () => {
    const items = [
      insight({ id: "internal_flows", group: "normal_activity", title: "42 internal-to-internal flows", count: 42 }),
    ];
    const html = render(
      <NetworkTopologyInsightsPanel insights={items} visibility={null} loading={false} />,
    );
    expect(html).toContain("Normal Activity");
    expect(html).toContain("42 internal-to-internal flows");
  });

  it("renders visibility_gaps group", () => {
    const items = [
      insight({ id: "no_physical_topology", group: "visibility_gaps", severity: "info", title: "Physical switch topology not available", count: null }),
    ];
    const html = render(
      <NetworkTopologyInsightsPanel insights={items} visibility={null} loading={false} />,
    );
    expect(html).toContain("Visibility Gaps");
    expect(html).toContain("Physical switch topology not available");
  });

  it("shows count badge when count > 0", () => {
    const items = [insight({ count: 12 })];
    const html = render(
      <NetworkTopologyInsightsPanel insights={items} visibility={null} loading={false} />,
    );
    expect(html).toContain("12");
  });

  it("hides count badge when count is null", () => {
    const items = [insight({ count: null, title: "No count item" })];
    const html = render(
      <NetworkTopologyInsightsPanel insights={items} visibility={null} loading={false} />,
    );
    expect(html).toContain("No count item");
  });

  it("renders data sources section with visibility data", () => {
    const vis = visibility();
    const html = render(
      <NetworkTopologyInsightsPanel insights={[]} visibility={vis} loading={false} />,
    );
    expect(html).toContain("Data Sources");
    expect(html).toContain("Agent Inventory");
    expect(html).toContain("Network Flows");
    expect(html).toContain("Alerts");
  });

  it("shows inventory coverage percentage", () => {
    const vis = visibility({ inventory_coverage: 0.75 });
    const html = render(
      <NetworkTopologyInsightsPanel insights={[]} visibility={vis} loading={false} />,
    );
    expect(html).toContain("75%");
  });

  it("renders known limitations when visibility is provided", () => {
    const vis = visibility({
      known_limitations: ["Physical switch topology is unavailable.", "VLAN segmentation is unknown."],
    });
    const items = [insight({ group: "visibility_gaps" })];
    const html = render(
      <NetworkTopologyInsightsPanel insights={items} visibility={vis} loading={false} />,
    );
    expect(html).toContain("Physical switch topology is unavailable.");
    expect(html).toContain("VLAN segmentation is unknown.");
  });

  it("renders IP scope glossary section", () => {
    const html = render(
      <NetworkTopologyInsightsPanel insights={[]} visibility={null} loading={false} />,
    );
    expect(html).toContain("IP Address Types");
    expect(html).toContain("Public internet");
    expect(html).toContain("Docker/container");
    expect(html).toContain("Loopback");
  });

  it("renders severity badge for high severity item", () => {
    const items = [insight({ severity: "high", title: "High severity item" })];
    const html = render(
      <NetworkTopologyInsightsPanel insights={items} visibility={null} loading={false} />,
    );
    expect(html).toContain("high");
  });

  it("does not render severity badge for ok severity", () => {
    const items = [insight({ severity: "ok", title: "OK item" })];
    const html = render(
      <NetworkTopologyInsightsPanel insights={items} visibility={null} loading={false} />,
    );
    const html_lower = html.toLowerCase();
    const okBadgeIndex = html_lower.indexOf("ok item");
    expect(okBadgeIndex).toBeGreaterThan(-1);
  });

  it("shows stale data insight with correct group", () => {
    const items = [
      insight({ id: "stale_agents", group: "needs_attention", severity: "medium", title: "2 agents marked stale", count: 2 }),
    ];
    const html = render(
      <NetworkTopologyInsightsPanel insights={items} visibility={null} loading={false} />,
    );
    expect(html).toContain("Needs Attention");
    expect(html).toContain("2 agents marked stale");
  });

  it("renders panel title", () => {
    const html = render(
      <NetworkTopologyInsightsPanel insights={[]} visibility={null} loading={false} />,
    );
    expect(html).toContain("Network Situation");
  });
});
