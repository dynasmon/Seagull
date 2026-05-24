import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { TopologyInsight, TopologyVisibility } from "../../types";
import { NetworkTopologyInsightsPanel } from "./NetworkTopologyInsightsPanel";

function insight(overrides: Partial<TopologyInsight> = {}): TopologyInsight {
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

function visibility(overrides: Partial<TopologyVisibility> = {}): TopologyVisibility {
  return {
    inventory_coverage: 1,
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

function render(element: React.ReactElement): string {
  return renderToStaticMarkup(element);
}

describe("NetworkTopologyInsightsPanel", () => {
  it("renders the current loading state", () => {
    const html = render(
      <NetworkTopologyInsightsPanel insights={[]} visibility={null} loading />,
    );
    expect(html).toContain("animate-pulse");
  });

  it("renders attention items and count badges", () => {
    const html = render(
      <NetworkTopologyInsightsPanel
        insights={[
          insight({
            id: "nodes_with_alerts",
            group: "needs_attention",
            severity: "high",
            title: "3 hosts with active alerts",
            count: 3,
          }),
        ]}
        visibility={null}
      />,
    );
    expect(html).toContain("Needs Attention");
    expect(html).toContain("3 hosts with active alerts");
    expect(html).toContain(">3<");
  });

  it("renders known limitations with visibility-gap content", () => {
    const html = render(
      <NetworkTopologyInsightsPanel
        insights={[
          insight({
            id: "no_physical_topology",
            group: "visibility_gaps",
            severity: "info",
            title: "No physical topology",
          }),
        ]}
        visibility={visibility({ known_limitations: ["Physical switch topology is unavailable."] })}
      />,
    );
    expect(html).toContain("Visibility Gaps");
    expect(html).toContain("Physical switch topology is unavailable.");
  });

  it("renders the panel title and IP glossary when there are no insights", () => {
    const html = render(
      <NetworkTopologyInsightsPanel insights={[]} visibility={null} loading={false} />,
    );
    expect(html).toContain("Network Situation");
    expect(html).toContain("IP Address Types");
  });
});
