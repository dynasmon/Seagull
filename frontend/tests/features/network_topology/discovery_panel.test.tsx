import { renderToStaticMarkup } from "react-dom/server";
import type { ComponentProps } from "react";
import { describe, expect, it } from "vitest";

import { NetworkTopologyDiscoveryPanel } from "@/features/network_topology/components/panels/NetworkTopologyDiscoveryPanel";

function renderPanel(overrides: Partial<ComponentProps<typeof NetworkTopologyDiscoveryPanel>> = {}) {
  return renderToStaticMarkup(
    <NetworkTopologyDiscoveryPanel
      isAdmin={true}
      selectedAgentId="agent-1"
      mode="passive_only"
      allowedCidrs={[]}
      lastRunAt={null}
      discoveredHosts={[]}
      observedHosts={[]}
      lastError={null}
      warnings={[]}
      confirmationText=""
      busy={false}
      latestAction={null}
      onSelectAgent={() => {}}
      onConfirmationTextChange={() => {}}
      onTrigger={() => {}}
      {...overrides}
    />,
  );
}

describe("NetworkTopologyDiscoveryPanel", () => {
  it("defaults to passive-only language", () => {
    const html = renderPanel();
    expect(html).toContain("Passive only");
    expect(html).toContain("Auto: private local CIDRs only");
  });

  it("shows bounded active state and discovered hosts", () => {
    const html = renderPanel({
      mode: "active_enabled",
      allowedCidrs: ["10.0.0.0/24"],
      discoveredHosts: ["10.0.0.20"],
      observedHosts: ["10.0.0.1", "10.0.0.20"],
      confirmationText: "DISCOVER",
    });
    expect(html).toContain("Active enabled");
    expect(html).toContain("10.0.0.0/24");
    expect(html).toContain("10.0.0.20");
    expect(html).toContain("Request discovery");
  });
});
