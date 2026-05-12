import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { TopologyIpScopeBadge } from "@/features/network_topology/components/TopologyIpScopeBadge";

describe("TopologyIpScopeBadge", () => {
  it("renders backend IP scope labels using shared classification labels", () => {
    const markup = renderToStaticMarkup(<TopologyIpScopeBadge scope="public_internet" />);

    expect(markup).toContain("Public");
    expect(markup).toContain('data-ip-scope="public_internet"');
    expect(markup).toContain('data-ip-scope-label="Public"');
  });
});
