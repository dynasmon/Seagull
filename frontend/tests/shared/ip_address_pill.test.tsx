import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { IpAddressPill } from "@/shared/components/IpAddressPill";

describe("IpAddressPill", () => {
  it("renders the raw IP and fallback classification", () => {
    const markup = renderToStaticMarkup(<IpAddressPill ip="10.0.0.5" compact />);

    expect(markup).toContain("10.0.0.5");
    expect(markup).toContain("Private");
    expect(markup).toContain('data-ip-label="Private"');
  });

  it("renders backend context before fallback classification", () => {
    const markup = renderToStaticMarkup(
      <IpAddressPill
        ip="8.8.8.8"
        ipContext={{
          scope: "internal_network",
          label: "Internal",
          matched_cidr: "8.8.8.0/24",
          match_source: "configured_cidr",
        }}
      />,
    );

    expect(markup).toContain("8.8.8.8");
    expect(markup).toContain("Internal");
    expect(markup).toContain("8.8.8.0/24");
    expect(markup).not.toContain('data-ip-label="Public"');
  });

  it("handles missing IPs", () => {
    const markup = renderToStaticMarkup(<IpAddressPill ip={null} compact />);

    expect(markup).toContain('aria-label="- Unknown"');
    expect(markup).toContain("Unknown");
    expect(markup).toContain('data-ip-scope="unknown"');
  });
});
