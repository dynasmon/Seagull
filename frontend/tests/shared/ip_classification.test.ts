import { describe, expect, it } from "vitest";

import {
  classifyIpFallback,
  ipContextFromFlatFields,
  resolveIpClassification,
} from "@/shared/lib/ipClassification";

describe("IP classification display fallback", () => {
  it("classifies common IPv4 display scopes", () => {
    expect(classifyIpFallback("8.8.8.8")).toMatchObject({ label: "Public", scope: "public_internet" });
    expect(classifyIpFallback("10.1.2.3")).toMatchObject({ label: "Private", matchedCidr: "10.0.0.0/8" });
    expect(classifyIpFallback("127.0.0.1")).toMatchObject({ label: "Loopback" });
    expect(classifyIpFallback("169.254.1.10")).toMatchObject({ label: "Link-local" });
    expect(classifyIpFallback("100.64.0.1")).toMatchObject({ label: "CGNAT" });
    expect(classifyIpFallback("198.51.100.10")).toMatchObject({ label: "Reserved/Test" });
  });

  it("classifies IPv6 display scopes", () => {
    expect(classifyIpFallback("2606:4700:4700::1111")).toMatchObject({ label: "Public" });
    expect(classifyIpFallback("fd00::1")).toMatchObject({ label: "Private", matchedCidr: "fc00::/7" });
    expect(classifyIpFallback("fe80::1")).toMatchObject({ label: "Link-local" });
    expect(classifyIpFallback("2001:db8::1")).toMatchObject({ label: "Reserved/Test" });
  });

  it("separates invalid and missing values", () => {
    expect(classifyIpFallback("not-an-ip")).toMatchObject({ label: "Invalid", scope: "invalid" });
    expect(classifyIpFallback("")).toMatchObject({ label: "Unknown", scope: "unknown" });
  });

  it("uses backend context before client-side fallback", () => {
    const result = resolveIpClassification("8.8.8.8", {
      scope: "internal_network",
      label: "Internal",
      matched_cidr: "8.8.8.0/24",
      match_source: "configured_cidr",
      is_internal: true,
      is_public: false,
    });

    expect(result).toMatchObject({
      label: "Internal",
      matchedCidr: "8.8.8.0/24",
      matchSource: "configured_cidr",
      source: "backend",
    });
  });

  it("normalizes flattened SSH context fields", () => {
    const context = ipContextFromFlatFields({
      src_ip: "192.168.1.10",
      src_ip_scope: "private_address",
      src_ip_label: "Private",
      src_is_internal: true,
      src_is_public: false,
    });

    expect(resolveIpClassification("192.168.1.10", context)).toMatchObject({
      label: "Private",
      source: "backend",
      isInternal: true,
    });
  });
});
