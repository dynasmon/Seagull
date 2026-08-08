import { describe, expect, it } from "vitest";

import { countryFlagCode, countryLabelText } from "@/features/threat_map/countryDisplay";

describe("threat map country display", () => {
  it("normalizes ISO alpha-2 codes for the flag asset lookup", () => {
    expect(countryFlagCode("US")).toBe("US");
    expect(countryFlagCode(" br ")).toBe("BR");
    expect(countryFlagCode("XK")).toBe("XK");
  });

  it("rejects values that are not ISO alpha-2 codes", () => {
    expect(countryFlagCode(null)).toBeNull();
    expect(countryFlagCode("USA")).toBeNull();
    expect(countryFlagCode("1A")).toBeNull();
    expect(countryFlagCode("-99")).toBeNull();
  });

  it("keeps the descriptive label as the visible text", () => {
    expect(countryLabelText("NL")).toBe("NL");
    expect(countryLabelText("FR", "France")).toBe("France");
    expect(countryLabelText("BR", "Fortaleza · BR")).toBe("Fortaleza · BR");
  });

  it("falls back to the country code when no label is given", () => {
    expect(countryLabelText("de", null)).toBe("DE");
    expect(countryLabelText(null)).toBe("");
  });
});
