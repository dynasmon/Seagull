import { describe, expect, it } from "vitest";

import type { Alert } from "../types";
import { formatScoreDelta, riskBreakdown } from "./alertPresenters";

function alert(details: Record<string, unknown> | null): Alert {
  return {
    id: 1,
    rule_id: "r1",
    severity: "high",
    src_ip: null,
    dst_ip: null,
    dst_port: null,
    description: "",
    details: details as Record<string, any> | null,
    created_at: "2026-06-04T00:00:00Z",
    status: "open",
  };
}

describe("riskBreakdown", () => {
  it("extracts and coerces score_breakdown factors", () => {
    const factors = riskBreakdown(
      alert({
        score_breakdown: [
          { factor: "base", risk_delta: 78, confidence_delta: 70, detail: "declared risk_score 78" },
          { factor: "locality", risk_delta: "-8", confidence_delta: "-6", detail: "loopback/local-only endpoints" },
        ],
      }),
    );
    expect(factors).toHaveLength(2);
    expect(factors[0]).toEqual({ factor: "base", riskDelta: 78, confidenceDelta: 70, detail: "declared risk_score 78" });
    expect(factors[1].riskDelta).toBe(-8);
  });

  it("returns [] for missing, null, or malformed details", () => {
    expect(riskBreakdown(alert(null))).toEqual([]);
    expect(riskBreakdown(alert({}))).toEqual([]);
    expect(riskBreakdown(alert({ score_breakdown: "nope" }))).toEqual([]);
  });
});

describe("formatScoreDelta", () => {
  it("shows the raw base value and signed deltas", () => {
    expect(formatScoreDelta({ factor: "base", riskDelta: 78, confidenceDelta: 70, detail: "" })).toBe("78");
    expect(formatScoreDelta({ factor: "locality", riskDelta: 6, confidenceDelta: 4, detail: "" })).toBe("+6");
    expect(formatScoreDelta({ factor: "fp_feedback", riskDelta: -15, confidenceDelta: -12, detail: "" })).toBe("-15");
  });
});
