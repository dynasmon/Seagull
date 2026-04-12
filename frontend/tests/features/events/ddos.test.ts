import { describe, expect, it } from "vitest";

import { isDdosEvent, isDdosEventType } from "@/features/events/lib/ddos";
import type { NetEvent } from "@/features/events/types";

function makeEvent(input: Partial<NetEvent>): NetEvent {
  return {
    id: 1,
    agent_id: "agent-1",
    event_type: "flow",
    schema_version: 1,
    timestamp: "2026-04-12T10:00:00Z",
    extra: {},
    ...input,
  };
}

describe("ddos classification helpers", () => {
  it("accepts canonical and variant ddos event types", () => {
    expect(isDdosEventType("dos_attack")).toBe(true);
    expect(isDdosEventType("ddos_attack")).toBe(true);
    expect(isDdosEventType("ddos_detector")).toBe(true);
    expect(isDdosEventType("ssh_auth")).toBe(false);
  });

  it("classifies events using ddos rule_id semantics", () => {
    const event = makeEvent({
      event_type: "alert",
      extra: {
        rule_id: "incident_ddos_correlated_v1",
      },
    });
    expect(isDdosEvent(event)).toBe(true);
  });

  it("classifies events by attack/vector payload when event_type is generic", () => {
    const event = makeEvent({
      event_type: "telemetry",
      extra: {
        attack: "ddos",
        vector: "tcp_flood",
      },
    });
    expect(isDdosEvent(event)).toBe(true);
  });

  it("classifies events by ddos metrics when explicit labels are missing", () => {
    const event = makeEvent({
      event_type: "signal",
      extra: {
        pps: 12345,
        unique_src_ips: 900,
      },
    });
    expect(isDdosEvent(event)).toBe(true);
  });

  it("does not classify non-ddos events", () => {
    const event = makeEvent({
      event_type: "ssh_auth",
      extra: {
        username: "root",
        action: "failed",
      },
    });
    expect(isDdosEvent(event)).toBe(false);
  });
});
