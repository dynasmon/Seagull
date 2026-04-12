import { describe, expect, it } from "vitest";

import { readAuditEventId, withAuditEventId } from "@/features/audit/urlState";

describe("audit drawer URL state", () => {
  it("reads event_id from query string", () => {
    const sp = new URLSearchParams("actor=admin&event_id=evt-123");
    expect(readAuditEventId(sp)).toBe("evt-123");
  });

  it("sets event_id while preserving other filter params", () => {
    const current = new URLSearchParams("actor=alice&sort=desc");
    const next = withAuditEventId(current, "evt-9");

    expect(next.get("actor")).toBe("alice");
    expect(next.get("sort")).toBe("desc");
    expect(next.get("event_id")).toBe("evt-9");
  });

  it("clears event_id on drawer close", () => {
    const current = new URLSearchParams("event_id=evt-9&resource_type=user");
    const next = withAuditEventId(current, null);

    expect(next.get("event_id")).toBeNull();
    expect(next.get("resource_type")).toBe("user");
  });
});

