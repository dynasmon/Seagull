import { describe, expect, it } from "vitest";

import { applyAgentHeartbeatRealtime } from "@/app/agents_realtime";
import type { AgentPublic } from "@/features/agents/types";

function makeAgent(agentId: string): AgentPublic {
  return {
    agent_id: agentId,
    display_name: agentId,
    description: null,
    tags: [],
    created_at: "2026-04-09T16:00:00Z",
    last_seen_at: null,
    is_revoked: false,
    metadata: {},
    metrics: {},
  };
}

describe("agents realtime heartbeat reducer", () => {
  it("updates matching agent presence fields", () => {
    const base = [makeAgent("agent-core-1"), makeAgent("agent-core-2")];
    const out = applyAgentHeartbeatRealtime(
      base,
      {
        agent_id: "agent-core-2",
        status: "ok",
        last_seen_at: "2026-04-09T18:20:00Z",
      },
      "2026-04-09T18:20:01Z",
    );

    expect(out.updated).toBe(true);
    expect(out.agents[1]?.last_seen_at).toBe("2026-04-09T18:20:00.000Z");
    expect(out.agents[1]?.metrics?.status).toBe("ok");
  });

  it("keeps catalog unchanged when heartbeat agent is unknown", () => {
    const base = [makeAgent("agent-core-1")];
    const out = applyAgentHeartbeatRealtime(
      base,
      {
        agent_id: "agent-new-1",
        status: "ok",
      },
      "2026-04-09T18:20:01Z",
    );

    expect(out.updated).toBe(false);
    expect(out.agentId).toBe("agent-new-1");
    expect(out.agents).toEqual(base);
  });
});
