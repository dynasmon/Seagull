import { describe, expect, it } from "vitest";

import {
  alertPivotUrl,
  attackChainCasePivotUrl,
  buildAlertsPivotUrl,
  buildAttackChainPivotUrl,
  buildEventsPivotUrl,
  buildExposureAssetPivotUrl,
  buildExposureFindingPivotUrl,
  buildInventoryPivotUrl,
  edgeAlertsPivot,
  edgeEventsPivot,
  exposureFindingPivotUrl,
  flowPivotUrl,
  nodeAlertsPivot,
  nodeAssetKey,
  nodeEventsPivot,
  nodePrimaryIp,
  observationPivotUrl,
} from "@/features/network_topology/lib/details/pivots";
import type {
  TopologyEdge,
  TopologyNode,
  TopologyObservation,
  TopologyRelatedAlert,
  TopologyRelatedAttackChainCase,
  TopologyRelatedExposureFinding,
  TopologyRelatedFlow,
} from "@/features/network_topology/types";

const now = "2026-05-13T12:00:00.000Z";

function node(overrides: Partial<TopologyNode> = {}): TopologyNode {
  return {
    node_key: "topo:host:agent-1:10.0.0.5",
    node_type: "host",
    agent_id: "agent-1",
    label: "host-1",
    ip: "10.0.0.5",
    cidr: null,
    port: null,
    protocol: null,
    severity: "high",
    risk_score: 70,
    confidence: 82,
    is_stale: false,
    event_count: 7,
    alert_count: 1,
    observation_count: 25,
    first_seen_at: now,
    last_seen_at: now,
    updated_at: now,
    metadata: {},
    ...overrides,
  };
}

function edge(overrides: Partial<TopologyEdge> = {}): TopologyEdge {
  return {
    edge_key: "topo:edge:observed_flow:agent-1:10.0.0.5:1.2.3.4:443",
    source_node_key: "topo:host:agent-1:10.0.0.5",
    target_node_key: "topo:external_ip:1.2.3.4",
    edge_type: "observed_flow",
    agent_id: "agent-1",
    weight: 1.0,
    confidence: 75,
    severity: "medium",
    port: 443,
    protocol: "tcp",
    event_count: 5,
    alert_count: 0,
    first_seen_at: now,
    last_seen_at: now,
    updated_at: now,
    metadata: {},
    ...overrides,
  };
}

describe("buildEventsPivotUrl", () => {
  it("builds URL with IP and agent", () => {
    const url = buildEventsPivotUrl({ ip: "10.0.0.5", agentId: "agent-1" });
    expect(url).toContain("/events");
    expect(url).toContain("search=10.0.0.5");
    expect(url).toContain("agent_id=agent-1");
  });

  it("uses explicit search when provided", () => {
    const url = buildEventsPivotUrl({ search: "ssh scan", ip: "10.0.0.5" });
    expect(url).toContain("search=ssh+scan");
    expect(url).not.toContain("10.0.0.5");
  });

  it("includes event_id when numeric", () => {
    const url = buildEventsPivotUrl({ eventId: 42 });
    expect(url).toContain("event_id=42");
  });

  it("returns base events path when no params", () => {
    const url = buildEventsPivotUrl({});
    expect(url).toBe("/events");
  });
});

describe("buildAlertsPivotUrl", () => {
  it("builds URL with IP and severity", () => {
    const url = buildAlertsPivotUrl({ ip: "10.0.0.5", severity: "HIGH" });
    expect(url).toContain("/alerts/queue");
    expect(url).toContain("search=10.0.0.5");
    expect(url).toContain("severity=high");
  });

  it("lowercases severity and status", () => {
    const url = buildAlertsPivotUrl({ severity: "CRITICAL", status: "OPEN" });
    expect(url).toContain("severity=critical");
    expect(url).toContain("status=open");
  });

  it("returns base path when no params", () => {
    const url = buildAlertsPivotUrl({});
    expect(url).toBe("/alerts/queue");
  });
});

describe("buildInventoryPivotUrl", () => {
  it("returns null when no agentId", () => {
    expect(buildInventoryPivotUrl({})).toBeNull();
    expect(buildInventoryPivotUrl({ agentId: null })).toBeNull();
    expect(buildInventoryPivotUrl({ agentId: "  " })).toBeNull();
  });

  it("builds URL with agent_id", () => {
    const url = buildInventoryPivotUrl({ agentId: "agent-1" });
    expect(url).toContain("/inventory");
    expect(url).toContain("agent_id=agent-1");
  });

  it("includes open_drawer when set", () => {
    const url = buildInventoryPivotUrl({ agentId: "agent-1", openDrawer: true });
    expect(url).toContain("open_drawer=1");
  });
});

describe("buildExposureAssetPivotUrl", () => {
  it("returns null when only tab param", () => {
    expect(buildExposureAssetPivotUrl({})).toBeNull();
  });

  it("builds URL with asset key", () => {
    const url = buildExposureAssetPivotUrl({ assetKey: "asset:host:10.0.0.5" });
    expect(url).toContain("/exposure");
    expect(url).toContain("tab=assets");
    expect(url).toContain("asset_key=");
  });
});

describe("buildExposureFindingPivotUrl", () => {
  it("returns null when only tab param", () => {
    expect(buildExposureFindingPivotUrl({})).toBeNull();
  });

  it("builds URL with finding key", () => {
    const url = buildExposureFindingPivotUrl({ findingKey: "finding:open-port:10.0.0.5:22" });
    expect(url).toContain("/exposure");
    expect(url).toContain("tab=findings");
    expect(url).toContain("finding_key=");
  });
});

describe("buildAttackChainPivotUrl", () => {
  it("returns null when no valid caseId", () => {
    expect(buildAttackChainPivotUrl({ caseId: null })).toBeNull();
    expect(buildAttackChainPivotUrl({ caseId: 0 })).toBeNull();
    expect(buildAttackChainPivotUrl({})).toBeNull();
  });

  it("builds URL with case_id", () => {
    const url = buildAttackChainPivotUrl({ caseId: 7 });
    expect(url).toContain("/attack-chain");
    expect(url).toContain("case_id=7");
  });
});

describe("node pivot helpers", () => {
  it("nodePrimaryIp returns ip when present", () => {
    expect(nodePrimaryIp(node({ ip: "10.0.0.5", cidr: null }))).toBe("10.0.0.5");
  });

  it("nodePrimaryIp falls back to cidr", () => {
    expect(nodePrimaryIp(node({ ip: null, cidr: "10.0.0.0/24" }))).toBe("10.0.0.0/24");
  });

  it("nodeAssetKey reads from metadata", () => {
    const n = node({ metadata: { exposure_asset_key: "asset:host:10.0.0.5" } });
    expect(nodeAssetKey(n)).toBe("asset:host:10.0.0.5");
  });

  it("nodeEventsPivot builds events URL with node IP", () => {
    const url = nodeEventsPivot(node());
    expect(url).toContain("/events");
    expect(url).toContain("10.0.0.5");
  });

  it("nodeAlertsPivot builds alerts URL with node IP", () => {
    const url = nodeAlertsPivot(node());
    expect(url).toContain("/alerts/queue");
    expect(url).toContain("10.0.0.5");
  });
});

describe("edge pivot helpers", () => {
  it("edgeEventsPivot uses source IP", () => {
    const url = edgeEventsPivot(edge(), "10.0.0.5", "1.2.3.4");
    expect(url).toContain("/events");
    expect(url).toContain("10.0.0.5");
  });

  it("edgeAlertsPivot uses source IP with severity", () => {
    const url = edgeAlertsPivot(edge(), "10.0.0.5", null);
    expect(url).toContain("/alerts/queue");
    expect(url).toContain("10.0.0.5");
    expect(url).toContain("severity=medium");
  });
});

describe("observationPivotUrl", () => {
  const base: TopologyObservation = {
    id: 1,
    node_key: "topo:host:agent-1:10.0.0.5",
    edge_key: null,
    agent_id: "agent-1",
    source_type: "flow",
    source_id: "42",
    observed_at: now,
    summary: "Observed flow",
    confidence: 80,
    raw_context: {},
  };

  it("builds events URL for flow source", () => {
    const url = observationPivotUrl({ ...base, source_type: "flow", source_id: "42" });
    expect(url).toContain("/events");
    expect(url).toContain("event_id=42");
  });

  it("builds alerts URL for alert source", () => {
    const url = observationPivotUrl({ ...base, source_type: "alert", source_id: "99" });
    expect(url).toContain("/alerts/queue");
  });

  it("builds inventory URL for inventory source", () => {
    const url = observationPivotUrl({ ...base, source_type: "inventory", source_id: null });
    expect(url).toContain("/inventory");
    expect(url).toContain("agent_id=agent-1");
  });

  it("returns null for unknown source type", () => {
    const url = observationPivotUrl({ ...base, source_type: "unknown", source_id: null });
    expect(url).toBeNull();
  });
});

describe("flowPivotUrl", () => {
  const flow: TopologyRelatedFlow = {
    id: 55,
    timestamp: now,
    agent_id: "agent-1",
    event_type: "flow",
    src_ip: "10.0.0.5",
    dst_ip: "1.2.3.4",
    src_port: 55000,
    dst_port: 443,
    protocol: "tcp",
    bytes: 2048,
    app_proto: "tls",
  };

  it("builds events URL with flow metadata", () => {
    const url = flowPivotUrl(flow);
    expect(url).toContain("/events");
    expect(url).toContain("event_id=55");
    expect(url).toContain("agent_id=agent-1");
  });
});

describe("alertPivotUrl", () => {
  const alert: TopologyRelatedAlert = {
    id: 33,
    created_at: now,
    rule_id: "rule-port-scan",
    severity: "high",
    status: "open",
    confidence: 85,
    description: "Port scan detected",
    src_ip: "10.0.0.5",
    dst_ip: null,
    dst_port: null,
  };

  it("builds alerts URL with alert ID", () => {
    const url = alertPivotUrl(alert);
    expect(url).toContain("/alerts/queue");
    expect(url).toContain("search=33");
    expect(url).toContain("severity=high");
    expect(url).toContain("status=open");
  });
});

describe("exposureFindingPivotUrl", () => {
  const finding: TopologyRelatedExposureFinding = {
    finding_key: "finding:open-port:10.0.0.5:22",
    asset_key: "asset:host:10.0.0.5",
    agent_id: "agent-1",
    finding_type: "open_port",
    severity: "medium",
    status: "open",
    confidence: 90,
    title: "SSH Port Exposed",
    summary: "Port 22 is accessible",
    last_seen_at: now,
  };

  it("builds exposure findings URL", () => {
    const url = exposureFindingPivotUrl(finding);
    expect(url).toContain("/exposure");
    expect(url).toContain("tab=findings");
  });
});

describe("attackChainCasePivotUrl", () => {
  const attackCase: TopologyRelatedAttackChainCase = {
    id: 7,
    agent_id: "agent-1",
    suspect_ip: "1.2.3.4",
    status: "open",
    score: 80,
    max_stage: "lateral_movement",
    step_count: 4,
    first_seen_at: now,
    last_seen_at: now,
  };

  it("builds attack chain URL with case ID", () => {
    const url = attackChainCasePivotUrl(attackCase);
    expect(url).toContain("/attack-chain");
    expect(url).toContain("case_id=7");
  });
});
