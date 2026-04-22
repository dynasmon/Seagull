import { describe, expect, it } from "vitest";

import {
  applyLifecycleScanPatch,
  buildVulnScanFromPatch,
  scanLifecycleLabel,
  scanPhaseLabel,
  scanTriggerLabel,
  upsertLifecycleScan,
} from "@/features/vulnerabilities/scanUtils";


describe("vulnerability scan helpers", () => {
  it("normalizes labels for lifecycle, phase, and trigger source", () => {
    expect(scanLifecycleLabel("running")).toBe("Running");
    expect(scanPhaseLabel("collecting_inventory")).toBe("Collecting inventory");
    expect(scanTriggerLabel("manual")).toBe("Manual");
  });

  it("builds and patches scans using the full realtime payload shape", () => {
    const built = buildVulnScanFromPatch({
      id: 9,
      scan_uuid: "scan-1",
      reporter_agent_id: "agent-1",
      target: "agent:agent-1",
      tool: "osv-wazuh-like",
      tool_version: "1",
      status: "queued",
      lifecycle_state: "queued",
      current_phase: "queued",
      queued_at: "2026-04-22T12:00:00.000Z",
      last_progress_at: "2026-04-22T12:00:00.000Z",
      trigger_source: "manual",
      scope: {},
      config: {},
      stats: {},
      phase_timestamps: { queued: "2026-04-22T12:00:00.000Z" },
      updated_at: "2026-04-22T12:00:00.000Z",
      created_at: "2026-04-22T12:00:00.000Z",
    });

    expect(built).not.toBeNull();
    const patched = applyLifecycleScanPatch(built!, {
      lifecycle_state: "running",
      current_phase: "querying_source",
      started_at: "2026-04-22T12:00:02.000Z",
      last_progress_at: "2026-04-22T12:00:04.000Z",
      stats: { queried_packages: 14 },
      config: { analysis_profile: "wazuh_like_v1" },
    });

    expect(patched.lifecycle_state).toBe("running");
    expect(patched.current_phase).toBe("querying_source");
    expect(patched.stats.queried_packages).toBe(14);
    expect(patched.config.analysis_profile).toBe("wazuh_like_v1");
  });

  it("upserts scans without duplicating the same scan uuid", () => {
    const first = buildVulnScanFromPatch({
      scan_uuid: "scan-1",
      tool: "osv-wazuh-like",
      lifecycle_state: "queued",
      current_phase: "queued",
      queued_at: "2026-04-22T12:00:00.000Z",
      last_progress_at: "2026-04-22T12:00:00.000Z",
    });

    const inserted = upsertLifecycleScan([], first!);
    expect(inserted).toHaveLength(1);

    const updated = upsertLifecycleScan(inserted, {
      scan_uuid: "scan-1",
      lifecycle_state: "running",
      current_phase: "collecting_inventory",
      last_progress_at: "2026-04-22T12:00:05.000Z",
    });

    expect(updated).toHaveLength(1);
    expect(updated[0].lifecycle_state).toBe("running");
    expect(updated[0].current_phase).toBe("collecting_inventory");
  });
});
