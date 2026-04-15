import { describe, expect, it } from "vitest";

import {
  applyOverviewRealtimeAlertsDelta,
  applyOverviewRealtimeAlertCreated,
  applyOverviewRealtimeAlertUpdated,
  applyOverviewRealtimePatch,
  mergeStormStatus,
  reconcileFetchedOverviewSnapshot,
  nextRealtimeInvalidationDelayMs,
} from "@/features/overview/live_realtime";
import type { OverviewSnapshot, StormStatus } from "@/features/overview/types";

function makeSnapshot(): OverviewSnapshot {
  return {
    meta: {
      lite: false,
      use_ingest_rollups: false,
      protection_active: false,
      draining: false,
      rollups_fresh: true,
      rollup_stuck_fallback: false,
      rollups_last_bucket: null,
      rollup_lag_seconds: null,
      live_lag_seconds: null,
      live_last_bucket: null,
      live_fresh: true,
      window_start: "2026-04-09T10:00:00Z",
      window_end: "2026-04-09T11:00:00Z",
      data_lag_seconds: 0,
      backlog_events: 0,
      backlog_messages: 0,
      ddos_telemetry_emission_per_sec: 0,
      ddos_telemetry_dropped_per_sec: 0,
      recent_feed_last_event_ts: null,
      recent_feed_freshness_seconds: null,
      recent_feed_events_per_sec: 0,
      recent_feed_dropped_per_sec: 0,
      sources: {
        traffic: { source: "postgres", source_freshness_seconds: 0, last_data_ts: null, degraded_reason: null },
        ddos_volume: { source: "postgres", source_freshness_seconds: 0, last_data_ts: null, degraded_reason: null },
        ingest_rates: { source: "postgres", source_freshness_seconds: 0, last_data_ts: null, degraded_reason: null },
      },
    },
    kpis: {
      total_agents: 1,
      online_agents: 1,
      events_5m: 10,
      alerts_60m: 1,
      last_event_age_m: 2,
    },
    traffic: { series: [], data: [] },
    ingest_rates: { series: [], data: [] },
    ssh_failures: { series: [], data: [] },
    alert_severity: { series: [], data: [] },
    ddos: { series: [], data: [] },
    ddos_volume: { series: [], data: [] },
    ports: [],
    top_sources: [],
    recent_alerts: [],
    ddos_alerts: [],
    recent_ssh: [],
    raw_events: [],
  };
}

describe("overview live realtime helpers", () => {
  it("applies overview patch deltas and ingest pressure fields", () => {
    const base = makeSnapshot();
    const next = applyOverviewRealtimePatch(base, {
      events_5m_delta: 7,
      backlog_events: 1200,
      backlog_messages: 12,
      protection_active: true,
      phase: "storm",
      reason: "volumetric",
    });

    expect(next?.kpis.events_5m).toBe(17);
    expect(next?.kpis.last_event_age_m).toBe(0);
    expect(next?.meta.backlog_events).toBe(1200);
    expect(next?.meta.backlog_messages).toBe(12);
    expect(next?.meta.protection_active).toBe(true);
  });

  it("merges storm status while preserving quality rows when omitted", () => {
    const current: StormStatus = {
      active: true,
      phase: "storm",
      eps: 1000,
      sample_hot_percent: 25,
      sample_warm_percent: 5,
      drop_percent: 10,
      backlog_events: 500,
      backlog_messages: 5,
      reason: "storm",
      since: "2026-04-09T12:00:00Z",
      open_alert_id: 1,
      quality_by_event_type: [{ event_type: "dns", received: 10, hot_kept: 5, warm_kept: 1, analytics_kept: 5, dropped_estimated: 4, kept_percent: 60, drop_percent: 40, analytics_percent: 50 }],
    };

    const merged = mergeStormStatus(current, {
      active: false,
      phase: "ok",
      reason: "recovered",
    });

    expect(merged?.active).toBe(false);
    expect(merged?.phase).toBe("ok");
    expect(merged?.reason).toBe("recovered");
    expect(merged?.quality_by_event_type?.length).toBe(1);
  });

  it("maps protection_active and phase-only patches into active state", () => {
    const protectionPatch = {
      protection_active: true,
      reason: "runtime protection",
    } as unknown as Partial<StormStatus>;

    const fromProtection = mergeStormStatus(null, {
      ...protectionPatch,
    });
    expect(fromProtection?.active).toBe(true);

    const fromPhase = mergeStormStatus(null, {
      phase: "storm",
      reason: "traffic spike",
    });
    expect(fromPhase?.active).toBe(true);
  });

  it("computes delayed invalidation refresh window to avoid refetch storms", () => {
    const delay = nextRealtimeInvalidationDelayMs({
      nowMs: 10_000,
      lastRefreshAtMs: 9_200,
      minIntervalMs: 2_500,
      debounceMs: 300,
    });

    expect(delay).toBe(1_700);

    const immediate = nextRealtimeInvalidationDelayMs({
      nowMs: 10_000,
      lastRefreshAtMs: 7_000,
      minIntervalMs: 2_500,
      debounceMs: 300,
    });

    expect(immediate).toBe(300);
  });

  it("applies alert.created into recent summary lists and increments 60m counter", () => {
    const base = makeSnapshot();
    const next = applyOverviewRealtimeAlertCreated(
      base,
      {
        alert_id: 77,
        created_at: new Date().toISOString(),
        rule_id: "ddos_tcp_flood_v1",
        severity: "high",
        src_ip: "192.0.2.10",
        dst_ip: "198.51.100.20",
        dst_port: 443,
        description: "DDoS detected",
      },
      "2026-04-09T18:00:00Z",
    );

    expect(next?.recent_alerts[0]?.id).toBe(77);
    expect(next?.ddos_alerts[0]?.id).toBe(77);
    expect(next?.kpis.alerts_60m).toBe(2);
  });

  it("applies alert.updated to existing summary row severity", () => {
    const base = makeSnapshot();
    const seeded = applyOverviewRealtimeAlertCreated(
      base,
      {
        alert_id: 88,
        created_at: "2026-04-09T18:05:00Z",
        rule_id: "port_scan_v1",
        severity: "medium",
        description: "Port scan",
      },
      "2026-04-09T18:05:00Z",
    );
    const updated = applyOverviewRealtimeAlertUpdated(seeded, {
      alert_id: 88,
      severity: "high",
    });

    expect(updated?.recent_alerts[0]?.severity).toBe("high");
  });

  it("applies ui alerts delta patch with compact alert projection", () => {
    const base = makeSnapshot();
    const next = applyOverviewRealtimeAlertsDelta(
      base,
      {
        action: "upsert",
        alert: {
          id: 99,
          created_at: new Date().toISOString(),
          rule_id: "ddos_tcp_flood_v1",
          severity: "high",
          description: "Projected alert",
        },
        counters: {
          alerts_60m_delta: 1,
        },
      },
      new Date().toISOString(),
    );

    expect(next?.recent_alerts[0]?.id).toBe(99);
    expect(next?.kpis.alerts_60m).toBe(2);
  });

  it("preserves live lists and backlog fields without carrying stale 5m event counters across fetches", () => {
    const current = applyOverviewRealtimeAlertCreated(
      applyOverviewRealtimePatch(makeSnapshot(), {
        events_5m_delta: 40,
        backlog_events: 2500,
        backlog_messages: 25,
        protection_active: true,
      })!,
      {
        alert_id: 120,
        created_at: "2026-04-09T18:10:00Z",
        rule_id: "ddos_tcp_flood_v1",
        severity: "high",
        description: "Fresh alert",
      },
      "2026-04-09T18:10:00Z",
    )!;

    const incoming: OverviewSnapshot = {
      ...makeSnapshot(),
      meta: {
        ...makeSnapshot().meta,
        backlog_events: 0,
        backlog_messages: 0,
        protection_active: false,
        lite: true,
      },
      kpis: {
        ...makeSnapshot().kpis,
        events_5m: 0,
        alerts_60m: 0,
      },
      recent_alerts: [],
      ddos_alerts: [],
      raw_events: [],
    };

    const reconciled = reconcileFetchedOverviewSnapshot(current, incoming, {
      preserveLiveFields: true,
    });

    expect(reconciled.kpis.events_5m).toBe(0);
    expect(reconciled.kpis.alerts_60m).toBe(2);
    expect(reconciled.kpis.last_event_age_m).toBe(2);
    expect(reconciled.meta.backlog_events).toBe(2500);
    expect(reconciled.meta.backlog_messages).toBe(25);
    expect(reconciled.meta.protection_active).toBe(true);
    expect(reconciled.recent_alerts[0]?.id).toBe(120);
    expect(reconciled.ddos_alerts[0]?.id).toBe(120);
  });

  it("keeps distinct recent SSH rows that share the same minute label", () => {
    const current: OverviewSnapshot = {
      ...makeSnapshot(),
      recent_ssh: [
        {
          id: 10,
          timestamp: "2026-04-09T18:05:10Z",
          ts: "18:05",
          agent_id: "agent-a",
          src_ip: "203.0.113.10",
          dst_ip: "10.0.0.2",
          dst_port: 22,
          proto: "ssh",
          username: "root",
          action: "failed_password",
        },
      ],
    };

    const incoming: OverviewSnapshot = {
      ...makeSnapshot(),
      meta: {
        ...makeSnapshot().meta,
        lite: true,
      },
      recent_ssh: [
        {
          id: 11,
          timestamp: "2026-04-09T18:05:40Z",
          ts: "18:05",
          agent_id: "agent-a",
          src_ip: "203.0.113.10",
          dst_ip: "10.0.0.2",
          dst_port: 22,
          proto: "ssh",
          username: "root",
          action: "failed_password",
        },
      ],
    };

    const reconciled = reconcileFetchedOverviewSnapshot(current, incoming, {
      preserveLiveFields: true,
    });

    expect(reconciled.recent_ssh).toHaveLength(2);
    expect(reconciled.recent_ssh[0]?.id).toBe(11);
    expect(reconciled.recent_ssh[1]?.id).toBe(10);
  });

  it("refreshes heavy recent SSH data on full snapshots even when live fields are preserved", () => {
    const current: OverviewSnapshot = {
      ...makeSnapshot(),
      recent_ssh: [
        {
          id: 10,
          timestamp: "2026-04-09T18:05:10Z",
          ts: "18:05",
          agent_id: "agent-a",
          src_ip: "203.0.113.10",
          dst_ip: "10.0.0.2",
          dst_port: 22,
          proto: "ssh",
          username: "root",
          action: "failed_password",
        },
      ],
    };

    const incoming: OverviewSnapshot = {
      ...makeSnapshot(),
      meta: {
        ...makeSnapshot().meta,
        lite: false,
      },
      recent_ssh: [
        {
          id: 20,
          timestamp: "2026-04-09T18:06:15Z",
          ts: "18:06",
          agent_id: "agent-b",
          src_ip: "203.0.113.11",
          dst_ip: "10.0.0.3",
          dst_port: 22,
          proto: "ssh",
          username: "admin",
          action: "invalid_user",
        },
      ],
    };

    const reconciled = reconcileFetchedOverviewSnapshot(current, incoming, {
      preserveLiveFields: true,
    });

    expect(reconciled.recent_ssh[0]?.id).toBe(20);
    expect(reconciled.recent_ssh.some((row) => row.id === 10)).toBe(true);
  });
});
