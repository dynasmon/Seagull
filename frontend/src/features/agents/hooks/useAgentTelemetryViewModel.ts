import { useMemo } from "react";

import type { OverviewSnapshot } from "@/features/overview/types";

import type { AgentPublic } from "../types";
import { fmtDateTime } from "../lib/agentUtils";

interface UseAgentTelemetryViewModelProps {
  snapshot: OverviewSnapshot | null;
  selectedAgentRow: AgentPublic | null;
}

export function useAgentTelemetryViewModel({ snapshot, selectedAgentRow }: UseAgentTelemetryViewModelProps) {
  const charts = useMemo(() => {
    if (!snapshot) {
      return {
        traffic: null as null | { series: string[]; data: Array<Record<string, any>> },
        ssh: null as null | { series: string[]; data: Array<Record<string, any>> },
        ddos: null as null | { series: string[]; data: Array<Record<string, any>> },
        sev: null as null | { series: string[]; data: Array<Record<string, any>> },
      };
    }
    return {
      traffic: snapshot.traffic,
      ssh: snapshot.ssh_failures,
      ddos: snapshot.ddos,
      sev: snapshot.alert_severity,
    };
  }, [snapshot]);

  const eventsRate = useMemo(() => {
    if (!snapshot) return "-";
    return String(snapshot.kpis.events_5m);
  }, [snapshot]);

  const alerts60m = useMemo(() => {
    if (!snapshot) return "-";
    return String(snapshot.kpis.alerts_60m);
  }, [snapshot]);

  const lastEventAge = useMemo(() => {
    if (!snapshot) return "-";
    const v = snapshot.kpis.last_event_age_m;
    if (v === null || v === undefined) return "-";
    if (typeof v !== "number" || !Number.isFinite(v)) return "-";
    return `${Math.round(v)}m`;
  }, [snapshot]);

  const topStats = useMemo(() => {
    const row = selectedAgentRow;
    const last = row?.last_seen_at ? new Date(row.last_seen_at) : null;
    const online = !row?.is_revoked && Boolean(row?.last_seen_at) && Date.now() - new Date(row!.last_seen_at!).getTime() <= 5 * 60_000;
    const status = row?.is_revoked ? "Disabled" : online ? "Online" : "Offline";
    return {
      status,
      online,
      lastSeen: last ? fmtDateTime(last) : "-",
    };
  }, [selectedAgentRow]);

  return { charts, eventsRate, alerts60m, lastEventAge, topStats };
}

export type AgentTelemetryViewModel = ReturnType<typeof useAgentTelemetryViewModel>;
