import { useMemo, useRef } from "react";

import type { OverviewSnapshot } from "@/features/overview/types";

import type { AgentPublic } from "../types";
import { fmtDateTime } from "../lib/agentUtils";

type ChartData = { series: string[]; data: Array<Record<string, any>> };

type AgentCharts = {
  traffic: ChartData | null;
  ssh: ChartData | null;
  ddos: ChartData | null;
  sev: ChartData | null;
};

const EMPTY_CHARTS: AgentCharts = { traffic: null, ssh: null, ddos: null, sev: null };

function chartsSignature(charts: AgentCharts): string {
  return JSON.stringify(charts);
}

interface UseAgentTelemetryViewModelProps {
  snapshot: OverviewSnapshot | null;
  selectedAgentRow: AgentPublic | null;
}

export function useAgentTelemetryViewModel({ snapshot, selectedAgentRow }: UseAgentTelemetryViewModelProps) {
  const chartsRef = useRef<{ signature: string; value: AgentCharts }>({
    signature: chartsSignature(EMPTY_CHARTS),
    value: EMPTY_CHARTS,
  });

  const charts = useMemo(() => {
    const next: AgentCharts = snapshot
      ? {
          traffic: snapshot.traffic,
          ssh: snapshot.ssh_failures,
          ddos: snapshot.ddos,
          sev: snapshot.alert_severity,
        }
      : EMPTY_CHARTS;

    const signature = chartsSignature(next);
    if (signature === chartsRef.current.signature) return chartsRef.current.value;

    chartsRef.current = { signature, value: next };
    return next;
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
