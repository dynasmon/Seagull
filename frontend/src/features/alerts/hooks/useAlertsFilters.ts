import { useMemo } from "react";

import { filterAlerts } from "../lib/alertFilters";
import type { Alert } from "../types";

export function useAlertsFilters(alerts: Alert[], search: string) {
  const filtered = useMemo(() => filterAlerts(alerts, search), [alerts, search]);

  const severityBreakdown = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    for (const alert of filtered) {
      const key = String(alert.severity || "unknown").toLowerCase();
      if (counts[key] === undefined) counts.unknown += 1;
      else counts[key] += 1;
    }
    return counts;
  }, [filtered]);

  return { filtered, severityBreakdown };
}

export type AlertsFilters = ReturnType<typeof useAlertsFilters>;
