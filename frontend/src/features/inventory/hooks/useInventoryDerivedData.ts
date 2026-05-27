import { useMemo } from "react";

import { useAgentsCatalog } from "@/app/providers";

import type { HygieneDomain, InventoryOverviewSnapshot, InventoryWarningRow, InventoryChangeRow, FleetHealthRow } from "../types";
import { EMPTY_WARNING_ROWS, EMPTY_CHANGE_ROWS, EMPTY_FLEET_ROWS } from "../constants";
import { warningMatchesDomain } from "../lib/inventoryDomainRules";

interface UseInventoryDerivedDataParams {
  snapshot: InventoryOverviewSnapshot | null;
  agentScope: string;
  domain: HygieneDomain;
}

export function useInventoryDerivedData({ snapshot, agentScope, domain }: UseInventoryDerivedDataParams) {
  const { agents } = useAgentsCatalog();

  const agentsOptions = useMemo(() => {
    const rows = [...agents];
    rows.sort((a, b) => {
      const an = (a.display_name || "").trim().toLowerCase();
      const bn = (b.display_name || "").trim().toLowerCase();
      if (an && bn && an !== bn) return an.localeCompare(bn);
      if (an && !bn) return -1;
      if (!an && bn) return 1;
      return a.agent_id.localeCompare(b.agent_id);
    });
    return rows;
  }, [agents]);

  const scopeLabel = useMemo(() => {
    if (agentScope === "__all") return "All agents";
    const found = agentsOptions.find((a) => a.agent_id === agentScope);
    if (!found) return agentScope;
    return found.display_name ? `${found.display_name} (${found.agent_id})` : found.agent_id;
  }, [agentScope, agentsOptions]);

  const warningsRows: InventoryWarningRow[] = snapshot?.recent_warnings ?? EMPTY_WARNING_ROWS;
  const changesRows: InventoryChangeRow[] = snapshot?.recent_changes ?? EMPTY_CHANGE_ROWS;
  const fleetRows: FleetHealthRow[] = snapshot?.fleet_health ?? EMPTY_FLEET_ROWS;

  const domainWarnings = useMemo(
    () => warningsRows.filter((w) => warningMatchesDomain(w.warning || "", domain)).slice(0, 12),
    [warningsRows, domain]
  );

  const domainPivotRows = useMemo(() => {
    const rows = [...fleetRows];
    if (domain === "software") {
      rows.sort((a, b) => (b.packages_count || 0) - (a.packages_count || 0));
      return rows.slice(0, 12);
    }
    if (domain === "processes" || domain === "services") {
      rows.sort((a, b) => b.warnings_count - a.warnings_count);
      return rows.slice(0, 12);
    }
    if (domain === "network") {
      rows.sort((a, b) => {
        const av = (a.inventory_age_min ?? 999999) + (a.warnings_count || 0) * 30;
        const bv = (b.inventory_age_min ?? 999999) + (b.warnings_count || 0) * 30;
        return bv - av;
      });
      return rows.slice(0, 12);
    }
    return rows.slice(0, 12);
  }, [fleetRows, domain]);

  return {
    agentsOptions,
    scopeLabel,
    warningsRows,
    changesRows,
    fleetRows,
    domainWarnings,
    domainPivotRows,
    osRows: snapshot?.os_distribution || [],
    mgrRows: snapshot?.manager_distribution || [],
  };
}

export type InventoryDerivedData = ReturnType<typeof useInventoryDerivedData>;
