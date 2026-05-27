import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { HYGIENE_TABS } from "../constants";
import type { HygieneDomain } from "../types";
import { normAgentId, parsePositiveInt } from "../lib/inventoryParsers";
import { buildInventoryUrl } from "../lib/inventoryUrl";

export function useInventoryUrlState() {
  const [sp, setSp] = useSearchParams();

  const urlAgentId = normAgentId(sp.get("agent_id"));
  const urlSnapshotId = parsePositiveInt(sp.get("snapshot_id"));
  const urlOpenDrawer = String(sp.get("open_drawer") || "").trim() === "1";
  const urlDomainRaw = String(sp.get("view") || "").trim().toLowerCase();
  const urlDomain = (HYGIENE_TABS.find((x) => x.key === urlDomainRaw)?.key || "dashboard") as HygieneDomain;
  const urlWindowMinutes = (() => {
    const w = Number(sp.get("window_minutes"));
    return Number.isFinite(w) && w >= 30 ? w : 360;
  })();

  const [agentScope, setAgentScope] = useState<string>(urlAgentId);
  const [domain, setDomain] = useState<HygieneDomain>(urlDomain);
  const [windowMinutes, setWindowMinutes] = useState<number>(urlWindowMinutes);

  useEffect(() => {
    setAgentScope(urlAgentId);
  }, [urlAgentId]);

  useEffect(() => {
    setDomain(urlDomain);
  }, [urlDomain]);

  const pushUrl = useCallback(
    (nextAgent: string, nextWindow?: number, nextDomain?: HygieneDomain) => {
      const next = buildInventoryUrl(sp, {
        agentId: normAgentId(nextAgent),
        windowMinutes: nextWindow,
        domain: nextDomain,
        clearDrawerParams: true,
      });
      setSp(next, { replace: true });
    },
    [sp, setSp]
  );

  const scopeToAgent = useCallback(
    (agentId: string, windowMins: number, currentDomain: HygieneDomain) => {
      const next = new URLSearchParams();
      next.set("agent_id", agentId);
      next.set("window_minutes", String(windowMins));
      if (currentDomain !== "dashboard") next.set("view", currentDomain);
      setSp(next, { replace: false });
    },
    [setSp]
  );

  return {
    sp,
    setSp,
    urlAgentId,
    urlSnapshotId,
    urlOpenDrawer,
    urlDomain,
    agentScope,
    setAgentScope,
    domain,
    setDomain,
    windowMinutes,
    setWindowMinutes,
    pushUrl,
    scopeToAgent,
  };
}

export type InventoryUrlState = ReturnType<typeof useInventoryUrlState>;
