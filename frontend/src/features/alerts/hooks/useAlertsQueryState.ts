import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { DEFAULTS } from "../constants";
import type { ViewCfg } from "../constants";
import { clampInt, persistView, safeLoadView } from "../lib/alertQuery";

export function useAlertsQueryState() {
  const [searchParams] = useSearchParams();
  const [view, setView] = useState<ViewCfg>(() => safeLoadView());
  const hydratedRef = useRef(false);

  useEffect(() => {
    setView((v) => {
      persistView(v);
      return v;
    });
  }, [view]);

  useEffect(() => {
    if (hydratedRef.current) return;
    hydratedRef.current = true;
    const ruleId = String(searchParams.get("rule_id") || "").trim();
    const agentId = String(searchParams.get("agent_id") || "").trim();
    const search = String(searchParams.get("search") || "").trim();
    const severity = String(searchParams.get("severity") || "").trim().toLowerCase();
    const status = String(searchParams.get("status") || "").trim().toLowerCase();
    const next: Partial<ViewCfg> = {};
    if (ruleId) next.rule_id = ruleId;
    if (agentId) next.agent_id = agentId;
    if (search) next.search = search;
    if (severity) next.severity = severity;
    if (status) next.status = status;
    if (Object.keys(next).length > 0) {
      setView((prev) => mergeView(prev, next));
    }
  }, [searchParams]);

  const patch = useCallback((next: Partial<ViewCfg>) => {
    setView((prev) => mergeView(prev, next));
  }, []);

  return { view, patch };
}

function mergeView(prev: ViewCfg, next: Partial<ViewCfg>): ViewCfg {
  const merged: ViewCfg = { ...prev, ...next };
  merged.severity = String(merged.severity || "all");
  merged.status = String(merged.status || "all");
  merged.rule_id = String(merged.rule_id || "").trim();
  merged.agent_id = String(merged.agent_id || "").trim();
  merged.search = String(merged.search || "");
  merged.page_size = clampInt(merged.page_size, 10, 200, DEFAULTS.page_size);
  merged.infinite_scroll = Boolean(merged.infinite_scroll);
  merged.wrap_json = Boolean(merged.wrap_json);
  merged.density = merged.density === "comfortable" ? "comfortable" : "compact";
  return merged;
}

export type AlertsQueryState = ReturnType<typeof useAlertsQueryState>;
