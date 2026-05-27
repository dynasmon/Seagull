import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { getAlertRuleHistory, getAlertRules } from "../api";
import type { RuleGovernanceHistory, RuleOut } from "../types";

export function useAlertsRulesData() {
  const [sp, setSp] = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rules, setRules] = useState<RuleOut[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [q, setQ] = useState("");

  const [historyRows, setHistoryRows] = useState<RuleGovernanceHistory[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  const reqSeq = useRef(0);

  async function reload() {
    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);

    try {
      const payload = await getAlertRules();
      if (reqSeq.current !== mySeq) return;

      setRules(payload);

      const rid = sp.get("rule_id");
      const ridExists = !!rid && payload.some((r) => r.id === rid);

      setSelectedId((prev) => {
        if (ridExists) return rid as string;
        if (prev && payload.some((r) => r.id === prev)) return prev;
        return payload[0]?.id ?? null;
      });

      if (ridExists) setDrawerOpen(true);
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(e?.message || "Failed to load rules");
      setRules([]);
      setSelectedId(null);
      setDrawerOpen(false);
    } finally {
      if (reqSeq.current !== mySeq) return;
      setLoading(false);
    }
  }

  async function loadHistory(ruleId: string) {
    if (!ruleId) return;
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const rows = await getAlertRuleHistory(ruleId, { limit: 100 });
      setHistoryRows(rows || []);
    } catch (e: any) {
      setHistoryError(e?.message || "Failed to load history");
      setHistoryRows([]);
    } finally {
      setHistoryLoading(false);
    }
  }

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const rid = sp.get("rule_id");
    if (!rid) return;
    if (!rules || rules.length === 0) return;
    if (!rules.some((r) => r.id === rid)) return;
    setSelectedId(rid);
    setDrawerOpen(true);
  }, [rules, sp]);

  const filtered = useMemo(() => {
    const qq = q.trim().toLowerCase();
    return (rules || []).filter((r) => {
      if (!qq) return true;
      const hay = [r.id, r.name, r.description, r.type, r.severity].filter(Boolean).join(" ").toLowerCase();
      return hay.includes(qq);
    });
  }, [q, rules]);

  const selected = useMemo(() => {
    if (!selectedId) return null;
    return (rules || []).find((r) => r.id === selectedId) || null;
  }, [rules, selectedId]);

  const ruleStats = useMemo(() => {
    const enabled = rules.filter((rule) => rule.enabled).length;
    const overrides = rules.filter((rule) => rule.has_override).length;
    const criticalHigh = rules.filter((rule) => {
      const severity = String(rule.severity || "").toLowerCase();
      return severity === "critical" || severity === "high";
    }).length;
    return { enabled, overrides, criticalHigh };
  }, [rules]);

  function openDrawerFor(rule: RuleOut) {
    setSelectedId(rule.id);
    setDrawerOpen(true);
    setSp((prev) => {
      const p = new URLSearchParams(prev);
      p.set("rule_id", rule.id);
      return p;
    });
  }

  function closeDrawer() {
    setDrawerOpen(false);
    setSp((prev) => {
      const p = new URLSearchParams(prev);
      p.delete("rule_id");
      return p;
    });
  }

  return {
    loading,
    error,
    rules,
    filtered,
    selected,
    selectedId,
    drawerOpen,
    q,
    setQ,
    ruleStats,
    historyRows,
    historyLoading,
    historyError,
    reload,
    loadHistory,
    openDrawerFor,
    closeDrawer,
  };
}

export type AlertsRulesData = ReturnType<typeof useAlertsRulesData>;
