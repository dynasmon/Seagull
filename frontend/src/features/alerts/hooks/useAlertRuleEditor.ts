import { useEffect, useState } from "react";

import { patchAlertRule, resetAlertRule, validateAlertRule } from "../api";
import { ALL_DAYS } from "../constants";
import { initialDaysObj, normalizeDays, parseJsonArray, parseJsonObject, safeJsonString } from "../lib/alertRuleEditor";
import type { RuleOut, RuleValidationResult } from "../types";

export function useAlertRuleEditor(selected: RuleOut | null, onSaved: () => void, onHistoryRefresh: (id: string) => void) {
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);

  const [enabled, setEnabled] = useState(true);
  const [severity, setSeverity] = useState("low");
  const [window, setWindow] = useState("5m");
  const [cooldown, setCooldown] = useState("10m");
  const [minEvents, setMinEvents] = useState<string>("");

  const [condOp, setCondOp] = useState(">=");
  const [condValue, setCondValue] = useState<string>("");

  const [schedEnabled, setSchedEnabled] = useState(false);
  const [schedTz, setSchedTz] = useState("America/Fortaleza");
  const [schedStart, setSchedStart] = useState("00:00");
  const [schedEnd, setSchedEnd] = useState("23:59");
  const [schedDays, setSchedDays] = useState<Record<string, boolean>>(initialDaysObj);

  const [patchText, setPatchText] = useState("{}");
  const [tuningText, setTuningText] = useState("{}");
  const [suppressionsText, setSuppressionsText] = useState("[]");
  const [patchError, setPatchError] = useState<string | null>(null);
  const [tuningError, setTuningError] = useState<string | null>(null);
  const [suppressionsError, setSuppressionsError] = useState<string | null>(null);

  const [showEffective, setShowEffective] = useState(true);

  useEffect(() => {
    if (!selected) return;

    const eff = selected.effective || {};
    const base = selected.base || {};
    const ovr = selected.override || {};

    setEnabled(Boolean((eff as any).enabled ?? true));
    setSeverity(String((eff as any).severity ?? "low"));
    setWindow(String((eff as any).window ?? (base as any).window ?? "5m"));
    setCooldown(String((eff as any).cooldown ?? (base as any).cooldown ?? "10m"));

    const me = (eff as any).min_events ?? (base as any).min_events;
    setMinEvents(typeof me === "number" ? String(me) : "");

    const cond = ((eff as any).condition ?? (base as any).condition ?? {}) as any;
    setCondOp(String(cond.operator ?? ">="));
    setCondValue(cond.value !== undefined && cond.value !== null ? String(cond.value) : "");

    const sched = ((eff as any).schedule ?? (base as any).schedule ?? {}) as any;
    setSchedEnabled(Boolean(sched.enabled));
    setSchedTz(String(sched.timezone ?? "America/Fortaleza"));
    setSchedStart(String(sched.start ?? "00:00"));
    setSchedEnd(String(sched.end ?? "23:59"));

    const days = normalizeDays(sched.days ?? sched.weekdays);
    const dayObj: Record<string, boolean> = {};
    for (const d of ALL_DAYS) dayObj[d] = days.length ? days.includes(d) : true;
    setSchedDays(dayObj);

    setPatchText(safeJsonString((ovr as any).patch ?? {}));
    setTuningText(safeJsonString((eff as any).tuning ?? {}));
    setSuppressionsText(safeJsonString((eff as any).suppressions ?? []));
    setPatchError(null);
    setTuningError(null);
    setSuppressionsError(null);
    setValidationErrors([]);
  }, [selected]);

  function toggleDay(d: string) {
    setSchedDays((prev) => ({ ...prev, [d]: !prev[d] }));
  }

  function setAllDays(v: boolean) {
    const next: Record<string, boolean> = {};
    for (const d of ALL_DAYS) next[d] = v;
    setSchedDays(next);
  }

  async function handleSave() {
    if (!selected) return;
    setSaving(true);
    setSaveError(null);
    setValidationErrors([]);

    const parsedPatch = parseJsonObject(patchText, "Patch");
    const parsedTuning = parseJsonObject(tuningText, "Tuning");
    const parsedSuppressions = parseJsonArray(suppressionsText, "Suppressions");
    if (!parsedPatch.ok || !parsedTuning.ok || !parsedSuppressions.ok) {
      setPatchError(parsedPatch.ok ? null : parsedPatch.error);
      setTuningError(parsedTuning.ok ? null : parsedTuning.error);
      setSuppressionsError(parsedSuppressions.ok ? null : parsedSuppressions.error);
      setSaving(false);
      return;
    }
    setPatchError(null);
    setTuningError(null);
    setSuppressionsError(null);

    const days = ALL_DAYS.filter((d) => !!schedDays[d]);
    const schedule = {
      enabled: Boolean(schedEnabled),
      timezone: String(schedTz || "UTC"),
      days,
      start: String(schedStart || "00:00"),
      end: String(schedEnd || "23:59"),
    };

    const meNum = minEvents.trim() ? Number(minEvents) : null;
    const cvNum = condValue.trim() ? Number(condValue) : null;

    const overrideBody = {
      enabled,
      severity,
      window,
      cooldown,
      min_events: typeof meNum === "number" && Number.isFinite(meNum) ? meNum : null,
      condition:
        cvNum !== null && Number.isFinite(cvNum) ? { operator: String(condOp || ">="), value: cvNum } : undefined,
      schedule,
      patch: parsedPatch.value,
      tuning: parsedTuning.value,
      suppressions: parsedSuppressions.value,
    };

    try {
      const validation: RuleValidationResult = await validateAlertRule(selected.id, overrideBody);
      if (!validation.ok) {
        setValidationErrors(validation.errors || ["Validation failed — unknown error"]);
        setSaving(false);
        return;
      }

      await patchAlertRule(selected.id, overrideBody);
      onSaved();
      onHistoryRefresh(selected.id);
    } catch (e: any) {
      setSaveError(e?.message || "Failed to save rule");
    } finally {
      setSaving(false);
    }
  }

  async function handleReset() {
    if (!selected) return;
    setSaving(true);
    setSaveError(null);
    try {
      await resetAlertRule(selected.id);
      onSaved();
      onHistoryRefresh(selected.id);
    } catch (e: any) {
      setSaveError(e?.message || "Failed to reset override");
    } finally {
      setSaving(false);
    }
  }

  return {
    saving,
    saveError,
    validationErrors,
    enabled,
    setEnabled,
    severity,
    setSeverity,
    window,
    setWindow,
    cooldown,
    setCooldown,
    minEvents,
    setMinEvents,
    condOp,
    setCondOp,
    condValue,
    setCondValue,
    schedEnabled,
    setSchedEnabled,
    schedTz,
    setSchedTz,
    schedStart,
    setSchedStart,
    schedEnd,
    setSchedEnd,
    schedDays,
    toggleDay,
    setAllDays,
    patchText,
    setPatchText,
    tuningText,
    setTuningText,
    suppressionsText,
    setSuppressionsText,
    patchError,
    tuningError,
    suppressionsError,
    showEffective,
    setShowEffective,
    handleSave,
    handleReset,
  };
}

export type AlertRuleEditor = ReturnType<typeof useAlertRuleEditor>;
