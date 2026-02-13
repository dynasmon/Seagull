import type { CSSProperties, ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Badge } from "@/shared/components/Badge";
import { cx } from "@/shared/lib/cx";

import { getAlertRules, patchAlertRule, resetAlertRule } from "../api";
import type { RuleOut } from "../types";

function Panel(props: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  style?: CSSProperties;
  scrollY?: boolean;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <div
      className={cx(
        "rounded-xl border border-border/60 bg-background/70 backdrop-blur-md flex flex-col min-h-0",
        props.className
      )}
    >
      <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-border/60 bg-muted/10">
        <div className="text-sm font-semibold tracking-tight truncate">{props.title}</div>
        {props.right ? <div className="text-xs text-muted-foreground truncate">{props.right}</div> : null}
      </div>

      <div className={cx("p-4 min-h-0", props.scrollY && "overflow-y-auto", props.bodyClassName)} style={props.style}>
        {props.children}
      </div>
    </div>
  );
}

function sevVariant(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
}

function safeJsonString(v: any) {
  try {
    return JSON.stringify(v ?? {}, null, 2);
  } catch {
    return "{}";
  }
}

function parseJson(s: string): { ok: true; value: any } | { ok: false; error: string } {
  const t = (s ?? "").trim();
  if (!t) return { ok: true, value: {} };
  try {
    const v = JSON.parse(t);
    if (v === null || typeof v !== "object" || Array.isArray(v)) {
      return { ok: false, error: "Patch must be a JSON object." };
    }
    return { ok: true, value: v };
  } catch (e: any) {
    return { ok: false, error: e?.message || "Invalid JSON" };
  }
}

function normalizeDays(days: any): string[] {
  const arr = Array.isArray(days) ? days : typeof days === "string" ? [days] : [];
  return arr
    .map((d) => String(d).trim().toLowerCase().slice(0, 3))
    .filter(Boolean);
}

const ALL_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

export default function AlertsRulesPage() {
  const [sp, setSp] = useSearchParams();

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [rules, setRules] = useState<RuleOut[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [q, setQ] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [showEffective, setShowEffective] = useState(true);

  // Editor state
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
  const [schedDays, setSchedDays] = useState<Record<string, boolean>>(() => {
    const o: Record<string, boolean> = {};
    for (const d of ALL_DAYS) o[d] = true;
    return o;
  });

  const [patchText, setPatchText] = useState("{}");
  const [patchError, setPatchError] = useState<string | null>(null);

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

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // If URL is updated with rule_id later (e.g., coming from Queue), open drawer.
  useEffect(() => {
    const rid = sp.get("rule_id");
    if (!rid) return;
    if (!rules || rules.length === 0) return;
    if (!rules.some((r) => r.id === rid)) return;

    setSelectedId(rid);
    setDrawerOpen(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
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

  // Hydrate editor when selection changes
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
    setPatchError(null);
  }, [selected]);

  const headerRight = useMemo(() => {
    if (loading) return "Loading…";
    return `${filtered.length} rules`;
  }, [filtered.length, loading]);

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
    setError(null);

    const parsed = parseJson(patchText);
    if (!parsed.ok) {
      setPatchError(parsed.error);
      setSaving(false);
      return;
    }
    setPatchError(null);

    const days = ALL_DAYS.filter((d) => !!schedDays[d]);
    const schedule = {
      enabled: Boolean(schedEnabled),
      timezone: String(schedTz || "UTC"),
      days,
      start: String(schedStart || "00:00"),
      end: String(schedEnd || "23:59")
    };

    const meNum = minEvents.trim() ? Number(minEvents) : null;
    const cvNum = condValue.trim() ? Number(condValue) : null;

    try {
      await patchAlertRule(selected.id, {
        enabled,
        severity,
        window,
        cooldown,
        min_events: typeof meNum === "number" && Number.isFinite(meNum) ? meNum : null,
        condition:
          cvNum !== null && Number.isFinite(cvNum)
            ? {
                operator: String(condOp || ">="),
                value: cvNum
              }
            : undefined,
        schedule,
        patch: parsed.value
      });

      await reload();
    } catch (e: any) {
      setError(e?.message || "Failed to save rule");
    } finally {
      setSaving(false);
    }
  }

  async function handleReset() {
    if (!selected) return;
    setSaving(true);
    setError(null);
    try {
      await resetAlertRule(selected.id);
      await reload();
    } catch (e: any) {
      setError(e?.message || "Failed to reset override");
    } finally {
      setSaving(false);
    }
  }

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

  const panelHeightClass = "h-[640px] xl:h-[calc(100vh-270px)]";

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <h2 className="text-lg font-semibold">Rules</h2>
          <div className="text-xs text-muted-foreground">
            Configure thresholds, severity, lookback window, cooldown and schedules. Overrides are stored in the DB — your YAML stays intact.
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search rule…"
            className={cx(
              "h-9 min-w-[220px] flex-1 rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none",
              "focus:ring-1 focus:ring-primary/40"
            )}
          />

          <button
            onClick={() => reload()}
            disabled={loading}
            className={cx(
              "h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm",
              "hover:bg-muted/30 disabled:opacity-60"
            )}
            type="button"
          >
            Refresh
          </button>
        </div>
      </div>

      {error ? (
        <div className="rounded-xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      ) : null}

      <Panel title="Rule catalog" right={headerRight} scrollY className={cx(panelHeightClass)}>
        {loading ? (
          <Loading label="Loading rules…" />
        ) : filtered.length === 0 ? (
          <EmptyState title="No rules" description="No rules match your current search." />
        ) : (
          <div className="space-y-2">
            {filtered.map((r) => {
              const isSel = selectedId === r.id;
              return (
                <div
                  key={r.id}
                  className={cx(
                    "w-full rounded-lg border border-border/60 bg-background/20 px-3 py-2",
                    "hover:bg-muted/30",
                    isSel && "bg-muted/40"
                  )}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <div className="font-mono text-[12px] truncate">{r.id}</div>
                        {!r.enabled ? <Badge variant="neutral">disabled</Badge> : r.has_override ? <Badge variant="neutral">override</Badge> : null}
                        <Badge variant={sevVariant(r.severity)}>{r.severity}</Badge>
                      </div>

                      <div className="mt-1 text-[11px] text-muted-foreground line-clamp-2">
                        {r.description || r.name || r.type || "(no description)"}
                      </div>

                      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                        <div>{r.type || "-"}</div>
                        <div className="font-mono">
                          {r.window || "-"} · cd {r.cooldown || "-"}
                        </div>
                        {r.source_file ? <div className="font-mono truncate">src: {r.source_file}</div> : null}
                      </div>
                    </div>

                    <div className="shrink-0 flex items-center gap-2">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          openDrawerFor(r);
                        }}
                        className={cx(
                          "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                          "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                          "hover:bg-muted/15 hover:text-foreground",
                          "focus:outline-none focus:ring-2 focus:ring-primary/30"
                        )}
                        title="Open rule editor"
                      >
                        Edit
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Panel>

      <Drawer
        open={drawerOpen}
        onClose={closeDrawer}
        title={selected ? `Edit: ${selected.id}` : "Rule editor"}
        description={selected ? (selected.source_file ? `src: ${selected.source_file}` : "") : "Select a rule"}
        widthClassName="w-[920px]"
      >
        {!selected ? (
          <EmptyState title="No selection" description="Select a rule using the Edit button in the catalog." />
        ) : (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border/60 bg-background/20 px-4 py-3">
              <div className="min-w-0">
                <div className="text-sm font-semibold truncate">Rule override</div>
                <div className="text-[11px] text-muted-foreground">
                  Changes here are persisted as overrides; baseline YAML remains unchanged.
                </div>
              </div>

              <div className="flex items-center gap-2">
                {selected.has_override ? <Badge variant="neutral">override active</Badge> : <Badge variant="neutral">baseline only</Badge>}
                <button
                  onClick={handleSave}
                  disabled={saving}
                  className={cx(
                    "h-9 rounded-md bg-primary px-3 text-sm font-medium text-primary-foreground",
                    "hover:opacity-95 disabled:opacity-60"
                  )}
                  type="button"
                >
                  {saving ? "Saving…" : "Save"}
                </button>
                <button
                  onClick={handleReset}
                  disabled={saving || !selected.has_override}
                  className={cx(
                    "h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm",
                    "hover:bg-muted/30 disabled:opacity-60"
                  )}
                  type="button"
                  title="Remove overrides and revert to YAML"
                >
                  Reset
                </button>
              </div>
            </div>

            <div className="rounded-xl border border-border/60 bg-background/20 p-4 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold">Enabled</div>
                  <div className="text-[11px] text-muted-foreground">Disable to stop generating alerts for this rule.</div>
                </div>
                <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="h-4 w-4" />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Severity</div>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    className={cx(
                      "mt-1 h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none",
                      "focus:ring-1 focus:ring-primary/40"
                    )}
                  >
                    <option value="critical">critical</option>
                    <option value="high">high</option>
                    <option value="medium">medium</option>
                    <option value="low">low</option>
                    <option value="unknown">unknown</option>
                  </select>
                </div>

                <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Lookback window</div>
                  <input
                    value={window}
                    onChange={(e) => setWindow(e.target.value)}
                    className={cx(
                      "mt-1 h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none",
                      "focus:ring-1 focus:ring-primary/40"
                    )}
                    placeholder="e.g. 5m, 30s, 1h"
                  />
                  <div className="mt-1 text-[11px] text-muted-foreground">Time range used to query events.</div>
                </div>

                <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Cooldown</div>
                  <input
                    value={cooldown}
                    onChange={(e) => setCooldown(e.target.value)}
                    className={cx(
                      "mt-1 h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none",
                      "focus:ring-1 focus:ring-primary/40"
                    )}
                    placeholder="e.g. 10m"
                  />
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    Deduplicates alerts for the same target within the cooldown.
                  </div>
                </div>

                <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Min events (guard)</div>
                  <input
                    value={minEvents}
                    onChange={(e) => setMinEvents(e.target.value)}
                    className={cx(
                      "mt-1 h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none",
                      "focus:ring-1 focus:ring-primary/40"
                    )}
                    placeholder="optional"
                  />
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    Suppresses alerts until a minimum number of events exists.
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-border/60 bg-background/20 p-4 space-y-3">
              <div>
                <div className="text-sm font-semibold">Primary condition</div>
                <div className="text-[11px] text-muted-foreground">
                  Optional post-filter condition. If set, rule only triggers when the aggregated value matches.
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Operator</div>
                  <select
                    value={condOp}
                    onChange={(e) => setCondOp(e.target.value)}
                    className={cx(
                      "mt-1 h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none",
                      "focus:ring-1 focus:ring-primary/40"
                    )}
                  >
                    <option value=">=">{">="}</option>
                    <option value=">">{">"}</option>
                    <option value="==">{"=="}</option>
                    <option value="<">{"<"}</option>
                    <option value="<=">{"<="}</option>
                    <option value="!=">{"!="}</option>
                  </select>
                </div>

                <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2 md:col-span-2">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Value</div>
                  <input
                    value={condValue}
                    onChange={(e) => setCondValue(e.target.value)}
                    className={cx(
                      "mt-1 h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none",
                      "focus:ring-1 focus:ring-primary/40"
                    )}
                    placeholder="e.g. 10"
                  />
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    Leave empty to disable (no post-filter condition).
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-border/60 bg-background/20 p-4 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold">Schedule</div>
                  <div className="text-[11px] text-muted-foreground">
                    Optional time window to enable this rule (useful for “business hours only”, etc).
                  </div>
                </div>

                <label className="flex items-center gap-2 text-sm text-muted-foreground">
                  <input type="checkbox" checked={schedEnabled} onChange={(e) => setSchedEnabled(e.target.checked)} className="h-4 w-4" />
                  enabled
                </label>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Timezone</div>
                  <input
                    value={schedTz}
                    onChange={(e) => setSchedTz(e.target.value)}
                    className={cx(
                      "mt-1 h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none",
                      "focus:ring-1 focus:ring-primary/40"
                    )}
                    placeholder="America/Fortaleza"
                  />
                </div>

                <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Start</div>
                      <input
                        value={schedStart}
                        onChange={(e) => setSchedStart(e.target.value)}
                        className={cx(
                          "mt-1 h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none",
                          "focus:ring-1 focus:ring-primary/40"
                        )}
                        placeholder="22:00"
                      />
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">End</div>
                      <input
                        value={schedEnd}
                        onChange={(e) => setSchedEnd(e.target.value)}
                        className={cx(
                          "mt-1 h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none",
                          "focus:ring-1 focus:ring-primary/40"
                        )}
                        placeholder="06:00"
                      />
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Days</div>
                  <div className="flex items-center gap-2">
                    <button type="button" onClick={() => setAllDays(true)} className="text-[11px] text-muted-foreground hover:text-foreground">
                      all
                    </button>
                    <span className="text-muted-foreground">·</span>
                    <button type="button" onClick={() => setAllDays(false)} className="text-[11px] text-muted-foreground hover:text-foreground">
                      none
                    </button>
                  </div>
                </div>

                <div className="mt-2 flex flex-wrap gap-2">
                  {ALL_DAYS.map((d) => (
                    <button
                      key={d}
                      onClick={() => toggleDay(d)}
                      className={cx(
                        "rounded-md border border-border/60 px-2 py-1 text-[11px] font-mono",
                        schedDays[d] ? "bg-muted/40" : "bg-background/20 text-muted-foreground"
                      )}
                      type="button"
                      title="Toggle"
                    >
                      {d}
                    </button>
                  ))}
                </div>

                <div className="mt-2 text-[11px] text-muted-foreground">
                  Tip: if start is greater than end, the window crosses midnight (e.g., 22:00 → 06:00).
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-border/60 bg-background/20 p-4 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold">Advanced patch (JSON)</div>
                  <div className="text-[11px] text-muted-foreground">
                    Deep-merge applied last. Use to edit <span className="font-mono">match</span>, <span className="font-mono">distinct_conditions</span>, etc.
                  </div>
                </div>
              </div>

              {patchError ? (
                <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                  {patchError}
                </div>
              ) : null}

              <textarea
                value={patchText}
                onChange={(e) => setPatchText(e.target.value)}
                className={cx(
                  "min-h-[180px] w-full rounded-md border border-border/60 bg-background/40 p-3",
                  "text-[11px] font-mono leading-relaxed outline-none",
                  "focus:ring-1 focus:ring-primary/40"
                )}
                spellCheck={false}
              />
            </div>

            <div className="rounded-xl border border-border/60 bg-background/20">
              <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-border/60">
                <div className="text-sm font-semibold">Effective rule</div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] text-muted-foreground">Show</span>
                  <input type="checkbox" checked={showEffective} onChange={(e) => setShowEffective(e.target.checked)} className="h-4 w-4" />
                </div>
              </div>
              {showEffective ? (
                <pre className="p-4 text-[11px] leading-relaxed overflow-auto">{safeJsonString(selected.effective)}</pre>
              ) : (
                <div className="p-4 text-xs text-muted-foreground">Hidden (toggle “Show” to display).</div>
              )}
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
