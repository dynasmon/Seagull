import type { CSSProperties, ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";

import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";

import { getRecentAlerts, runAllRules } from "../api";
import AlertsTable from "../components/AlertsTable";
import SeverityFilter from "../components/SeverityFilter";
import type { Alert } from "../types";

const DEFAULT_LIMIT = 500;

type ViewMode = "balanced" | "focusQueue" | "focusDetails";
type Density = "comfortable" | "compact";

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
    <div className={cx("rounded-xl border border-border/60 bg-card/10 backdrop-blur-md flex flex-col min-h-0", props.className)}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-border/60">
        <div className="text-sm font-semibold tracking-tight truncate">{props.title}</div>
        {props.right ? <div className="text-xs text-muted-foreground truncate">{props.right}</div> : null}
      </div>

      <div
        className={cx("p-4 min-h-0", props.scrollY && "overflow-y-auto", props.bodyClassName)}
        style={props.style}
      >
        {props.children}
      </div>
    </div>
  );
}

function safeJson(v: any) {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function Segmented(props: {
  value: ViewMode;
  onChange: (v: ViewMode) => void;
  className?: string;
}) {
  const items: Array<{ v: ViewMode; label: string }> = [
    { v: "balanced", label: "Split" },
    { v: "focusQueue", label: "Focus queue" },
    { v: "focusDetails", label: "Focus details" }
  ];

  return (
    <div className={cx("flex rounded-md border border-border/60 bg-background/40", props.className)}>
      {items.map((it) => {
        const active = props.value === it.v;
        return (
          <button
            key={it.v}
            type="button"
            onClick={() => props.onChange(it.v)}
            className={cx(
              "h-9 px-3 text-sm",
              "hover:bg-muted/30",
              active ? "bg-muted/40 text-foreground" : "text-muted-foreground"
            )}
          >
            {it.label}
          </button>
        );
      })}
    </div>
  );
}

export default function AlertsQueuePage() {
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [severity, setSeverity] = useState("all");
  const [q, setQ] = useState("");
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  // UI preferences
  const [view, setView] = useState<ViewMode>("balanced");
  const [wrapJson, setWrapJson] = useState(true);
  const [density, setDensity] = useState<Density>("comfortable");
  const [limit, setLimit] = useState<number>(DEFAULT_LIMIT);
  const [copied, setCopied] = useState(false);

  const reqSeq = useRef(0);

  async function reload() {
    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);
    try {
      const payload = await getRecentAlerts({ limit });
      if (reqSeq.current !== mySeq) return;
      setAlerts(payload);
      setSelected((prev) => {
        if (!prev) return payload[0] || null;
        const still = payload.find((x) => x.id === prev.id);
        return still || payload[0] || null;
      });
      setLastRefresh(new Date());
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(e?.message || "Failed to load alerts");
      setAlerts([]);
      setSelected(null);
    } finally {
      if (reqSeq.current !== mySeq) return;
      setLoading(false);
    }
  }

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    // reload when user changes limit
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [limit]);

  const filtered = useMemo(() => {
    const qq = q.trim().toLowerCase();
    const sev = severity.toLowerCase();
    return (alerts || []).filter((a) => {
      if (sev !== "all" && String(a.severity || "").toLowerCase() !== sev) return false;
      if (!qq) return true;
      const hay = [a.rule_id, a.src_ip, a.dst_ip, a.description].filter(Boolean).join(" ").toLowerCase();
      return hay.includes(qq);
    });
  }, [alerts, q, severity]);

  const headerRight = useMemo(() => {
    if (loading) return "Loading…";
    const base = `${filtered.length} alerts`;
    if (!lastRefresh) return base;
    const hh = String(lastRefresh.getHours()).padStart(2, "0");
    const mm = String(lastRefresh.getMinutes()).padStart(2, "0");
    const ss = String(lastRefresh.getSeconds()).padStart(2, "0");
    return `${base} · refreshed ${hh}:${mm}:${ss}`;
  }, [filtered.length, lastRefresh, loading]);

  async function handleRunAll() {
    setRunning(true);
    setError(null);
    try {
      await runAllRules();
      await reload();
    } catch (e: any) {
      setError(e?.message || "Failed to run rules");
    } finally {
      setRunning(false);
    }
  }

  const gridSpans = useMemo(() => {
    // IMPORTANT: keep explicit Tailwind classes (no dynamic col-span strings), otherwise JIT might not include them.
    if (view === "focusQueue") return { left: "xl:col-span-8", right: "xl:col-span-4" };
    if (view === "focusDetails") return { left: "xl:col-span-4", right: "xl:col-span-8" };
    return { left: "xl:col-span-6", right: "xl:col-span-6" };
  }, [view]);

  const panelHeightClass = "h-[560px] xl:h-[calc(100vh-270px)]";

  const detailsJson = useMemo(() => {
    if (!selected) return "";
    return safeJson({
      id: selected.id,
      severity: selected.severity,
      rule_id: selected.rule_id,
      src_ip: selected.src_ip,
      dst_ip: selected.dst_ip,
      dst_port: selected.dst_port,
      created_at: selected.created_at,
      description: selected.description,
      details: selected.details
    });
  }, [selected]);

  async function copyDetailsJson() {
    if (!detailsJson) return;
    try {
      await navigator.clipboard.writeText(detailsJson);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      // ignore
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <h2 className="text-lg font-semibold">Alert queue</h2>
          <div className="text-xs text-muted-foreground">
            Inspect alerts generated by rules. Use the <span className="text-foreground">Rules</span> tab to tune detection.
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search rule, IP, description…"
            className={cx(
              "h-9 min-w-[220px] flex-1 rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none",
              "focus:ring-1 focus:ring-primary/40"
            )}
          />

          <SeverityFilter value={severity} onChange={setSeverity} />

          <select
            value={String(limit)}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none focus:ring-1 focus:ring-primary/40"
            title="Rows to fetch"
          >
            <option value="100">Last 100</option>
            <option value="500">Last 500</option>
            <option value="1000">Last 1000</option>
          </select>

          <Segmented value={view} onChange={setView} className="hidden 2xl:flex" />

          <button
            onClick={() => setDensity((d) => (d === "comfortable" ? "compact" : "comfortable"))}
            className={cx(
              "h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm",
              "hover:bg-muted/30"
            )}
            title="Toggle row density"
          >
            {density === "compact" ? "Compact" : "Comfort"}
          </button>

          <button
            onClick={() => reload()}
            disabled={loading}
            className={cx(
              "h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm",
              "hover:bg-muted/30 disabled:opacity-60"
            )}
            title="Refresh"
          >
            Refresh
          </button>

          <button
            onClick={handleRunAll}
            disabled={running}
            className={cx(
              "h-9 rounded-md bg-primary px-3 text-sm font-medium text-primary-foreground",
              "hover:opacity-95 disabled:opacity-60"
            )}
            title="Run all rules now"
          >
            {running ? "Running…" : "Run rules"}
          </button>
        </div>
      </div>

      {/* lightweight view toggle for smaller screens */}
      <div className="2xl:hidden">
        <Segmented value={view} onChange={setView} />
      </div>

      {error ? (
        <div className="rounded-xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      ) : null}

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        <Panel
          title="Queue"
          right={headerRight}
          scrollY
          className={cx(panelHeightClass, gridSpans.left, "xl:col-start-1")}
        >
          {loading ? (
            <Loading label="Loading alerts…" />
          ) : filtered.length === 0 ? (
            <EmptyState title="No alerts" description="No alerts match the current filters." />
          ) : (
            <AlertsTable rows={filtered} selectedId={selected?.id ?? null} onSelect={(a) => setSelected(a)} density={density} />
          )}
        </Panel>

        <Panel
          title="Details"
          right={selected ? selected.rule_id : "Select an alert"}
          scrollY
          className={cx(panelHeightClass, gridSpans.right)}
          bodyClassName="space-y-4"
        >
          {!selected ? (
            <EmptyState title="No selection" description="Select an alert in the table to view details." />
          ) : (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-2">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Source</div>
                  <div className="font-mono text-sm truncate">{selected.src_ip || "-"}</div>
                </div>
                <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-2">
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Destination</div>
                  <div className="font-mono text-sm truncate">
                    {selected.dst_ip || "-"}
                    {typeof selected.dst_port === "number" ? `:${selected.dst_port}` : ""}
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Description</div>
                <div className="text-sm leading-relaxed">{selected.description || ""}</div>
              </div>

              <div className="rounded-xl border border-border/60 bg-background/20">
                <div className="flex items-center justify-between gap-3 px-3 py-2 border-b border-border/60">
                  <div className="text-[11px] font-semibold">Raw event (JSON)</div>
                  <div className="flex items-center gap-3">
                    <label className="flex items-center gap-2 text-[11px] text-muted-foreground select-none">
                      <input type="checkbox" checked={wrapJson} onChange={(e) => setWrapJson(e.target.checked)} className="h-4 w-4" />
                      Wrap
                    </label>
                    <button
                      type="button"
                      onClick={copyDetailsJson}
                      className={cx(
                        "h-8 rounded-md border border-border/60 bg-background/40 px-2 text-[11px]",
                        "hover:bg-muted/30"
                      )}
                      title="Copy JSON to clipboard"
                    >
                      {copied ? "Copied" : "Copy"}
                    </button>
                  </div>
                </div>

                <pre
                  className={cx(
                    "p-3 text-[11px] leading-relaxed overflow-auto",
                    wrapJson ? "whitespace-pre-wrap break-words" : "whitespace-pre"
                  )}
                >
                  {detailsJson}
                </pre>
              </div>
            </>
          )}
        </Panel>
      </div>
    </div>
  );
}
