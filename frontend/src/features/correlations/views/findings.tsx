import type { CSSProperties, ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";

import { Link } from "react-router-dom";

import { Badge } from "@/shared/components/Badge";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";

import SeverityFilter from "@/features/alerts/components/SeverityFilter";

import { runCorrelations } from "../api";
import type { CorrelationIncident, CorrelationRunOut } from "../types";

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
    <div
      className={cx(
        "rounded-xl border border-border/60 bg-background/70 backdrop-blur-md flex flex-col min-h-0",
        props.className
      )}
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-border/60 bg-muted/10">
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

function fmtTs(iso: string) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

function sevVariant(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
}

function safeJson(v: any) {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function FindingsTable(props: {
  rows: CorrelationIncident[];
  selectedId: string | null;
  onView: (x: CorrelationIncident) => void;
  density: Density;
}) {
  const dense = props.density === "compact";
  return (
    <div className="w-full overflow-auto">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
          <tr className="border-b border-border/60 text-muted-foreground">
            <th className="text-left font-medium px-3 py-2 w-[220px]">Window</th>
            <th className="text-left font-medium px-3 py-2 w-[120px]">Severity</th>
            <th className="text-left font-medium px-3 py-2 w-[260px]">Correlation rule</th>
            <th className="text-left font-medium px-3 py-2 w-[220px]">Group</th>
            <th className="text-left font-medium px-3 py-2 w-[100px]">Alerts</th>
            <th className="text-left font-medium px-3 py-2">Unique rules</th>
            <th className="text-right font-medium px-3 py-2 w-[120px]">Actions</th>
          </tr>
        </thead>

        <tbody>
          {props.rows.map((x) => {
            const selected = props.selectedId !== null && x.id === props.selectedId;
            const uniq = (x.unique_rules || []).slice(0, 4);
            return (
              <tr
                key={x.id}
                className={cx("border-b border-border/40 hover:bg-muted/30", selected && "bg-muted/40")}
              >
                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>
                  <div className="text-muted-foreground">{fmtTs(x.started_at)}</div>
                  <div className="text-muted-foreground">→ {fmtTs(x.ended_at)}</div>
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <Badge variant={sevVariant(String(x.severity || "unknown"))}>{String(x.severity || "unknown")}</Badge>
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <div className="font-mono text-[12px] truncate">{x.correlation_rule_name}</div>
                  <div className="text-[11px] text-muted-foreground">#{x.correlation_rule_id}</div>
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <div className="text-[11px] text-muted-foreground">{x.group_by}</div>
                  <div className="font-mono text-[12px] truncate" title={x.group_value}>
                    {x.group_value}
                  </div>
                </td>

                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>
                  {x.alert_count}
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  {uniq.length ? (
                    <div className="flex flex-wrap gap-2">
                      {uniq.map((u) => (
                        <span
                          key={u}
                          className="inline-flex items-center rounded-md border border-border/60 bg-background/30 px-2 py-0.5 text-[11px] font-mono"
                          title={u}
                        >
                          {u}
                        </span>
                      ))}
                      {(x.unique_rules || []).length > uniq.length ? (
                        <span className="text-[11px] text-muted-foreground">+{(x.unique_rules || []).length - uniq.length}</span>
                      ) : null}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">-</span>
                  )}
                </td>

                <td className={cx("px-3 text-right", dense ? "py-1.5" : "py-2")}>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      props.onView(x);
                    }}
                    className={cx(
                      "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                      "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                      "hover:bg-muted/15 hover:text-foreground",
                      "focus:outline-none focus:ring-2 focus:ring-primary/30"
                    )}
                    title="Open drawer"
                  >
                    View
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function CorrelationFindingsPage() {
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [payload, setPayload] = useState<CorrelationRunOut | null>(null);
  const [selected, setSelected] = useState<CorrelationIncident | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("all");
  const [density, setDensity] = useState<Density>("comfortable");

  const [limit, setLimit] = useState<number>(500);
  const [maxAge, setMaxAge] = useState<number>(1440);
  const [sampleLimit, setSampleLimit] = useState<number>(25);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [copied, setCopied] = useState(false);

  const reqSeq = useRef(0);

  async function run() {
    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);
    try {
      const out = await runCorrelations({ limit, max_age_minutes: maxAge, sample_limit: sampleLimit });
      if (reqSeq.current !== mySeq) return;
      setPayload(out);
      setLastRefresh(new Date());

      // keep selection only if still present
      setSelected((prev) => {
        if (!prev) return null;
const still = (out.incidents || []).find((x: CorrelationIncident) => x.id === prev.id);
        return still || null;
      });
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(e?.message || "Failed to run correlations");
      setPayload(null);
      setSelected(null);
      setDrawerOpen(false);
    } finally {
      if (reqSeq.current !== mySeq) return;
      setLoading(false);
    }
  }

  useEffect(() => {
    setRunning(true);
    run().finally(() => setRunning(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const incidents = payload?.incidents || [];

  const filtered = useMemo(() => {
    const qq = q.trim().toLowerCase();
    const sev = severity.toLowerCase();

    return incidents.filter((x) => {
      if (sev !== "all" && String(x.severity || "").toLowerCase() !== sev) return false;
      if (!qq) return true;
      const hay = [
        x.correlation_rule_name,
        x.group_by,
        x.group_value,
        ...(x.unique_rules || []),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(qq);
    });
  }, [incidents, q, severity]);

  const headerRight = useMemo(() => {
    if (loading) return "Running…";
    const base = `${filtered.length} findings · scanned ${payload?.alerts_scanned ?? 0} alerts · rules ${payload?.rules_evaluated ?? 0}`;
    if (!lastRefresh) return base;
    const hh = String(lastRefresh.getHours()).padStart(2, "0");
    const mm = String(lastRefresh.getMinutes()).padStart(2, "0");
    const ss = String(lastRefresh.getSeconds()).padStart(2, "0");
    return `${base} · refreshed ${hh}:${mm}:${ss}`;
  }, [filtered.length, loading, payload?.alerts_scanned, payload?.rules_evaluated, lastRefresh]);

  function openDrawerFor(x: CorrelationIncident) {
    setSelected(x);
    setDrawerOpen(true);
  }

  const detailsJson = useMemo(() => (selected ? safeJson(selected) : ""), [selected]);

  async function copyJson() {
    if (!detailsJson) return;
    try {
      await navigator.clipboard.writeText(detailsJson);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      // ignore
    }
  }

  const panelHeightClass = "h-[560px] xl:h-[calc(100vh-270px)]";

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <h2 className="text-lg font-semibold">Correlation findings</h2>
          <div className="text-xs text-muted-foreground">
            Group related alerts into incidents using portal-managed correlation rules.
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search rule, group, rule_id…"
            className={cx(
              "h-9 min-w-[220px] flex-1 rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none",
              "focus:ring-1 focus:ring-primary/40"
            )}
          />

          <SeverityFilter value={severity} onChange={setSeverity} />

          <select
            value={String(maxAge)}
            onChange={(e) => setMaxAge(Number(e.target.value))}
            className="h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none focus:ring-1 focus:ring-primary/40"
            title="Lookback window"
          >
            <option value={60}>Last 60m</option>
            <option value={360}>Last 6h</option>
            <option value={1440}>Last 24h</option>
            <option value={10080}>Last 7d</option>
          </select>

          <select
            value={String(limit)}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none focus:ring-1 focus:ring-primary/40"
            title="Alerts to scan"
          >
            <option value={200}>Scan 200</option>
            <option value={500}>Scan 500</option>
            <option value={1000}>Scan 1,000</option>
            <option value={2000}>Scan 2,000</option>
          </select>

          <select
            value={String(sampleLimit)}
            onChange={(e) => setSampleLimit(Number(e.target.value))}
            className="h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none focus:ring-1 focus:ring-primary/40"
            title="Sample size per incident"
          >
            <option value={10}>Sample 10</option>
            <option value={25}>Sample 25</option>
            <option value={50}>Sample 50</option>
          </select>

          <button
            onClick={() => setDensity((d) => (d === "comfortable" ? "compact" : "comfortable"))}
            className={cx("h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm", "hover:bg-muted/30")}
            title="Toggle row density"
          >
            {density === "compact" ? "Compact" : "Comfort"}
          </button>

          <button
            onClick={() => {
              setRunning(true);
              run().finally(() => setRunning(false));
            }}
            disabled={running}
            className={cx(
              "h-9 rounded-md bg-primary px-3 text-sm font-medium text-primary-foreground",
              "hover:opacity-95 disabled:opacity-60"
            )}
            title="Run correlations now"
          >
            {running ? "Running…" : "Run correlations"}
          </button>
        </div>
      </div>

      {error ? (
        <div className="rounded-xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      ) : null}

      <Panel title="Findings" right={headerRight} scrollY className={cx(panelHeightClass)}>
        {loading ? (
          <Loading label="Running correlations…" />
        ) : (payload?.rules_evaluated ?? 0) === 0 ? (
          <EmptyState
            title="No correlation rules"
            description={
              <div className="space-y-3">
                <div className="text-sm text-muted-foreground">
                  Create a correlation rule to start grouping alerts into higher-level incidents.
                </div>
                <div>
                  <Link
                    to="/correlations/rules"
                    className={cx(
                      "inline-flex h-9 items-center rounded-md bg-primary px-3 text-sm font-medium text-primary-foreground",
                      "hover:opacity-95"
                    )}
                  >
                    Go to rules
                  </Link>
                </div>
              </div>
            }
          />
        ) : filtered.length === 0 ? (
          <EmptyState
            title="No findings"
            description="No correlation incidents were found for the selected time range."
          />
        ) : (
          <FindingsTable rows={filtered} selectedId={selected?.id ?? null} onView={openDrawerFor} density={density} />
        )}
      </Panel>

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={selected ? selected.correlation_rule_name : "Finding"}
        description={selected ? `${selected.group_by} · ${selected.group_value}` : undefined}
        widthClassName="w-[980px]"
      >
        {!selected ? (
          <EmptyState title="No selection" description="Select a finding using the View button." />
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Badge variant={sevVariant(String(selected.severity || "unknown"))}>{String(selected.severity || "unknown")}</Badge>
                <div className="font-mono text-xs text-muted-foreground">rule #{selected.correlation_rule_id}</div>
                <div className="font-mono text-xs text-muted-foreground">alerts {selected.alert_count}</div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={copyJson}
                  className={cx(
                    "h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm",
                    "hover:bg-muted/30"
                  )}
                  title="Copy incident JSON to clipboard"
                >
                  {copied ? "Copied" : "Copy JSON"}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Window</div>
                <div className="font-mono text-sm truncate">
                  {fmtTs(selected.started_at)} → {fmtTs(selected.ended_at)}
                </div>
              </div>
              <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Group</div>
                <div className="font-mono text-sm truncate" title={selected.group_value}>
                  {selected.group_by}: {selected.group_value}
                </div>
              </div>
            </div>

            {Object.keys(selected.stage_hits || {}).length ? (
              <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Stage hits</div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {Object.entries(selected.stage_hits).map(([k, v]) => (
                    <span
                      key={k}
                      className="inline-flex items-center rounded-md border border-border/60 bg-background/40 px-2 py-0.5 text-[11px] font-mono"
                    >
                      {k}: {v}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="rounded-xl border border-border/60 bg-background/20">
              <div className="flex items-center justify-between gap-3 px-3 py-2 border-b border-border/60">
                <div className="text-[11px] font-semibold">Sample alerts</div>
                <div className="text-[11px] text-muted-foreground font-mono">showing {selected.sample_alerts.length}</div>
              </div>

              <div className="overflow-auto">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
                    <tr className="border-b border-border/60 text-muted-foreground">
                      <th className="text-left font-medium px-3 py-2 w-[180px]">Time</th>
                      <th className="text-left font-medium px-3 py-2 w-[120px]">Severity</th>
                      <th className="text-left font-medium px-3 py-2 w-[260px]">Rule</th>
                      <th className="text-left font-medium px-3 py-2 w-[200px]">Source</th>
                      <th className="text-left font-medium px-3 py-2 w-[220px]">Destination</th>
                      <th className="text-left font-medium px-3 py-2">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selected.sample_alerts.map((a) => (
                      <tr key={a.id} className="border-b border-border/40">
                        <td className="px-3 py-2 font-mono text-[12px] text-muted-foreground">{fmtTs(a.created_at)}</td>
                        <td className="px-3 py-2">
                          <Badge variant={sevVariant(String(a.severity || "unknown"))}>{String(a.severity || "unknown")}</Badge>
                        </td>
                        <td className="px-3 py-2 font-mono text-[12px]">{a.rule_id}</td>
                        <td className="px-3 py-2 font-mono text-[12px]">{a.src_ip || "-"}</td>
                        <td className="px-3 py-2 font-mono text-[12px]">
                          {a.dst_ip || "-"}
                          {typeof a.dst_port === "number" ? <span className="text-muted-foreground">:{a.dst_port}</span> : null}
                        </td>
                        <td className="px-3 py-2">
                          <div className="text-[12px] text-muted-foreground line-clamp-2">{a.description}</div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="rounded-xl border border-border/60 bg-background/20">
              <div className="flex items-center justify-between gap-3 px-3 py-2 border-b border-border/60">
                <div className="text-[11px] font-semibold">Raw incident (JSON)</div>
                <div className="text-[11px] text-muted-foreground font-mono">{selected.id}</div>
              </div>
              <pre className="p-3 text-[11px] leading-relaxed overflow-auto whitespace-pre-wrap break-words">{detailsJson}</pre>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
