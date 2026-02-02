import type { CSSProperties, ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { Badge } from "@/shared/components/Badge";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";

import { getRecentAlerts, runAllRules } from "../api";
import SeverityFilter from "../components/SeverityFilter";
import type { Alert } from "../types";

const DEFAULT_LIMIT = 500;
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

      <div className={cx("p-4 min-h-0", props.scrollY && "overflow-y-auto", props.bodyClassName)} style={props.style}>
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

function fmtTs(ts: string) {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
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

function AlertsQueueTable(props: {
  rows: Alert[];
  selectedId: number | null;
  onEdit: (a: Alert) => void;
  density?: Density;
}) {
  const dense = props.density === "compact";

  return (
    <div className="w-full overflow-auto">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
          <tr className="border-b border-border/60 text-muted-foreground">
            <th className="text-left font-medium px-3 py-2 w-[180px]">Time</th>
            <th className="text-left font-medium px-3 py-2 w-[120px]">Severity</th>
            <th className="text-left font-medium px-3 py-2 w-[260px]">Rule</th>
            <th className="text-left font-medium px-3 py-2 w-[180px]">Source</th>
            <th className="text-left font-medium px-3 py-2 w-[220px]">Destination</th>
            <th className="text-left font-medium px-3 py-2">Description</th>
            <th className="text-right font-medium px-3 py-2 w-[120px]">Actions</th>
          </tr>
        </thead>

        <tbody>
          {props.rows.map((a) => {
            const selected = props.selectedId !== null && a.id === props.selectedId;
            return (
              <tr
                key={a.id}
                className={cx(
                  "border-b border-border/40 hover:bg-muted/30",
                  selected && "bg-muted/40"
                )}
              >
                <td className={cx("px-3 font-mono text-[12px] text-muted-foreground", dense ? "py-1.5" : "py-2")}>
                  {fmtTs(a.created_at)}
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <Badge variant={sevVariant(String(a.severity || "unknown"))}>{String(a.severity || "unknown")}</Badge>
                </td>

                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>{a.rule_id}</td>

                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>
                  {a.src_ip || <span className="text-muted-foreground">-</span>}
                </td>

                <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}>
                  {a.dst_ip ? <span>{a.dst_ip}</span> : <span className="text-muted-foreground">-</span>}
                  {typeof a.dst_port === "number" ? <span className="text-muted-foreground">:{a.dst_port}</span> : null}
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <div className="text-[12px] text-muted-foreground line-clamp-2">{a.description || ""}</div>
                </td>

                <td className={cx("px-3 text-right", dense ? "py-1.5" : "py-2")}>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      props.onEdit(a);
                    }}
                    className={cx(
                      "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                      "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                      "hover:bg-muted/15 hover:text-foreground",
                      "focus:outline-none focus:ring-2 focus:ring-primary/30"
                    )}
                    title="Open drawer"
                  >
                    Edit
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

export default function AlertsQueuePage() {
  const nav = useNavigate();

  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const [severity, setSeverity] = useState("all");
  const [q, setQ] = useState("");
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  // UI preferences
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

      // keep selection only if still present
      setSelected((prev) => {
        if (!prev) return null;
        const still = payload.find((x) => x.id === prev.id);
        return still || null;
      });

      setLastRefresh(new Date());

      // if selection vanished while drawer is open, close it
      if (drawerOpen && selected) {
        const still = payload.find((x) => x.id === selected.id);
        if (!still) setDrawerOpen(false);
      }
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(e?.message || "Failed to load alerts");
      setAlerts([]);
      setSelected(null);
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

  useEffect(() => {
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

  function openDrawerFor(a: Alert) {
    setSelected(a);
    setDrawerOpen(true);
  }

  function openRuleEditor() {
    if (!selected?.rule_id) return;
    nav(`/alerts/rules?rule_id=${encodeURIComponent(selected.rule_id)}`);
  }

  const panelHeightClass = "h-[560px] xl:h-[calc(100vh-270px)]";

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

          <button
            onClick={() => setDensity((d) => (d === "comfortable" ? "compact" : "comfortable"))}
            className={cx("h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm", "hover:bg-muted/30")}
            title="Toggle row density"
          >
            {density === "compact" ? "Compact" : "Comfort"}
          </button>

          <button
            onClick={() => reload()}
            disabled={loading}
            className={cx("h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm", "hover:bg-muted/30 disabled:opacity-60")}
            title="Refresh"
          >
            Refresh
          </button>

          <button
            onClick={handleRunAll}
            disabled={running}
            className={cx("h-9 rounded-md bg-primary px-3 text-sm font-medium text-primary-foreground", "hover:opacity-95 disabled:opacity-60")}
            title="Run all rules now"
          >
            {running ? "Running…" : "Run rules"}
          </button>
        </div>
      </div>

      {error ? (
        <div className="rounded-xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      ) : null}

      <Panel title="Queue" right={headerRight} scrollY className={cx(panelHeightClass)}>
        {loading ? (
          <Loading label="Loading alerts…" />
        ) : filtered.length === 0 ? (
          <EmptyState title="No alerts" description="No alerts match the current filters." />
        ) : (
          <AlertsQueueTable rows={filtered} selectedId={selected?.id ?? null} onEdit={openDrawerFor} density={density} />
        )}
      </Panel>

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={selected ? `Alert #${selected.id}` : "Alert"}
        description={selected ? `${selected.rule_id} · ${fmtTs(selected.created_at)}` : undefined}
        widthClassName="w-[860px]"
      >
        {!selected ? (
          <EmptyState title="No selection" description="Select an alert using the Edit button." />
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Badge variant={sevVariant(String(selected.severity || "unknown"))}>{String(selected.severity || "unknown")}</Badge>
                <div className="font-mono text-xs text-muted-foreground">{selected.rule_id}</div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={openRuleEditor}
                  className={cx(
                    "h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm",
                    "hover:bg-muted/30"
                  )}
                  title="Open rule editor"
                >
                  Edit rule
                </button>

                <button
                  type="button"
                  onClick={copyDetailsJson}
                  className={cx(
                    "h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm",
                    "hover:bg-muted/30"
                  )}
                  title="Copy JSON to clipboard"
                >
                  {copied ? "Copied" : "Copy JSON"}
                </button>
              </div>
            </div>

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
                <label className="flex items-center gap-2 text-[11px] text-muted-foreground select-none">
                  <input type="checkbox" checked={wrapJson} onChange={(e) => setWrapJson(e.target.checked)} className="h-4 w-4" />
                  Wrap
                </label>
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
          </div>
        )}
      </Drawer>
    </div>
  );
}
