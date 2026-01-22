import type { CSSProperties, ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";

import { useAgentsCatalog } from "@/app/providers";

import { getOverview } from "@/features/overview/api";
import { SimpleTimeSeries } from "@/features/overview/components/Charts";
import type { OverviewSnapshot } from "@/features/overview/types";

import { getRecentEvents } from "@/features/events/api";
import EventsTable from "@/features/events/components/EventsTable";
import type { NetEvent } from "@/features/events/types";

import { disableAgent, enableAgent, getAgent, setAgentConfig, updateAgent } from "./api";
import type { AgentDetail, AgentPublic, AgentUpdateIn } from "./types";

// Grafana-like fixed panel heights.
const H_PANEL_SM = 240;
const H_PANEL_MD = 320;
const H_PANEL_STREAM = 520;

const DEFAULT_WINDOW_MINUTES = 60;
const DEFAULT_EVENTS_LIMIT = 500;
const DEFAULT_POLL_MS = 5000;

function fmtDateTime(d: Date) {
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

function safeJsonParse(text: string): { ok: true; value: any } | { ok: false; error: string } {
  try {
    const v = JSON.parse(text);
    return { ok: true, value: v };
  } catch (e: any) {
    return { ok: false, error: e?.message || "Invalid JSON" };
  }
}

function normalizeTags(raw: string): string[] {
  return raw
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
    .filter((v, idx, arr) => arr.indexOf(v) === idx);
}

function isOnline(lastSeenAt?: string | null): boolean {
  if (!lastSeenAt) return false;
  const t = new Date(lastSeenAt).getTime();
  if (!Number.isFinite(t)) return false;
  return Date.now() - t <= 5 * 60_000;
}

function Switch({
  checked,
  onChange,
  disabled,
  label
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  label: string;
}) {
  return (
    <div className={cx("flex items-center justify-between gap-3", disabled && "opacity-60")}> 
      <span className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
        {label}
      </span>

      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cx(
          "relative inline-flex h-6 w-11 items-center rounded-full border border-border/60",
          "bg-background/40 transition-colors",
          "focus:outline-none focus:ring-2 focus:ring-primary/30",
          "disabled:cursor-not-allowed",
          checked && "bg-primary/15"
        )}
      >
        <span
          className={cx(
            "inline-block h-5 w-5 transform rounded-full bg-foreground/80",
            "transition-transform",
            checked ? "translate-x-5" : "translate-x-1"
          )}
        />
      </button>
    </div>
  );
}

function Panel({
  title,
  right,
  children,
  scrollY = false,
  className = "",
  style
}: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  scrollY?: boolean;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <div className={cx("border border-border/60 bg-background/70 backdrop-blur-sm flex flex-col", className)} style={style}>
      <div className="flex items-center justify-between border-b border-border/60 bg-muted/10 px-3 py-2 shrink-0">
        <h3 className="text-xs font-bold uppercase tracking-widest font-mono text-primary/90">{title}</h3>
        {right && <div className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">{right}</div>}
      </div>
      <div className={cx("p-3 flex-1 min-h-0", scrollY ? "overflow-y-auto" : "overflow-hidden")}>{children}</div>
    </div>
  );
}

function StatTile({
  label,
  value,
  hint,
  tone = "default"
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "default" | "good" | "warn";
}) {
  const valueClass =
    tone === "warn" ? "text-red-500" : tone === "good" ? "text-green-500" : "text-foreground";

  return (
    <div className="border border-border/60 bg-background/80 backdrop-blur-md px-4 py-3">
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1 font-mono">{label}</div>
      <div className={cx("text-3xl font-bold font-mono tracking-tight leading-none", valueClass)}>{value}</div>
      {hint && <div className="text-[10px] text-muted-foreground font-mono opacity-70 mt-1">{hint}</div>}
    </div>
  );
}

function inputClassName(disabled?: boolean) {
  return cx(
    "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-sm text-foreground outline-none",
    "placeholder:text-muted-foreground/60",
    "focus:ring-2 focus:ring-primary/30",
    disabled && "opacity-60 cursor-not-allowed"
  );
}

function textAreaClassName(disabled?: boolean) {
  return cx(
    "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-sm text-foreground outline-none",
    "placeholder:text-muted-foreground/60",
    "focus:ring-2 focus:ring-primary/30",
    "font-mono text-[12px]",
    disabled && "opacity-60 cursor-not-allowed"
  );
}

function FieldLabel({ children }: { children: ReactNode }) {
  return <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">{children}</div>;
}

function prettyJson(v: any) {
  try {
    return JSON.stringify(v ?? {}, null, 2);
  } catch {
    return "{}";
  }
}

function pickTimingKeys(config: Record<string, any>): string[] {
  const keys: string[] = [];
  const re = /(interval|window|timeout|ttl|period|rate|cooldown|delay|heartbeat)/i;
  for (const k of Object.keys(config || {})) {
    const v = (config as any)[k];
    if (!re.test(k)) continue;
    if (typeof v === "number" && Number.isFinite(v)) keys.push(k);
  }
  return keys.sort().slice(0, 12);
}

export default function AgentsPage() {
  const { agents, selectedAgentId, setSelectedAgentId, refresh } = useAgentsCatalog();
  const [searchParams, setSearchParams] = useSearchParams();

  const [agent, setAgent] = useState<AgentDetail | null>(null);
  const [agentLoading, setAgentLoading] = useState(false);
  const [agentError, setAgentError] = useState<string | null>(null);

  const [snapshot, setSnapshot] = useState<OverviewSnapshot | null>(null);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [telemetryError, setTelemetryError] = useState<string | null>(null);

  const [autoRefresh, setAutoRefresh] = useState(true);
  const [pollMs, setPollMs] = useState(DEFAULT_POLL_MS);
  const [windowMinutes, setWindowMinutes] = useState(DEFAULT_WINDOW_MINUTES);
  const [eventsLimit, setEventsLimit] = useState(DEFAULT_EVENTS_LIMIT);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);

  const [draftName, setDraftName] = useState("");
  const [draftDesc, setDraftDesc] = useState("");
  const [draftTags, setDraftTags] = useState("");
  const [draftMetaText, setDraftMetaText] = useState("{}");

  const [configText, setConfigText] = useState("{}");
  const [configObj, setConfigObj] = useState<Record<string, any>>({});
  const [configParseError, setConfigParseError] = useState<string | null>(null);

  const [saveBusy, setSaveBusy] = useState(false);
  const [configBusy, setConfigBusy] = useState(false);
  const [toggleBusy, setToggleBusy] = useState(false);

  const inFlightTelemetry = useRef(false);

  const lastUrlId = useRef<string | null>(null);

  useEffect(() => {
    const q = (searchParams.get("agent_id") || "").trim();

    // Só aplica quando de fato houve mudança na URL
    if (lastUrlId.current === q) return;
    lastUrlId.current = q;

    setSelectedAgentId(q);
  }, [searchParams, setSelectedAgentId]);

  const selectedAgentRow = useMemo<AgentPublic | null>(() => {
    if (!selectedAgentId) return null;
    return agents.find((a) => a.agent_id === selectedAgentId) || null;
  }, [agents, selectedAgentId]);

  const loadAgent = useCallback(async (agentId: string) => {
    setAgentLoading(true);
    try {
      const a = await getAgent(agentId);
      setAgent(a);
      setAgentError(null);

      setDraftName(a.display_name || "");
      setDraftDesc(a.description || "");
      setDraftTags((a.tags || []).join(", "));
      setDraftMetaText(prettyJson(a.metadata || {}));

      setConfigObj(a.config || {});
      setConfigText(prettyJson(a.config || {}));
      setConfigParseError(null);
    } catch (e: any) {
      setAgentError(e?.message || "Failed to load agent details");
      setAgent(null);
    } finally {
      setAgentLoading(false);
    }
  }, []);

  const loadTelemetry = useCallback(async (agentId: string) => {
    if (inFlightTelemetry.current) return;
    inFlightTelemetry.current = true;

    try {
      const [snap, ev] = await Promise.all([
        getOverview({ window_minutes: windowMinutes, agent_id: agentId }),
        getRecentEvents({ limit: eventsLimit, agent_id: agentId })
      ]);
      setSnapshot(snap);
      setEvents(ev);
      setTelemetryError(null);
      setLastUpdatedAt(new Date());
    } catch (e: any) {
      setTelemetryError(e?.message || "Failed to load telemetry");
    } finally {
      inFlightTelemetry.current = false;
    }
  }, [eventsLimit, windowMinutes]);

  // Recarrega os dados quando o selectedAgentId muda
  useEffect(() => {
    if (!selectedAgentId) {
      // Limpa os dados se nenhum agente estiver selecionado
      setAgent(null);
      setSnapshot(null);
      setEvents([]);
      return;
    }
    loadAgent(selectedAgentId);
    loadTelemetry(selectedAgentId);
  }, [selectedAgentId, loadAgent, loadTelemetry]);

  useEffect(() => {
    if (!selectedAgentId) return;
    if (!autoRefresh) return;

    const t = window.setInterval(() => {
      loadTelemetry(selectedAgentId);
      refresh();
    }, Math.max(2000, pollMs));

    return () => window.clearInterval(t);
  }, [selectedAgentId, autoRefresh, pollMs, loadTelemetry, refresh]);

  const timingKeys = useMemo(() => pickTimingKeys(configObj), [configObj]);

  const dirty = useMemo(() => {
    if (!agent) return false;
    const desiredTags = normalizeTags(draftTags);
    const currentTags = (agent.tags || []).slice().sort();
    const desiredSorted = desiredTags.slice().sort();

    const meta = safeJsonParse(draftMetaText);
    const metaObj = meta.ok && typeof meta.value === "object" && meta.value ? meta.value : null;

    const nameChanged = (agent.display_name || "") !== draftName;
    const descChanged = (agent.description || "") !== draftDesc;
    const tagsChanged = JSON.stringify(currentTags) !== JSON.stringify(desiredSorted);
    const metaChanged = metaObj ? JSON.stringify(agent.metadata || {}) !== JSON.stringify(metaObj) : false;

    return nameChanged || descChanged || tagsChanged || metaChanged;
  }, [agent, draftName, draftDesc, draftTags, draftMetaText]);

  const canSaveAgent = useMemo(() => {
    if (!agent) return false;
    const meta = safeJsonParse(draftMetaText);
    if (!meta.ok) return false;
    if (meta.ok && (meta.value === null || typeof meta.value !== "object" || Array.isArray(meta.value))) return false;
    return dirty && !saveBusy;
  }, [agent, draftMetaText, dirty, saveBusy]);

  const onSaveAgent = async () => {
    if (!agent) return;

    const meta = safeJsonParse(draftMetaText);
    if (!meta.ok) {
      setAgentError(`Metadata JSON: ${meta.error}`);
      return;
    }
    if (meta.value === null || typeof meta.value !== "object" || Array.isArray(meta.value)) {
      setAgentError("Metadata must be a JSON object");
      return;
    }

    const patch: AgentUpdateIn = {
      display_name: draftName.trim() || null,
      description: draftDesc.trim() || null,
      tags: normalizeTags(draftTags),
      metadata: meta.value
    };

    setSaveBusy(true);
    try {
      const updated = await updateAgent(agent.agent_id, patch);
      setAgent(updated);
      setAgentError(null);
      refresh();
    } catch (e: any) {
      setAgentError(e?.message || "Failed to update agent");
    } finally {
      setSaveBusy(false);
    }
  };

  const onToggleRevoked = async () => {
    if (!agent) return;
    setToggleBusy(true);
    try {
      const updated = agent.is_revoked
        ? await enableAgent(agent.agent_id)
        : await disableAgent(agent.agent_id);
      setAgent(updated);
      setAgentError(null);
      refresh();
    } catch (e: any) {
      setAgentError(e?.message || "Failed to update agent state");
    } finally {
      setToggleBusy(false);
    }
  };

  const onApplyConfig = async () => {
    if (!agent) return;

    const parsed = safeJsonParse(configText);
    if (!parsed.ok) {
      setConfigParseError(parsed.error);
      return;
    }
    if (parsed.value === null || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
      setConfigParseError("Config must be a JSON object");
      return;
    }

    setConfigBusy(true);
    try {
      const updated = await setAgentConfig(agent.agent_id, parsed.value as Record<string, any>);
      setAgent(updated);
      setConfigObj(updated.config || {});
      setConfigText(prettyJson(updated.config || {}));
      setConfigParseError(null);
      setAgentError(null);
    } catch (e: any) {
      setAgentError(e?.message || "Failed to push config");
    } finally {
      setConfigBusy(false);
    }
  };

  const onConfigTextChange = (v: string) => {
    setConfigText(v);
    const parsed = safeJsonParse(v);
    if (!parsed.ok) {
      setConfigParseError(parsed.error);
      return;
    }
    if (parsed.value === null || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
      setConfigParseError("Config must be a JSON object");
      return;
    }
    setConfigParseError(null);
    setConfigObj(parsed.value as Record<string, any>);
  };

  const onUpdateTiming = (key: string, value: number) => {
    const next = { ...(configObj || {}) };
    next[key] = value;
    setConfigObj(next);
    setConfigText(prettyJson(next));
    setConfigParseError(null);
  };

  const topStats = useMemo(() => {
    const last = selectedAgentRow?.last_seen_at ? new Date(selectedAgentRow.last_seen_at) : null;
    const online = isOnline(selectedAgentRow?.last_seen_at);
    const status = selectedAgentRow?.is_revoked ? "Disabled" : online ? "Online" : "Offline";
    return {
      status,
      online,
      lastSeen: last ? fmtDateTime(last) : "-"
    };
  }, [selectedAgentRow]);

  const charts = useMemo(() => {
    if (!snapshot) {
      return {
        traffic: null as null | { series: string[]; data: Array<Record<string, any>> },
        ssh: null as null | { series: string[]; data: Array<Record<string, any>> },
        ddos: null as null | { series: string[]; data: Array<Record<string, any>> },
        sev: null as null | { series: string[]; data: Array<Record<string, any>> }
      };
    }
    return {
      traffic: snapshot.traffic,
      ssh: snapshot.ssh_failures,
      ddos: snapshot.ddos,
      sev: snapshot.alert_severity
    };
  }, [snapshot]);

  const eventsRate = useMemo(() => {
    if (!snapshot) return "-";
    return String(snapshot.kpis.events_5m);
  }, [snapshot]);

  // --- RENDER ---

  if (!selectedAgentId) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-semibold">Agents</h1>
        <div className="min-h-[60vh] flex flex-col items-center justify-center border border-dashed border-border/60 bg-background/20 rounded-lg">
          <EmptyState
            title="No Agent Selected"
            hint="Select an agent from the sidebar to view details, configure settings, and inspect telemetry."
          />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <span className="text-muted-foreground font-normal">Agent /</span>
            <span>{agent?.display_name || selectedAgentId}</span>
          </h1>
          <div className="text-sm text-muted-foreground font-mono text-[11px] opacity-70">
            ID: {selectedAgentId}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => {
              loadAgent(selectedAgentId);
              loadTelemetry(selectedAgentId);
              refresh();
            }}
            className={cx(
              "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
              "hover:bg-primary/5"
            )}
          >
            Refresh
          </button>

          <div className="border border-border/60 bg-background/40 px-3 py-2 flex items-center gap-3">
            <Switch checked={autoRefresh} onChange={setAutoRefresh} label="Auto refresh" />
          </div>

          <select
            className={cx(
              "border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
              "focus:ring-2 focus:ring-primary/30"
            )}
            value={String(pollMs)}
            onChange={(e) => setPollMs(Number(e.target.value))}
            disabled={!autoRefresh}
          >
            <option value={2000}>2s</option>
            <option value={5000}>5s</option>
            <option value={10000}>10s</option>
            <option value={30000}>30s</option>
          </select>

          {lastUpdatedAt && (
            <div className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">
              Updated {fmtDateTime(lastUpdatedAt)}
            </div>
          )}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        {/* LEFT COLUMN: MANAGEMENT (Identity, Config) */}
        <div className="xl:col-span-4 space-y-4">
          <Panel
            title="Identity & State"
            right={agent?.is_revoked ? "Disabled" : "Enabled"}
            scrollY
            style={{ height: H_PANEL_MD }}
          >
            {agentLoading ? (
              <Loading label="Loading agent details..." />
            ) : !agent ? (
              <EmptyState title="Agent not loaded" hint="Check connectivity and admin token." />
            ) : (
              <div className="space-y-4">
                <div>
                  <FieldLabel>Display name</FieldLabel>
                  <input
                    className={inputClassName(saveBusy)}
                    value={draftName}
                    onChange={(e) => setDraftName(e.target.value)}
                    placeholder="e.g., Web Server - PROD"
                    disabled={saveBusy}
                  />
                </div>

                <div>
                  <FieldLabel>Description</FieldLabel>
                  <input
                    className={inputClassName(saveBusy)}
                    value={draftDesc}
                    onChange={(e) => setDraftDesc(e.target.value)}
                    placeholder="Short context about what this agent protects"
                    disabled={saveBusy}
                  />
                </div>

                <div>
                  <FieldLabel>Tags</FieldLabel>
                  <input
                    className={inputClassName(saveBusy)}
                    value={draftTags}
                    onChange={(e) => setDraftTags(e.target.value)}
                    placeholder="prod, web, ssh, dmz"
                    disabled={saveBusy}
                  />
                  <div className="mt-1 text-[11px] text-muted-foreground">Comma-separated.</div>
                </div>

                <div>
                  <FieldLabel>Metadata (JSON)</FieldLabel>
                  <textarea
                    className={textAreaClassName(saveBusy)}
                    rows={4}
                    value={draftMetaText}
                    onChange={(e) => setDraftMetaText(e.target.value)}
                    disabled={saveBusy}
                  />
                </div>

                <div className="flex items-center justify-between gap-3 pt-2">
                  <button
                    type="button"
                    onClick={onSaveAgent}
                    disabled={!canSaveAgent}
                    className={cx(
                      "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                      "hover:bg-primary/5",
                      (!canSaveAgent || saveBusy) && "opacity-60 cursor-not-allowed"
                    )}
                  >
                    {saveBusy ? "Saving..." : "Save"}
                  </button>

                  <button
                    type="button"
                    onClick={onToggleRevoked}
                    disabled={toggleBusy}
                    className={cx(
                      "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                      "hover:bg-primary/5",
                      toggleBusy && "opacity-60 cursor-not-allowed"
                    )}
                  >
                    {toggleBusy
                      ? "Working..."
                      : agent.is_revoked
                        ? "Enable agent"
                        : "Disable agent"}
                  </button>
                </div>
              </div>
            )}
            {agentError && <div className="mt-3 text-[11px] text-red-400">{agentError}</div>}
          </Panel>

          <Panel title="Config" scrollY style={{ height: H_PANEL_STREAM }}>
            {!agent ? (
              <EmptyState title="Agent not loaded" />
            ) : (
              <div className="space-y-4">
                {timingKeys.length > 0 && (
                  <div className="border border-border/60 bg-background/40 p-3 space-y-3">
                    <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
                      Timings
                    </div>
                    <div className="grid gap-3 sm:grid-cols-2">
                      {timingKeys.map((k) => (
                        <div key={k}>
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                            {k}
                          </div>
                          <input
                            type="number"
                            className={inputClassName(configBusy)}
                            value={String((configObj as any)[k] ?? "")}
                            onChange={(e) => onUpdateTiming(k, Number(e.target.value))}
                            disabled={configBusy}
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <div className="flex items-center justify-between">
                    <FieldLabel>Raw config</FieldLabel>
                    <button
                      type="button"
                      onClick={() => {
                        const parsed = safeJsonParse(configText);
                        if (parsed.ok) setConfigText(prettyJson(parsed.value));
                      }}
                      className="text-[10px] text-primary hover:underline"
                    >
                      Format
                    </button>
                  </div>

                  <textarea
                    className={textAreaClassName(configBusy)}
                    rows={14}
                    value={configText}
                    onChange={(e) => onConfigTextChange(e.target.value)}
                    disabled={configBusy}
                  />

                  {configParseError && <div className="mt-2 text-[11px] text-red-400">Config: {configParseError}</div>}
                </div>

                <div className="flex items-center justify-between gap-3 pt-2">
                  <button
                    type="button"
                    onClick={onApplyConfig}
                    disabled={configBusy || Boolean(configParseError)}
                    className={cx(
                      "w-full border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                      "hover:bg-primary/5",
                      (configBusy || Boolean(configParseError)) && "opacity-60 cursor-not-allowed"
                    )}
                  >
                    {configBusy ? "Pushing..." : "Push config"}
                  </button>
                </div>
              </div>
            )}
          </Panel>
        </div>

        {/* RIGHT COLUMN: TELEMETRY (Stats, Charts, Events) */}
        <div className="xl:col-span-8 space-y-4">
          <Panel title="Live Status" style={{ height: 100 }}>
             <div className="grid grid-cols-2 gap-4 h-full items-center">
                <StatTile label="Status" value={topStats.status} tone={topStats.online ? "good" : selectedAgentRow?.is_revoked ? "warn" : "default"} />
                <StatTile label="Events / 5m" value={eventsRate} />
             </div>
          </Panel>

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="Traffic" style={{ height: H_PANEL_MD }}>
              {!charts.traffic ? (
                <Loading label="Loading chart..." />
              ) : (
                <div className="h-full w-full flex items-center justify-center overflow-hidden">
                  <div className="w-full max-w-full flex justify-center">
                    <SimpleTimeSeries 
                      data={charts.traffic.data} 
                      seriesKeys={charts.traffic.series} 
                      height={H_PANEL_MD - 100} 
                      allowHorizontalScroll={false} 
                    />
                  </div>
                </div>
              )}
            </Panel>

            <Panel title="SSH failures" style={{ height: H_PANEL_MD }}>
              {!charts.ssh ? (
                <Loading label="Loading chart..." />
              ) : (
                <div className="h-full w-full flex items-center justify-center overflow-hidden">
                  <div className="w-full max-w-full flex justify-center">
                    <SimpleTimeSeries 
                      data={charts.ssh.data} 
                      seriesKeys={charts.ssh.series} 
                      height={H_PANEL_MD - 100} 
                      allowHorizontalScroll={false} 
                    />
                  </div>
                </div>
              )}
            </Panel>

            <Panel title="DDoS" style={{ height: H_PANEL_MD }}>
              {!charts.ddos ? (
                <Loading label="Loading chart..." />
              ) : (
                <div className="h-full w-full flex items-center justify-center overflow-hidden">
                  <div className="w-full max-w-full flex justify-center">
                    <SimpleTimeSeries 
                      data={charts.ddos.data} 
                      seriesKeys={charts.ddos.series} 
                      height={H_PANEL_MD - 100} 
                      allowHorizontalScroll={false} 
                    />
                  </div>
                </div>
              )}
            </Panel>

            <Panel title="Alert severity" style={{ height: H_PANEL_MD }}>
              {!charts.sev ? (
                <Loading label="Loading chart..." />
              ) : (
                <div className="h-full w-full flex items-center justify-center overflow-hidden">
                  <div className="w-full max-w-full flex justify-center">
                    <SimpleTimeSeries 
                      data={charts.sev.data} 
                      seriesKeys={charts.sev.series} 
                      height={H_PANEL_MD - 100} 
                      allowHorizontalScroll={false} 
                    />
                  </div>
                </div>
              )}
            </Panel>
          </div>

          <Panel
            title="Recent events"
            right={telemetryError ? "Error" : `${events.length} events`}
            scrollY
            style={{ height: H_PANEL_STREAM }}
          >
            {telemetryError ? (
              <EmptyState title="Telemetry error" hint={telemetryError} />
            ) : events.length === 0 ? (
              <EmptyState title="No events" hint="This agent has no recent telemetry." />
            ) : (
              <div className="h-full">
                <EventsTable
                  rows={events}
                  selectedId={null}
                  compact
                  showExtra
                  onSelect={() => {}}
                />
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}