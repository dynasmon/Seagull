import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { useAgentsCatalog } from "@/app/providers";
import AsyncState from "@/shared/components/AsyncState";
import { Badge } from "@/shared/components/Badge";
import { Card } from "@/shared/components/Card";
import { DataQueryStateBanner, DataStatsStrip, DataViewToolbar } from "@/shared/components/DataView";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Table, type Column } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";
import { getErrorMessage } from "@/shared/lib/errors";
import { clampInt } from "@/shared/lib/filters";
import { useLiveRefresh, usePortalRealtimeSubscription } from "@/shared/realtime";

import { fmtDateTime } from "../../lib/aggregates";
import { getProtocolIntelSummary } from "./api";
import ProtocolIndicatorDrawer, { type ProtocolIndicatorSelection } from "./ProtocolIndicatorDrawer";
import type { ProtocolIntelSummaryResponse, ProtocolIntelIndicatorKind } from "./types";

type ViewState = {
  agent_id: string;
  since_minutes: number;
  top_n: number;
  refresh_ms: number;
  auto_refresh: boolean;
};

type DraftState = {
  agent_id: string;
  since_minutes: string;
  top_n: string;
  refresh_ms: string;
  auto_refresh: boolean;
};

const DEFAULTS: ViewState = {
  agent_id: "",
  since_minutes: 60 * 12,
  top_n: 25,
  refresh_ms: 20_000,
  auto_refresh: true
};

const LS_KEY = "nw_protocol_intel_view_v1";
const MAX_FALLBACK_SINCE_MINUTES = 60 * 24 * 30;

function digitsOnly(v: string): string {
  return String(v ?? "").replace(/[^0-9]/g, "");
}

function parsePositiveInt(raw: string | null): number | null {
  const text = String(raw || "").trim();
  if (!text) return null;
  const n = Number(text);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.trunc(n);
}

function parseDraftInt(raw: string, fallback: number): number {
  const n = Number.parseInt(String(raw ?? "").trim(), 10);
  return Number.isFinite(n) ? n : fallback;
}

function draftFromView(v: ViewState): DraftState {
  return {
    agent_id: v.agent_id,
    since_minutes: String(v.since_minutes),
    top_n: String(v.top_n),
    refresh_ms: String(v.refresh_ms),
    auto_refresh: v.auto_refresh
  };
}

function fmtPct(num: number, den: number) {
  if (!Number.isFinite(num) || !Number.isFinite(den) || den <= 0) return "0%";
  const p = Math.round((num / den) * 100);
  return `${p}%`;
}

function fmtQueryMeta(meta?: { source?: string; source_freshness_seconds?: number | null; degraded_reason?: string | null; cache_hit?: boolean; approximate?: boolean; query_latency_ms?: number | null } | null) {
  if (!meta) return "source: -";
  const src = String(meta.source || "unknown");
  const fresh = typeof meta.source_freshness_seconds === "number" ? `${meta.source_freshness_seconds}s` : "-";
  const latency = typeof meta.query_latency_ms === "number" ? `${Math.round(meta.query_latency_ms)}ms` : "-";
  const degraded = meta.degraded_reason ? `degraded (${meta.degraded_reason})` : "ok";
  const cache = meta.cache_hit ? "cache" : "live";
  const approx = meta.approximate ? "approx" : "exact";
  return `source ${src} · fresh ${fresh} · latency ${latency} · ${cache} · ${approx} · ${degraded}`;
}

function RiskPill({ risk }: { risk: number }) {
  const r = clampInt(risk, 0, 5, 0);
  const label = r === 0 ? "low" : r === 1 ? "medium" : r === 2 ? "high" : "critical";
  const variant = label as any;
  return <Badge variant={variant}>{label}</Badge>;
}

function Section({ title, right, children }: { title: string; right?: any; children: any }) {
  return (
    <Card className="rounded-xl overflow-hidden">
      <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-border/60 bg-muted/10">
        <div className="text-sm font-semibold tracking-tight">{title}</div>
        {right ? <div className="text-xs text-muted-foreground">{right}</div> : null}
      </div>
      <div className="p-4">{children}</div>
    </Card>
  );
}

function Stat({ label, value, sub }: { label: string; value: any; sub?: any }) {
  return (
    <div className="rounded-lg border border-border/60 bg-background/40 p-4">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-2 text-2xl font-semibold tracking-tight">{value}</div>
      {sub ? <div className="mt-1 text-xs text-muted-foreground">{sub}</div> : null}
    </div>
  );
}

function TableEmpty({ title, desc }: { title: string; desc?: string }) {
  return <EmptyState title={title} description={desc ?? "No results for the selected scope."} />;
}

function InspectButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cx(
        "inline-flex items-center rounded-md border border-border/60 bg-background/40",
        "px-2 py-1 text-xs text-muted-foreground",
        "hover:bg-muted/15 hover:text-foreground",
        "focus:outline-none focus:ring-2 focus:ring-primary/30"
      )}
    >
      Inspect
    </button>
  );
}

export default function ProtocolIntelPage() {
  const [searchParams] = useSearchParams();
  const { agents } = useAgentsCatalog();

  const [view, setView] = useState<ViewState>(() => {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (!raw) return DEFAULTS;
      const parsed = JSON.parse(raw);
      return {
        agent_id: typeof parsed?.agent_id === "string" ? parsed.agent_id : "",
        since_minutes: clampInt(parsed?.since_minutes, 1, 60 * 24 * 30, DEFAULTS.since_minutes),
        top_n: clampInt(parsed?.top_n, 5, 200, DEFAULTS.top_n),
        refresh_ms: clampInt(parsed?.refresh_ms, 10_000, 120_000, DEFAULTS.refresh_ms),
        auto_refresh: typeof parsed?.auto_refresh === "boolean" ? parsed.auto_refresh : DEFAULTS.auto_refresh
      };
    } catch {
      return DEFAULTS;
    }
  });

  // Draft scope state: prevents hammering the API while typing large windows.
  // Use string draft for numeric inputs so the value doesn't "jump" while the user types.
  const [draft, setDraft] = useState<DraftState>(() => draftFromView(view));
  useEffect(() => {
    setDraft(draftFromView(view));
  }, [view]);

  const isDirty =
    draft.agent_id !== view.agent_id ||
    draft.since_minutes !== String(view.since_minutes) ||
    draft.top_n !== String(view.top_n) ||
    draft.refresh_ms !== String(view.refresh_ms) ||
    draft.auto_refresh !== view.auto_refresh;

  const viewRef = useRef(view);
  useEffect(() => {
    viewRef.current = view;
    try {
      localStorage.setItem(LS_KEY, JSON.stringify(view));
    } catch {
      // ignore
    }
  }, [view]);

  // Safety guard: auto-refresh + very large windows can hammer the DB and the browser.
  useEffect(() => {
    if (view.since_minutes > 60 * 24 && view.auto_refresh) {
      setView((v) => ({ ...v, auto_refresh: false, refresh_ms: Math.max(v.refresh_ms, 60_000) }));
    }
    if (view.auto_refresh && view.since_minutes > 60 * 12 && view.refresh_ms < 45_000) {
      setView((v) => ({ ...v, refresh_ms: 45_000 }));
    }
  }, [view.since_minutes, view.auto_refresh, view.refresh_ms]);

  const agentNameById = useMemo(() => {
    const map: Record<string, string> = {};
    for (const a of agents || []) {
      if (!a?.agent_id) continue;
      map[a.agent_id] = a.display_name || a.agent_id;
    }
    return map;
  }, [agents]);

  const agentOptions = useMemo(() => {
    return (agents || []).map((a) => ({ agent_id: a.agent_id, display_name: a.display_name || a.agent_id }));
  }, [agents]);

  // Guard against stale persisted agent filters.
  // If the selected agent no longer exists, fallback to "All agents".
  useEffect(() => {
    const selected = (view.agent_id || "").trim();
    if (!selected) return;
    if ((agentOptions?.length ?? 0) <= 0) return;
    const exists = agentOptions.some((a) => a.agent_id === selected);
    if (exists) return;
    setView((cur) => (cur.agent_id ? { ...cur, agent_id: "" } : cur));
    setDraft((cur) => (cur.agent_id ? { ...cur, agent_id: "" } : cur));
  }, [agentOptions, view.agent_id]);

  const reqSeq = useRef(0);
  const didBootRef = useRef(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<ProtocolIntelSummaryResponse | null>(null);
  const [lastOkAt, setLastOkAt] = useState<Date | null>(null);
  const [fallbackSinceMinutes, setFallbackSinceMinutes] = useState<number | null>(null);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerSel, setDrawerSel] = useState<ProtocolIndicatorSelection | null>(null);
  const [deepLinkFocusEventId, setDeepLinkFocusEventId] = useState<number | null>(null);
  const didInitFromUrl = useRef(false);

  const [healthOpen, setHealthOpen] = useState(false);

  useEffect(() => {
    if (didInitFromUrl.current) return;
    didInitFromUrl.current = true;

    const agentId = (searchParams.get("agent_id") || "").trim();
    const sinceFromUrl = clampInt(searchParams.get("since_minutes"), 1, 60 * 24 * 30, DEFAULTS.since_minutes);
    const focusEventId = parsePositiveInt(searchParams.get("focus_event_id"));
    const indicatorKind = (searchParams.get("indicator_kind") || "").trim().toLowerCase();
    const indicatorValue = (searchParams.get("indicator_value") || "").trim();

    if (agentId || sinceFromUrl !== DEFAULTS.since_minutes) {
      setView((prev) => ({
        ...prev,
        agent_id: agentId || prev.agent_id,
        since_minutes: sinceFromUrl,
      }));
    }
    if (focusEventId) setDeepLinkFocusEventId(focusEventId);

    const allowedKinds = new Set<ProtocolIntelIndicatorKind>([
      "app_proto",
      "transport",
      "ja4_ptype",
      "http_method",
      "app_proto_reason",
      "app_proto_conf_band",
      "tls_sni",
      "tls_alpn_first",
      "http_host",
      "dns_qname",
      "dst_port",
      "src_port",
      "ja3",
      "ja4",
    ]);
    if (indicatorValue && allowedKinds.has(indicatorKind as ProtocolIntelIndicatorKind)) {
      const label = indicatorKind.replace(/_/g, " ");
      setDrawerSel({
        kind: indicatorKind as ProtocolIntelIndicatorKind,
        value: indicatorValue,
        label,
        hint: "Focused from investigation bookmark",
      });
      setDrawerOpen(true);
    }
  }, [searchParams]);

  const load = useCallback(async () => {
    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);

    const agent_id = viewRef.current.agent_id ? viewRef.current.agent_id : undefined;
    const since_minutes = viewRef.current.since_minutes;
    const limit = viewRef.current.top_n;

    try {
      let res = await getProtocolIntelSummary({ agent_id, since_minutes, limit });
      let fallbackMinutes: number | null = null;

      // If the selected window is empty, automatically widen scope to show historical data.
      if ((res?.total_events ?? 0) <= 0 && since_minutes < MAX_FALLBACK_SINCE_MINUTES) {
        const widened = clampInt(
          Math.max(since_minutes * 6, since_minutes + 60),
          since_minutes + 1,
          MAX_FALLBACK_SINCE_MINUTES,
          MAX_FALLBACK_SINCE_MINUTES
        );
        const fallbackRes = await getProtocolIntelSummary({ agent_id, since_minutes: widened, limit });
        if ((fallbackRes?.total_events ?? 0) > 0) {
          res = fallbackRes;
          fallbackMinutes = widened;
        }
      }

      if (reqSeq.current !== mySeq) return;
      setData(res);
      setFallbackSinceMinutes(fallbackMinutes);
      setLastOkAt(new Date());
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      const msg = getErrorMessage(e, "Failed to load summary");
      setError(msg);
      setFallbackSinceMinutes(null);
    } finally {
      if (reqSeq.current !== mySeq) return;
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!didBootRef.current) {
      didBootRef.current = true;
      if (view.auto_refresh) return;
    }
    void load();
  }, [load, view.agent_id, view.auto_refresh, view.since_minutes, view.top_n]);

  const live = useLiveRefresh({
    enabled: view.auto_refresh,
    profile: view.since_minutes > 12 * 60 ? "expensive-operational" : "operational",
    refresh: async ({ signal }) => {
      const mySeq = ++reqSeq.current;
      setLoading(true);
      setError(null);

      const agent_id = viewRef.current.agent_id ? viewRef.current.agent_id : undefined;
      const since_minutes = viewRef.current.since_minutes;
      const limit = viewRef.current.top_n;

      try {
        let res = await getProtocolIntelSummary({ agent_id, since_minutes, limit }, { signal });
        let fallbackMinutes: number | null = null;

        if ((res?.total_events ?? 0) <= 0 && since_minutes < MAX_FALLBACK_SINCE_MINUTES) {
          const widened = clampInt(
            Math.max(since_minutes * 6, since_minutes + 60),
            since_minutes + 1,
            MAX_FALLBACK_SINCE_MINUTES,
            MAX_FALLBACK_SINCE_MINUTES
          );
          const fallbackRes = await getProtocolIntelSummary({ agent_id, since_minutes: widened, limit }, { signal });
          if ((fallbackRes?.total_events ?? 0) > 0) {
            res = fallbackRes;
            fallbackMinutes = widened;
          }
        }

        if (reqSeq.current !== mySeq) return;
        setData(res);
        setFallbackSinceMinutes(fallbackMinutes);
        setLastOkAt(new Date());
      } catch (e: any) {
        if (reqSeq.current !== mySeq) return;
        const msg = getErrorMessage(e, "Failed to load summary");
        setError(msg);
        setFallbackSinceMinutes(null);
      } finally {
        if (reqSeq.current !== mySeq) return;
        setLoading(false);
      }
    },
  });

  usePortalRealtimeSubscription("ui.events.invalidate", (event) => {
    const eventAgentId = String(event.payload?.agent_id || "").trim();
    if (view.agent_id && eventAgentId && eventAgentId !== view.agent_id) return;
    const domains = Array.isArray(event.payload?.domains) ? event.payload.domains.map((value) => String(value)) : [];
    if (domains.length > 0 && !domains.includes("network") && !domains.includes("protocol_intel")) return;
    live.invalidate();
  });

  const coverage = useMemo(() => {
    const total = data?.total_events ?? 0;
    const withMeta = data?.with_proto_metadata ?? 0;
    return fmtPct(withMeta, total);
  }, [data]);

  const generatedAt = useMemo(() => {
    if (!data?.generated_at) return "-";
    const d = new Date(data.generated_at);
    if (Number.isNaN(d.getTime())) return data.generated_at;
    return fmtDateTime(d);
  }, [data]);

  const shouldWarnNoCoverage = useMemo(() => {
    if (!data) return false;
    const hasAnyUsefulBreakdown =
      (data.app_protocols?.length ?? 0) > 0 ||
      (data.transport_protocols?.length ?? 0) > 0 ||
      (data.top_dst_ports?.length ?? 0) > 0;
    return data.total_events > 0 && data.with_proto_metadata === 0 && !hasAnyUsefulBreakdown;
  }, [data]);
  const hasBlockingState = (loading && !data) || (!!error && !data);

  const onPick = useCallback(
    (sel: ProtocolIndicatorSelection) => {
      setDrawerSel(sel);
      setDrawerOpen(true);
    },
    [setDrawerSel, setDrawerOpen]
  );

  const mkPick = useCallback(
    (kind: ProtocolIntelIndicatorKind, value: string, label: string, count?: number, hint?: string) => {
      onPick({ kind, value, label, count, hint });
    },
    [onPick]
  );

  const applyDraft = useCallback(() => {
    const next: ViewState = {
      agent_id: typeof draft.agent_id === "string" ? draft.agent_id : "",
      since_minutes: clampInt(parseDraftInt(draft.since_minutes, view.since_minutes), 1, 60 * 24 * 30, DEFAULTS.since_minutes),
      top_n: clampInt(parseDraftInt(draft.top_n, view.top_n), 5, 200, DEFAULTS.top_n),
      refresh_ms: clampInt(parseDraftInt(draft.refresh_ms, view.refresh_ms), 10_000, 120_000, DEFAULTS.refresh_ms),
      auto_refresh: !!draft.auto_refresh
    };
    setView(next);
    setDraft(draftFromView(next));
  }, [draft, view.refresh_ms, view.since_minutes, view.top_n]);

  const headerRight = (
    <div className="flex flex-wrap items-center justify-end gap-2">
      {isDirty ? (
        <button
          type="button"
          onClick={applyDraft}
          className={cx(
            "inline-flex items-center gap-2 rounded-md border border-border/60 bg-primary/15",
            "px-3 py-2 text-xs font-medium text-primary",
            "hover:bg-primary/20",
            "focus:outline-none focus:ring-2 focus:ring-primary/30"
          )}
        >
          Apply
        </button>
      ) : null}

      <button
        type="button"
        onClick={() => void load()}
        className={cx(
          "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
          "px-3 py-2 text-xs font-medium text-muted-foreground",
          "hover:bg-muted/15 hover:text-foreground",
          "focus:outline-none focus:ring-2 focus:ring-primary/30"
        )}
      >
        Refresh
      </button>
    </div>
  );

  return (
    <div className="space-y-4">
      <DataViewToolbar
        left={<div className="text-sm font-semibold tracking-tight">Protocol Intelligence</div>}
        right={headerRight}
      />

      <DataStatsStrip
        stats={[
          { label: "Total events", value: data ? data.total_events : "-" },
          { label: "With metadata", value: data ? data.with_proto_metadata : "-", hint: `Coverage ${coverage}` },
          { label: "DNS events", value: data ? data.dns_events : "-" },
          { label: "HTTP events", value: data ? data.http_events : "-" },
          { label: "TLS/DTLS/QUIC", value: data ? data.tls_events : "-" },
          { label: "Generated at", value: generatedAt },
          { label: "Scope", value: view.agent_id || "all agents", hint: `Lookback ${view.since_minutes}m` },
          { label: "Top-N", value: view.top_n, hint: view.auto_refresh ? `${Math.round(live.state.profile.fallbackMs / 1000)}s shared fallback` : "Manual refresh" },
        ]}
      />

      <div className="grid grid-cols-1 xl:grid-cols-[360px_1fr] gap-5">
        <div className="space-y-5">
          <Section title="Scope" right={view.auto_refresh ? `${Math.round(live.state.profile.fallbackMs / 1000)}s shared fallback` : "manual"}>
            <div className="space-y-3">
              <div className="grid grid-cols-1 gap-3">
                <div>
                  <div className="text-xs text-muted-foreground">Agent</div>
                  <select
                    value={draft.agent_id}
                    onChange={(e) => {
                      const v = e.target.value;
                      setDraft((s) => ({ ...s, agent_id: v }));
                      // Agent changes are safe to apply immediately (single click, no typing spam).
                      setView((cur) => ({ ...cur, agent_id: v }));
                    }}
                    className="mt-2 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                  >
                    <option value="">All agents</option>
                    {agentOptions.map((a) => (
                      <option key={a.agent_id} value={a.agent_id}>
                        {a.display_name}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-xs text-muted-foreground">Lookback (minutes)</div>
                    <input
                      inputMode="numeric"
                      pattern="[0-9]*"
                      type="text"
                      value={draft.since_minutes}
                      onChange={(e) => {
                        const raw = digitsOnly(e.target.value).slice(0, 6);
                        setDraft((s) => ({ ...s, since_minutes: raw }));
                      }}
                      placeholder={String(view.since_minutes)}
                      className="mt-2 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                    />
                    <div className="mt-1 text-[11px] text-muted-foreground">1–43200 (30 days)</div>
                  </div>

                  <div>
                    <div className="text-xs text-muted-foreground">Top-N</div>
                    <input
                      inputMode="numeric"
                      pattern="[0-9]*"
                      type="text"
                      value={draft.top_n}
                      onChange={(e) => {
                        const raw = digitsOnly(e.target.value).slice(0, 3);
                        setDraft((s) => ({ ...s, top_n: raw }));
                      }}
                      placeholder={String(view.top_n)}
                      className="mt-2 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                    />
                    <div className="mt-1 text-[11px] text-muted-foreground">5–200</div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-xs text-muted-foreground">Refresh cadence</div>
                    <div className="mt-2 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm text-muted-foreground">
                      {draft.auto_refresh ? `${Math.round(live.state.profile.fallbackMs / 1000)}s shared fallback` : "Manual only"}
                    </div>
                    <div className="mt-1 text-[11px] text-muted-foreground">Cadence is controlled centrally by the live-refresh policy.</div>
                  </div>

                  <div className="flex items-end">
                    <label className="inline-flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={draft.auto_refresh}
                        onChange={(e) => setDraft((s) => ({ ...s, auto_refresh: e.target.checked }))}
                      />
                      <span className="text-sm text-muted-foreground">Auto refresh</span>
                    </label>
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                  <div className="text-[11px] text-muted-foreground">
                    {isDirty ? "Draft changes pending. Click Apply to update the query scope." : "Scope applied."}
                  </div>
                  <div className="flex items-center gap-2">
                    {isDirty ? (
                      <button
                        type="button"
                        onClick={applyDraft}
                        className={cx(
                          "inline-flex items-center gap-2 rounded-md border border-border/60 bg-primary/15",
                          "px-3 py-2 text-xs font-medium text-primary",
                          "hover:bg-primary/20",
                          "focus:outline-none focus:ring-2 focus:ring-primary/30"
                        )}
                      >
                        Apply
                      </button>
                    ) : null}
                    <button
                      type="button"
                      onClick={() => setDraft(draftFromView(view))}
                      className={cx(
                        "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                        "px-3 py-2 text-xs font-medium text-muted-foreground",
                        "hover:bg-muted/15 hover:text-foreground",
                        "focus:outline-none focus:ring-2 focus:ring-primary/30"
                      )}
                      disabled={!isDirty}
                    >
                      Reset
                    </button>
                  </div>
                </div>

                {parseDraftInt(draft.since_minutes, view.since_minutes) > 60 * 24 ? (
                  <div className="rounded-md border border-warning/30 bg-warning/10 p-3 text-xs text-warning">
                    Large lookback windows can be expensive. Auto refresh is disabled above 24h to protect CPU/DB.
                  </div>
                ) : parseDraftInt(draft.since_minutes, view.since_minutes) > 60 * 12 && draft.auto_refresh ? (
                  <div className="rounded-md border border-border/60 bg-background/40 p-3 text-xs text-muted-foreground">
                    Refresh interval was increased to reduce CPU load for large windows.
                  </div>
                ) : null}
              </div>
            </div>
          </Section>

          <Section title="Coverage" right={data ? `generated ${generatedAt}` : ""}>
            <div className="grid grid-cols-2 gap-3">
              <Stat label="Total events" value={data ? data.total_events : "-"} sub={`Lookback ${view.since_minutes} min`} />
              <Stat label="With protocol metadata" value={data ? data.with_proto_metadata : "-"} sub={`Coverage ${coverage}`} />
              <Stat label="DNS" value={data ? data.dns_events : "-"} />
              <Stat label="HTTP" value={data ? data.http_events : "-"} />
              <Stat label="TLS/DTLS/QUIC" value={data ? data.tls_events : "-"} />
              <Stat label="Last updated" value={lastOkAt ? fmtDateTime(lastOkAt) : "-"} />
            </div>
          </Section>

          <Section
            title="Health hints"
            right={
              <button
                type="button"
                onClick={() => setHealthOpen((v) => !v)}
                className="text-xs text-muted-foreground hover:text-foreground"
              >
                {healthOpen ? "Hide" : "Show"}
              </button>
            }
          >
            {!healthOpen ? (
              <div className="text-sm text-muted-foreground">
                Quick troubleshooting when the tables are empty.
              </div>
            ) : (
              <div className="space-y-2 text-sm text-muted-foreground leading-relaxed">
                <div>
                  This view is powered by the <span className="font-mono">proto-intel</span> worker inside{" "}
                  <span className="font-mono">seagull-intelligence-worker</span>. L7 collection is{" "}
                  <span className="text-foreground font-medium">enabled by default</span>. If tables stay empty:
                </div>
                <ul className="list-disc pl-5 space-y-1">
                  <li>
                    Confirm the worker is running: <span className="font-mono">docker ps | grep intelligence-worker</span>
                  </li>
                  <li>
                    Check for parsing errors: <span className="font-mono">docker logs -f seagull-intelligence-worker</span>
                  </li>
                  <li>Generate traffic: DNS lookups, plaintext HTTP requests, and TLS handshakes.</li>
                  <li>
                    Without payload evidence, the worker falls back to port-based guesses (confidence 70–90).
                    With agent L7 evidence, classifications score 99.
                  </li>
                  <li>
                    Encrypted HTTPS traffic shows as <span className="font-mono">tls</span> or{" "}
                    <span className="font-mono">quic</span>, not <span className="font-mono">http</span>. This is correct —
                    only plaintext payloads are labelled HTTP.
                  </li>
                </ul>
              </div>
            )}
          </Section>
        </div>

        <div className="space-y-5">
          {hasBlockingState ? (
            <AsyncState
              loading={loading && !data}
              error={error && !data ? error : null}
              empty={false}
              emptyTitle=""
              loadingLabel="Loading protocol intelligence..."
              errorTitle="Protocol intel error"
              onRetry={load}
              className="px-0"
            />
          ) : null}

          {!hasBlockingState && error ? (
            <div className="rounded-xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">{error}</div>
          ) : null}

          {!hasBlockingState && !error && fallbackSinceMinutes ? (
            <div className="rounded-xl border border-info/30 bg-info/10 p-4 text-sm text-info">
              No events were found in the selected window. Showing historical protocol telemetry from the last{" "}
              <span className="font-mono">{fallbackSinceMinutes}</span> minutes.
            </div>
          ) : null}

          {!hasBlockingState && data?.meta ? (
            <DataQueryStateBanner
              tone={data.meta.degraded_reason ? "warning" : "neutral"}
              message={fmtQueryMeta(data.meta)}
            />
          ) : null}

          {!hasBlockingState && shouldWarnNoCoverage ? (
            <div className="rounded-xl border border-warning/30 bg-warning/10 p-4 text-sm text-warning space-y-1">
              <div className="font-medium">No protocol metadata in this window.</div>
              <div>
                L7 collection is enabled by default. If tables stay empty, confirm the{" "}
                <span className="font-mono">proto-intel</span> worker is running and that agents are
                capturing traffic (DNS, HTTP, or TLS handshakes).
              </div>
            </div>
          ) : null}

          {!hasBlockingState ? <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
            <Section title="Application protocols (L7)" right={`top ${view.top_n}`}>
              {loading && !data ? <Loading label="Loading..." /> : null}
              {!loading && data && data.app_protocols.length === 0 ? (
                <TableEmpty
                  title="No protocols classified yet"
                  desc="Plaintext HTTP is labelled HTTP. Encrypted traffic (HTTPS, QUIC) appears as TLS or QUIC unless a handshake was captured."
                />
              ) : null}
              {data && data.app_protocols.length > 0 ? (
                <div className="overflow-auto space-y-3">
                  <div className="text-[11px] text-muted-foreground leading-relaxed">
                    <span className="font-mono">http</span> = plaintext request bytes visible ·{" "}
                    <span className="font-mono">tls</span>/<span className="font-mono">quic</span>/<span className="font-mono">dtls</span> = encrypted, handshake only
                  </div>
                  <Table
                    columns={[
                      {
                        key: "key",
                        title: "APP PROTO",
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => (
                          <InspectButton
                            onClick={() =>
                              mkPick("app_proto", r.key, "Application protocol", r.count, "Top application protocol classification")
                            }
                          />
                        )
                      }
                    ] satisfies Array<Column<(typeof data.app_protocols)[number]>>}
                    rows={data.app_protocols}
                    rowKey={(r) => r.key}
                  />
                </div>
              ) : null}
            </Section>

            <Section title="Transport protocols (L4)" right={`top ${view.top_n}`}>
              {!loading && data && data.transport_protocols.length === 0 ? <TableEmpty title="No transport protocols" /> : null}
              {data && data.transport_protocols.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "key",
                        title: "PROTO",
                        width: 140,
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => (
                          <InspectButton onClick={() => mkPick("transport", r.key, "Transport protocol", r.count, "Layer-4 protocol mix")} />
                        )
                      }
                    ] as Array<Column<any>>}
                    rows={data.transport_protocols}
                    rowKey={(r) => r.key}
                  />
                </div>
              ) : null}
            </Section>

            <Section title="JA4 ptype distribution" right="q=QUIC · d=DTLS · t=TLS">
              {!loading && data && data.ja4_ptypes.length === 0 ? (
                <TableEmpty title="No JA4 ptype data" desc="Populated when TLS, QUIC, or DTLS handshakes are fingerprinted." />
              ) : null}
              {data && data.ja4_ptypes.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "key",
                        title: "PTYPE",
                        width: 140,
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => (
                          <InspectButton
                            onClick={() =>
                              mkPick("ja4_ptype", r.key, "JA4 ptype", r.count, "Distribution of JA4 transport type")
                            }
                          />
                        )
                      }
                    ] as Array<Column<any>>}
                    rows={data.ja4_ptypes}
                    rowKey={(r) => r.key}
                  />
                </div>
              ) : null}
            </Section>

            <Section title="HTTP methods" right="from plaintext HTTP/1 parsing">
              {!loading && data && data.http_methods.length === 0 ? (
                <TableEmpty title="No HTTP methods" desc="Requires plaintext HTTP/1 request payloads. Encrypted HTTPS traffic does not contribute here." />
              ) : null}
              {data && data.http_methods.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "key",
                        title: "METHOD",
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => (
                          <InspectButton onClick={() => mkPick("http_method", r.key, "HTTP method", r.count, "HTTP request methods")} />
                        )
                      }
                    ] as Array<Column<any>>}
                    rows={data.http_methods}
                    rowKey={(r) => r.key}
                  />
                </div>
              ) : null}
            </Section>

            <Section title="Classification reasons" right={`top ${view.top_n}`}>
              {!loading && data && data.app_proto_reasons.length === 0 ? (
                <TableEmpty title="No classification reasons yet" desc="Reasons appear once the proto-intel worker processes events." />
              ) : null}
              {data && data.app_proto_reasons.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "key",
                        title: "REASON",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => (
                          <InspectButton
                            onClick={() =>
                              mkPick("app_proto_reason", r.key, "Classification reason", r.count, "Why app protocol was inferred")
                            }
                          />
                        )
                      }
                    ] as Array<Column<any>>}
                    rows={data.app_proto_reasons}
                    rowKey={(r) => r.key}
                  />
                </div>
              ) : null}
            </Section>

            <Section title="Confidence bands" right="80-100 · 60-79 · 40-59 · 0-39">
              {!loading && data && data.app_proto_conf_bands.length === 0 ? (
                <TableEmpty title="No confidence bands yet" desc="Bands reflect how certain the classifier is: agent evidence scores 99, parsed payloads 98, port guesses 70-90." />
              ) : null}
              {data && data.app_proto_conf_bands.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "key",
                        title: "BAND",
                        width: 160,
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => (
                          <InspectButton
                            onClick={() =>
                              mkPick("app_proto_conf_band", r.key, "Confidence band", r.count, "Confidence range of app_proto inference")
                            }
                          />
                        )
                      }
                    ] as Array<Column<any>>}
                    rows={data.app_proto_conf_bands}
                    rowKey={(r) => r.key}
                  />
                </div>
              ) : null}
            </Section>
          </div> : null}

          {!hasBlockingState ? (
          <>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
            <Section title="Top destination ports" right={`top ${view.top_n} by volume`}>
              {!loading && data && data.top_dst_ports.length === 0 ? <TableEmpty title="No destination ports" /> : null}
              {data && data.top_dst_ports.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "key",
                        title: "DST PORT",
                        width: 160,
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => <InspectButton onClick={() => mkPick("dst_port", r.key, "Destination port", r.count)} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_dst_ports}
                    rowKey={(r) => r.key}
                  />
                </div>
              ) : null}
            </Section>

            <Section title="Top source ports" right={`top ${view.top_n} by volume`}>
              {!loading && data && data.top_src_ports.length === 0 ? <TableEmpty title="No source ports" /> : null}
              {data && data.top_src_ports.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "key",
                        title: "SRC PORT",
                        width: 160,
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => <InspectButton onClick={() => mkPick("src_port", r.key, "Source port", r.count)} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_src_ports}
                    rowKey={(r) => r.key}
                  />
                </div>
              ) : null}
            </Section>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
            <Section title="Top DNS queries" right={`top ${view.top_n} by volume`}>
              {!loading && data && data.top_dns_queries.length === 0 ? <TableEmpty title="No DNS evidence" desc="DNS queries require payload evidence." /> : null}
              {data && data.top_dns_queries.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "qname",
                        title: "QNAME",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.qname}</span>
                      },
                      {
                        key: "risk",
                        title: "RISK",
                        width: 120,
                        render: (r) => <RiskPill risk={r.risk} />
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => <InspectButton onClick={() => mkPick("dns_qname", r.qname, "DNS qname", r.count, "Top DNS queries")} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_dns_queries}
                    rowKey={(r, i) => `${r.qname}-${i}`}
                  />
                </div>
              ) : null}
            </Section>

            <Section title="Top HTTP hosts" right={`top ${view.top_n} by volume`}>
              {!loading && data && data.top_http_hosts.length === 0 ? <TableEmpty title="No HTTP evidence" desc="HTTP hosts require payload evidence." /> : null}
              {data && data.top_http_hosts.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "key",
                        title: "HOST",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => <InspectButton onClick={() => mkPick("http_host", r.key, "HTTP host", r.count, "Top HTTP Host headers")} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_http_hosts}
                    rowKey={(r) => r.key}
                  />
                </div>
              ) : null}
            </Section>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
            <Section title="Top TLS SNI" right={`top ${view.top_n} by volume`}>
              {!loading && data && data.top_tls_sni.length === 0 ? <TableEmpty title="No SNI" desc="SNI requires TLS ClientHello evidence." /> : null}
              {data && data.top_tls_sni.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "key",
                        title: "SNI",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => <InspectButton onClick={() => mkPick("tls_sni", r.key, "TLS SNI", r.count, "Top SNI values")} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_tls_sni}
                    rowKey={(r) => r.key}
                  />
                </div>
              ) : null}
            </Section>

            <Section title="Top TLS/QUIC ALPN" right={`top ${view.top_n} by volume`}>
              {!loading && data && data.top_alpn.length === 0 ? <TableEmpty title="No ALPN" desc="ALPN requires TLS ClientHello evidence." /> : null}
              {data && data.top_alpn.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "key",
                        title: "ALPN",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => <InspectButton onClick={() => mkPick("tls_alpn_first", r.key, "ALPN", r.count, "Top ALPN values")} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_alpn}
                    rowKey={(r) => r.key}
                  />
                </div>
              ) : null}
            </Section>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
            <Section title="Top JA4 fingerprints" right={`top ${view.top_n} by volume`}>
              {!loading && data && data.top_ja4.length === 0 ? <TableEmpty title="No JA4" desc="JA4 requires TLS/DTLS/QUIC fingerprint evidence." /> : null}
              {data && data.top_ja4.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "ja4",
                        title: "JA4",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.ja4}</span>
                      },
                      {
                        key: "ptype",
                        title: "PTYPE",
                        width: 110,
                        render: (r) => (
                          <span className="font-mono text-[12px]">
                            <Badge>{r.ptype || "t"}</Badge>
                          </span>
                        )
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => <InspectButton onClick={() => mkPick("ja4", r.ja4, "JA4 fingerprint", r.count, `ptype=${r.ptype}`)} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_ja4}
                    rowKey={(r, i) => `${r.ja4}-${r.ptype || "t"}-${i}`}
                  />
                </div>
              ) : null}
            </Section>

            <Section title="Top JA3 fingerprints" right={`top ${view.top_n} by volume`}>
              {!loading && data && data.top_ja3.length === 0 ? <TableEmpty title="No JA3" desc="JA3 requires TLS ClientHello evidence." /> : null}
              {data && data.top_ja3.length > 0 ? (
                <div className="overflow-auto">
                  <Table
                    columns={[
                      {
                        key: "key",
                        title: "JA3",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        className: "text-right",
                        width: 120,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        className: "text-right",
                        width: 110,
                        render: (r) => <InspectButton onClick={() => mkPick("ja3", r.key, "JA3 fingerprint", r.count)} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_ja3}
                    rowKey={(r) => r.key}
                  />
                </div>
              ) : null}
            </Section>
          </div>

          {loading && data ? (
            <div className="text-xs text-muted-foreground">Refreshing…</div>
          ) : null}
          </>
          ) : null}
        </div>
      </div>

      <ProtocolIndicatorDrawer
        open={drawerOpen}
        selection={drawerSel}
        onClose={() => {
          setDrawerOpen(false);
          setDrawerSel(null);
          setDeepLinkFocusEventId(null);
        }}
        focusEventId={deepLinkFocusEventId}
        agentId={view.agent_id || undefined}
        sinceMinutes={view.since_minutes}
        agentNameById={agentNameById}
      />
    </div>
  );
}
