import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { useAgentsCatalog } from "@/app/providers";
import AsyncState from "@/shared/components/AsyncState";
import { MetricCard } from "@/shared/components/MetricCard";
import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { DataQueryStateBanner, DataStatsStrip, DataViewToolbar } from "@/shared/components/DataView";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { Table, type Column } from "@/shared/components/Table";
import { Tabs } from "@/shared/components/Tabs";
import { ToggleSwitch } from "@/shared/components/ToggleSwitch";
import { TextInput } from "@/shared/components/TextInput";
import { getErrorMessage } from "@/shared/lib/errors";
import { clampInt } from "@/shared/lib/filters";
import { useLiveRefresh, usePortalRealtimeSubscription } from "@/shared/realtime";

import { fmtDateTime } from "../../lib/aggregates";
import { getProtocolIntelSummary, streamProtocolIntelSummary } from "./api";
import ProtocolIndicatorDrawer, { type ProtocolIndicatorSelection } from "./ProtocolIndicatorDrawer";
import type { ProtocolIntelSummaryResponse, ProtocolIntelIndicatorKind } from "./types";

type IntelTab = "protocols" | "names" | "fingerprints" | "ports";

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

const EMPTY_SUMMARY: ProtocolIntelSummaryResponse = {
  generated_at: "",
  since_minutes: 0,
  agent_id: null,
  total_events: 0,
  with_proto_metadata: 0,
  dns_events: 0,
  http_events: 0,
  tls_events: 0,
  app_protocols: [],
  transport_protocols: [],
  top_dst_ports: [],
  top_src_ports: [],
  app_proto_reasons: [],
  app_proto_conf_bands: [],
  ja4_ptypes: [],
  http_methods: [],
  top_dns_queries: [],
  top_http_hosts: [],
  top_tls_sni: [],
  top_alpn: [],
  top_ja4: [],
  top_ja3: [],
  effective_since_minutes: null,
  meta: null
};

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
  const variant = label as "low" | "medium" | "high" | "critical";
  return <Badge variant={variant}>{label}</Badge>;
}

function Section({
  title,
  right,
  children,
  padded = true,
}: {
  title: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  padded?: boolean;
}) {
  return (
    <Panel
      title={title}
      actions={right ? <span className="text-[10.5px] text-muted-foreground">{right}</span> : undefined}
      padded={padded}
    >
      {children}
    </Panel>
  );
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{children}</div>
  );
}


function TableEmpty({ title, desc }: { title: string; desc?: string }) {
  return <EmptyState title={title} description={desc ?? "No results for the selected scope."} />;
}

function InspectButton({ onClick }: { onClick: () => void }) {
  return (
    <Button variant="subtle" size="sm" onClick={onClick}>
      Inspect
    </Button>
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

  const dataRef = useRef<ProtocolIntelSummaryResponse | null>(data);
  useEffect(() => {
    dataRef.current = data;
  }, [data]);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerSel, setDrawerSel] = useState<ProtocolIndicatorSelection | null>(null);
  const [deepLinkFocusEventId, setDeepLinkFocusEventId] = useState<number | null>(null);
  const didInitFromUrl = useRef(false);

  const [healthOpen, setHealthOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<IntelTab>("protocols");

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

  const runLoad = useCallback(async (signal?: AbortSignal) => {
    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);

    const agent_id = viewRef.current.agent_id ? viewRef.current.agent_id : undefined;
    const since_minutes = viewRef.current.since_minutes;
    const limit = viewRef.current.top_n;
    const reqParams = { agent_id, since_minutes, limit, widen_if_empty: true };

    try {
      const acc: { value: ProtocolIntelSummaryResponse | null } = { value: null };
      const base = (): ProtocolIntelSummaryResponse =>
        acc.value ?? (dataRef.current ? { ...dataRef.current } : { ...EMPTY_SUMMARY });

      await streamProtocolIntelSummary(
        reqParams,
        {
          onOverview: (overview) => {
            if (reqSeq.current !== mySeq) return;
            acc.value = { ...base(), ...overview } as ProtocolIntelSummaryResponse;
            setData(acc.value);
          },
          onFacet: (name, items) => {
            if (reqSeq.current !== mySeq) return;
            acc.value = { ...base(), [name]: items } as ProtocolIntelSummaryResponse;
            setData(acc.value);
          }
        },
        { signal }
      );

      if (reqSeq.current !== mySeq) return;
      if (!acc.value) throw new Error("empty stream");
      setFallbackSinceMinutes((acc.value.effective_since_minutes ?? null) as number | null);
      setLastOkAt(new Date());
    } catch {
      if (signal?.aborted || reqSeq.current !== mySeq) return;
      try {
        const res = await getProtocolIntelSummary(reqParams, { signal });
        if (reqSeq.current !== mySeq) return;
        setData(res);
        setFallbackSinceMinutes((res.effective_since_minutes ?? null) as number | null);
        setLastOkAt(new Date());
      } catch (e: any) {
        if (signal?.aborted || reqSeq.current !== mySeq) return;
        setError(getErrorMessage(e, "Failed to load summary"));
        setFallbackSinceMinutes(null);
      }
    } finally {
      if (reqSeq.current === mySeq) setLoading(false);
    }
  }, []);

  const load = useCallback(() => {
    void runLoad();
  }, [runLoad]);

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
      await runLoad(signal);
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
        <Button variant="primary" size="lg" onClick={applyDraft}>
          Apply
        </Button>
      ) : null}

      <Button variant="subtle" size="lg" onClick={() => void load()}>
        Refresh
      </Button>
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
              <div>
                <FieldLabel>Agent</FieldLabel>
                <SelectInput
                  value={draft.agent_id}
                  onChange={(e) => {
                    const v = e.target.value;
                    setDraft((s) => ({ ...s, agent_id: v }));
                    setView((cur) => ({ ...cur, agent_id: v }));
                  }}
                  className="mt-1 font-mono text-[11.5px]"
                >
                  <option value="">All agents</option>
                  {agentOptions.map((a) => (
                    <option key={a.agent_id} value={a.agent_id}>
                      {a.display_name}
                    </option>
                  ))}
                </SelectInput>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <FieldLabel>Lookback (min)</FieldLabel>
                  <TextInput
                    inputMode="numeric"
                    pattern="[0-9]*"
                    type="text"
                    value={draft.since_minutes}
                    onChange={(e) => {
                      const raw = digitsOnly(e.target.value).slice(0, 6);
                      setDraft((s) => ({ ...s, since_minutes: raw }));
                    }}
                    placeholder={String(view.since_minutes)}
                    className="mt-1 font-mono text-[11.5px]"
                  />
                  <div className="mt-1 text-[11px] text-muted-foreground">1–43200 (30 days)</div>
                </div>

                <div>
                  <FieldLabel>Top-N</FieldLabel>
                  <TextInput
                    inputMode="numeric"
                    pattern="[0-9]*"
                    type="text"
                    value={draft.top_n}
                    onChange={(e) => {
                      const raw = digitsOnly(e.target.value).slice(0, 3);
                      setDraft((s) => ({ ...s, top_n: raw }));
                    }}
                    placeholder={String(view.top_n)}
                    className="mt-1 font-mono text-[11.5px]"
                  />
                  <div className="mt-1 text-[11px] text-muted-foreground">5–200</div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <FieldLabel>Refresh cadence</FieldLabel>
                  <div className="mt-1 inline-flex h-9 w-full items-center rounded-md border border-border bg-surface-2 px-3 font-mono text-[11px] text-muted-foreground">
                    {draft.auto_refresh ? `${Math.round(live.state.profile.fallbackMs / 1000)}s shared fallback` : "Manual only"}
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground">Controlled centrally by the live-refresh policy.</div>
                </div>

                <div className="flex items-end">
                  <div className="inline-flex h-9 w-full items-center rounded-md border border-border bg-card px-3">
                    <ToggleSwitch
                      label="Auto refresh"
                      checked={draft.auto_refresh}
                      onChange={(e) => setDraft((s) => ({ ...s, auto_refresh: e.target.checked }))}
                    />
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                <div className="text-[11px] text-muted-foreground">
                  {isDirty ? "Draft changes pending — click Apply to update the query scope." : "Scope applied."}
                </div>
                <div className="flex items-center gap-2">
                  {isDirty ? (
                    <Button variant="primary" size="md" onClick={applyDraft}>
                      Apply
                    </Button>
                  ) : null}
                  <Button variant="subtle" size="md" onClick={() => setDraft(draftFromView(view))} disabled={!isDirty}>
                    Reset
                  </Button>
                </div>
              </div>

              {parseDraftInt(draft.since_minutes, view.since_minutes) > 60 * 24 ? (
                <InlineAlert tone="warning" className="text-xs">
                  Large lookback windows can be expensive. Auto refresh is disabled above 24h to protect CPU/DB.
                </InlineAlert>
              ) : parseDraftInt(draft.since_minutes, view.since_minutes) > 60 * 12 && draft.auto_refresh ? (
                <InlineAlert tone="info" className="text-xs">
                  Refresh interval was increased to reduce CPU load for large windows.
                </InlineAlert>
              ) : null}
            </div>
          </Section>

          <Section title="Coverage" right={data ? `generated ${generatedAt}` : ""}>
            <div className="grid grid-cols-2 gap-3">
              <MetricCard title="Total events" value={data ? data.total_events : "-"} helper={`Lookback ${view.since_minutes} min`} />
              <MetricCard title="With protocol metadata" value={data ? data.with_proto_metadata : "-"} helper={`Coverage ${coverage}`} />
              <MetricCard title="DNS" value={data ? data.dns_events : "-"} />
              <MetricCard title="HTTP" value={data ? data.http_events : "-"} />
              <MetricCard title="TLS/DTLS/QUIC" value={data ? data.tls_events : "-"} />
              <MetricCard title="Last updated" value={lastOkAt ? fmtDateTime(lastOkAt) : "-"} />
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

          {!hasBlockingState && error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}

          {!hasBlockingState && !error && fallbackSinceMinutes ? (
            <InlineAlert tone="info">
              No events were found in the selected window. Showing historical protocol telemetry from the last{" "}
              <span className="font-mono">{fallbackSinceMinutes}</span> minutes.
            </InlineAlert>
          ) : null}

          {!hasBlockingState && data?.meta ? (
            <DataQueryStateBanner
              tone={data.meta.degraded_reason ? "warning" : "neutral"}
              message={fmtQueryMeta(data.meta)}
            />
          ) : null}

          {!hasBlockingState && shouldWarnNoCoverage ? (
            <InlineAlert tone="warning">
              <div className="space-y-0.5">
                <div className="font-semibold">No protocol metadata in this window.</div>
                <div>
                  L7 collection is enabled by default. If tables stay empty, confirm the{" "}
                  <span className="font-mono">proto-intel</span> worker is running and that agents are capturing
                  traffic (DNS, HTTP, or TLS handshakes).
                </div>
              </div>
            </InlineAlert>
          ) : null}

          <Tabs<IntelTab>
            value={activeTab}
            onChange={setActiveTab}
            tabs={[
              { key: "protocols", label: "Protocols" },
              { key: "names", label: "Hosts & Names" },
              { key: "fingerprints", label: "Fingerprints" },
              { key: "ports", label: "Ports" },
            ]}
          />

          {!hasBlockingState && activeTab === "protocols" ? (
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
              <Section title="Application protocols (L7)" right={`top ${view.top_n}`} padded={false}>
                {loading && !data ? <div className="p-4"><Loading label="Loading..." /></div> : null}
                {!loading && data && data.app_protocols.length === 0 ? (
                  <div className="p-4">
                    <TableEmpty
                      title="No protocols classified yet"
                      desc="Plaintext HTTP is labelled HTTP. Encrypted traffic (HTTPS, QUIC) appears as TLS or QUIC unless a handshake was captured."
                    />
                  </div>
                ) : null}
                {data && data.app_protocols.length > 0 ? (
                  <div className="space-y-2">
                    <div className="px-4 pt-3 text-[11px] text-muted-foreground leading-relaxed">
                      <span className="font-mono">http</span> = plaintext request bytes visible ·{" "}
                      <span className="font-mono">tls</span>/<span className="font-mono">quic</span>/<span className="font-mono">dtls</span> = encrypted, handshake only
                    </div>
                    <Table
                      className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                      columns={[
                        {
                          key: "key",
                          title: "APP PROTO",
                          render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                        },
                        {
                          key: "count",
                          title: "COUNT",
                          align: "right",
                          width: 80,
                          render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                        },
                        {
                          key: "act",
                          title: "",
                          align: "right",
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

              <Section title="Transport protocols (L4)" right={`top ${view.top_n}`} padded={false}>
                {!loading && data && data.transport_protocols.length === 0 ? <div className="p-4"><TableEmpty title="No transport protocols" /></div> : null}
                {data && data.transport_protocols.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "key",
                        title: "PROTO",
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
                        render: (r) => (
                          <InspectButton onClick={() => mkPick("transport", r.key, "Transport protocol", r.count, "Layer-4 protocol mix")} />
                        )
                      }
                    ] as Array<Column<any>>}
                    rows={data.transport_protocols}
                    rowKey={(r) => r.key}
                  />
                ) : null}
              </Section>

              <Section title="HTTP methods" right="from plaintext HTTP/1 parsing" padded={false}>
                {!loading && data && data.http_methods.length === 0 ? (
                  <div className="p-4"><TableEmpty title="No HTTP methods" desc="Requires plaintext HTTP/1 request payloads. Encrypted HTTPS traffic does not contribute here." /></div>
                ) : null}
                {data && data.http_methods.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "key",
                        title: "METHOD",
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
                        render: (r) => (
                          <InspectButton onClick={() => mkPick("http_method", r.key, "HTTP method", r.count, "HTTP request methods")} />
                        )
                      }
                    ] as Array<Column<any>>}
                    rows={data.http_methods}
                    rowKey={(r) => r.key}
                  />
                ) : null}
              </Section>

              <Section title="JA4 ptype distribution" right="q=QUIC · d=DTLS · t=TLS" padded={false}>
                {!loading && data && data.ja4_ptypes.length === 0 ? (
                  <div className="p-4"><TableEmpty title="No JA4 ptype data" desc="Populated when TLS, QUIC, or DTLS handshakes are fingerprinted." /></div>
                ) : null}
                {data && data.ja4_ptypes.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "key",
                        title: "PTYPE",
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
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
                ) : null}
              </Section>

              <Section title="Classification reasons" right={`top ${view.top_n}`} padded={false}>
                {!loading && data && data.app_proto_reasons.length === 0 ? (
                  <div className="p-4"><TableEmpty title="No classification reasons yet" desc="Reasons appear once the proto-intel worker processes events." /></div>
                ) : null}
                {data && data.app_proto_reasons.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "key",
                        title: "REASON",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
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
                ) : null}
              </Section>

              <Section title="Confidence bands" right="80-100 · 60-79 · 40-59 · 0-39" padded={false}>
                {!loading && data && data.app_proto_conf_bands.length === 0 ? (
                  <div className="p-4"><TableEmpty title="No confidence bands yet" desc="Bands reflect how certain the classifier is: agent evidence scores 99, parsed payloads 98, port guesses 70-90." /></div>
                ) : null}
                {data && data.app_proto_conf_bands.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "key",
                        title: "BAND",
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
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
                ) : null}
              </Section>
            </div>
          ) : null}

          {!hasBlockingState && activeTab === "ports" ? (
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
              <Section title="Top destination ports" right={`top ${view.top_n} by volume`} padded={false}>
                {!loading && data && data.top_dst_ports.length === 0 ? <div className="p-4"><TableEmpty title="No destination ports" /></div> : null}
                {data && data.top_dst_ports.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "key",
                        title: "DST PORT",
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
                        render: (r) => <InspectButton onClick={() => mkPick("dst_port", r.key, "Destination port", r.count)} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_dst_ports}
                    rowKey={(r) => r.key}
                  />
                ) : null}
              </Section>

              <Section title="Top source ports" right={`top ${view.top_n} by volume`} padded={false}>
                {!loading && data && data.top_src_ports.length === 0 ? <div className="p-4"><TableEmpty title="No source ports" /></div> : null}
                {data && data.top_src_ports.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "key",
                        title: "SRC PORT",
                        render: (r) => <span className="font-mono text-[12px]">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
                        render: (r) => <InspectButton onClick={() => mkPick("src_port", r.key, "Source port", r.count)} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_src_ports}
                    rowKey={(r) => r.key}
                  />
                ) : null}
              </Section>
            </div>
          ) : null}

          {!hasBlockingState && activeTab === "names" ? (
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
              <Section title="Top DNS queries" right={`top ${view.top_n} by volume`} padded={false}>
                {!loading && data && data.top_dns_queries.length === 0 ? <div className="p-4"><TableEmpty title="No DNS evidence" desc="DNS queries require payload evidence." /></div> : null}
                {data && data.top_dns_queries.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "qname",
                        title: "QNAME",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.qname}</span>
                      },
                      {
                        key: "risk",
                        title: "RISK",
                        width: 80,
                        render: (r) => <RiskPill risk={r.risk} />
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
                        render: (r) => <InspectButton onClick={() => mkPick("dns_qname", r.qname, "DNS qname", r.count, "Top DNS queries")} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_dns_queries}
                    rowKey={(r, i) => `${r.qname}-${i}`}
                  />
                ) : null}
              </Section>

              <Section title="Top HTTP hosts" right={`top ${view.top_n} by volume`} padded={false}>
                {!loading && data && data.top_http_hosts.length === 0 ? <div className="p-4"><TableEmpty title="No HTTP evidence" desc="HTTP hosts require payload evidence." /></div> : null}
                {data && data.top_http_hosts.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "key",
                        title: "HOST",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
                        render: (r) => <InspectButton onClick={() => mkPick("http_host", r.key, "HTTP host", r.count, "Top HTTP Host headers")} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_http_hosts}
                    rowKey={(r) => r.key}
                  />
                ) : null}
              </Section>

              <Section title="Top TLS SNI" right={`top ${view.top_n} by volume`} padded={false}>
                {!loading && data && data.top_tls_sni.length === 0 ? <div className="p-4"><TableEmpty title="No SNI" desc="SNI requires TLS ClientHello evidence." /></div> : null}
                {data && data.top_tls_sni.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "key",
                        title: "SNI",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
                        render: (r) => <InspectButton onClick={() => mkPick("tls_sni", r.key, "TLS SNI", r.count, "Top SNI values")} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_tls_sni}
                    rowKey={(r) => r.key}
                  />
                ) : null}
              </Section>

              <Section title="Top TLS/QUIC ALPN" right={`top ${view.top_n} by volume`} padded={false}>
                {!loading && data && data.top_alpn.length === 0 ? <div className="p-4"><TableEmpty title="No ALPN" desc="ALPN requires TLS ClientHello evidence." /></div> : null}
                {data && data.top_alpn.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "key",
                        title: "ALPN",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
                        render: (r) => <InspectButton onClick={() => mkPick("tls_alpn_first", r.key, "ALPN", r.count, "Top ALPN values")} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_alpn}
                    rowKey={(r) => r.key}
                  />
                ) : null}
              </Section>
            </div>
          ) : null}

          {!hasBlockingState && activeTab === "fingerprints" ? (
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
              <Section title="Top JA4 fingerprints" right={`top ${view.top_n} by volume`} padded={false}>
                {!loading && data && data.top_ja4.length === 0 ? <div className="p-4"><TableEmpty title="No JA4" desc="JA4 requires TLS/DTLS/QUIC fingerprint evidence." /></div> : null}
                {data && data.top_ja4.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "ja4",
                        title: "JA4",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.ja4}</span>
                      },
                      {
                        key: "ptype",
                        title: "PTYPE",
                        width: 80,
                        render: (r) => (
                          <span className="font-mono text-[12px]">
                            <Badge>{r.ptype || "t"}</Badge>
                          </span>
                        )
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
                        render: (r) => <InspectButton onClick={() => mkPick("ja4", r.ja4, "JA4 fingerprint", r.count, `ptype=${r.ptype}`)} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_ja4}
                    rowKey={(r, i) => `${r.ja4}-${r.ptype || "t"}-${i}`}
                  />
                ) : null}
              </Section>

              <Section title="Top JA3 fingerprints" right={`top ${view.top_n} by volume`} padded={false}>
                {!loading && data && data.top_ja3.length === 0 ? <div className="p-4"><TableEmpty title="No JA3" desc="JA3 requires TLS ClientHello evidence." /></div> : null}
                {data && data.top_ja3.length > 0 ? (
                  <Table
                    className="!shadow-none !border-0 !bg-transparent !rounded-none seagullTable-inset"
                    columns={[
                      {
                        key: "key",
                        title: "JA3",
                        render: (r) => <span className="font-mono text-[12px] break-all">{r.key}</span>
                      },
                      {
                        key: "count",
                        title: "COUNT",
                        align: "right",
                        width: 80,
                        render: (r) => <span className="font-mono text-[12px]">{r.count}</span>
                      },
                      {
                        key: "act",
                        title: "",
                        align: "right",
                        render: (r) => <InspectButton onClick={() => mkPick("ja3", r.key, "JA3 fingerprint", r.count)} />
                      }
                    ] as Array<Column<any>>}
                    rows={data.top_ja3}
                    rowKey={(r) => r.key}
                  />
                ) : null}
              </Section>
            </div>
          ) : null}

          {!hasBlockingState && loading && data ? (
            <div className="text-xs text-muted-foreground">Refreshing…</div>
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
