import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import PageHeader from "@/shared/components/PageHeader";
import Loading from "@/shared/components/Loading";
import EmptyState from "@/shared/components/EmptyState";
import { Card } from "@/shared/components/Card";
import { Table } from "@/shared/components/Table";
import { Badge } from "@/shared/components/Badge";

import { useAgentsCatalog } from "@/app/providers";

import { getNetworkSummary } from "./api";
import type { DnsQnameStat, NetworkSummaryResponse, TlsJa4Stat, TopValue } from "./types";
import NetworkIndicatorDrawer, { type IndicatorSelection, type IndicatorKind } from "./NetworkIndicatorDrawer";

function ActionButton({
  children,
  onClick,
  disabled,
  title
}: {
  children: any;
  onClick: () => void;
  disabled?: boolean;
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={
        "inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20 disabled:opacity-50"
      }
    >
      {children}
    </button>
  );
}

type ViewCfg = {
  agent_id: string; // empty = all agents
  since_minutes: number;
  limit: number;
  auto_refresh: boolean;
  refresh_ms: number;
  samples_window_minutes: number;
};

const LS_KEY = "nw_network_intel_view_v1";

const DEFAULTS: ViewCfg = {
  agent_id: "",
  since_minutes: 60 * 24,
  limit: 25,
  auto_refresh: true,
  refresh_ms: 15000,
  samples_window_minutes: 60 * 6
};

function clampInt(v: any, min: number, max: number, fallback: number) {
  const n = Number.parseInt(String(v ?? ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function safeLoadView(): ViewCfg {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw) as Partial<ViewCfg>;
    return {
      ...DEFAULTS,
      ...parsed,
      agent_id: (parsed.agent_id ?? "").trim(),
      since_minutes: clampInt(parsed.since_minutes, 1, 60 * 24 * 30, DEFAULTS.since_minutes),
      limit: clampInt(parsed.limit, 5, 200, DEFAULTS.limit),
      refresh_ms: clampInt(parsed.refresh_ms, 2000, 300000, DEFAULTS.refresh_ms),
      samples_window_minutes: clampInt(parsed.samples_window_minutes, 5, 60 * 24 * 7, DEFAULTS.samples_window_minutes),
      auto_refresh: Boolean(parsed.auto_refresh)
    };
  } catch {
    return DEFAULTS;
  }
}

function persistView(v: ViewCfg) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(v));
  } catch {
    // no-op
  }
}

function fmtWhen(iso?: string | null) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

function fmtAgo(ms: number) {
  if (!Number.isFinite(ms) || ms <= 0) return "";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  return `${h}h ago`;
}

function ptypeBadge(v?: string | null) {
  const x = String(v || "").toLowerCase();
  if (x === "q") return <Badge variant="info">quic</Badge>;
  if (x === "d") return <Badge variant="medium">dtls</Badge>;
  if (x === "t") return <Badge variant="neutral">tls</Badge>;
  return <Badge variant="neutral">unknown</Badge>;
}

function riskBadge(r: number | null | undefined) {
  const rr = typeof r === "number" ? r : 0;
  if (rr >= 70) return <Badge variant="critical">risk {rr}</Badge>;
  if (rr >= 40) return <Badge variant="high">risk {rr}</Badge>;
  if (rr >= 20) return <Badge variant="medium">risk {rr}</Badge>;
  return <Badge variant="neutral">risk {rr}</Badge>;
}

function StatTile({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="rounded-lg border border-border/60 bg-background/40 px-3 py-2">
      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className="mt-1 text-xl font-semibold tracking-tight">{value}</div>
      {hint ? <div className="mt-1 text-[11px] text-muted-foreground">{hint}</div> : null}
    </div>
  );
}

function MiniSelect({
  label,
  value,
  onChange,
  children
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  children: ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="h-9 rounded-md border border-border/60 bg-background/40 px-2 text-sm"
      >
        {children}
      </select>
    </label>
  );
}

function MiniInput({
  label,
  value,
  onChange,
  min,
  max,
  step
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  min: number;
  max: number;
  step?: number;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</span>
      <input
        type="number"
        value={value}
        min={min}
        max={max}
        step={step ?? 1}
        onChange={(e) => onChange(clampInt(e.target.value, min, max, value))}
        className="h-9 rounded-md border border-border/60 bg-background/40 px-2 text-sm"
      />
    </label>
  );
}

function MiniToggle({
  label,
  checked,
  onChange,
  hint
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  hint?: string;
}) {
  return (
    <label className="flex items-start gap-3 rounded-lg border border-border/60 bg-background/40 px-3 py-2">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="mt-1" />
      <div className="min-w-0">
        <div className="text-[12px] font-mono text-foreground">{label}</div>
        {hint ? <div className="mt-1 text-[11px] text-muted-foreground">{hint}</div> : null}
      </div>
    </label>
  );
}

function toEventsLink(params: { agent_id?: string; search?: string }): string {
  const q = new URLSearchParams();
  if (params.agent_id) q.set("agent_id", params.agent_id);
  if (params.search) q.set("search", params.search);
  const s = q.toString();
  return s ? `/events?${s}` : "/events";
}

function huntToken(key: string, value: string): string {
  // Search is substring-based; using a JSON-ish token reduces false positives.
  return `"${key}":${JSON.stringify(String(value))}`;
}

function withBars<T extends { count: number }>(rows: T[]) {
  const max = rows.reduce((acc, r) => Math.max(acc, r.count), 0) || 1;
  return { rows, max };
}

function bar(count: number, max: number) {
  const pct = Math.max(0, Math.min(100, Math.round((count / max) * 100)));
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 w-24 rounded bg-muted/20">
        <div className="h-2 rounded bg-primary/40" style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono">{count}</span>
    </div>
  );
}

export default function NetworkIntelPage() {
  const { agents } = useAgentsCatalog();
  const [searchParams, setSearchParams] = useSearchParams();

  const [view, setView] = useState<ViewCfg>(() => safeLoadView());
  const viewRef = useRef(view);
  useEffect(() => {
    viewRef.current = view;
    persistView(view);
  }, [view]);

  const didInitFromUrl = useRef(false);
  useEffect(() => {
    if (didInitFromUrl.current) return;
    didInitFromUrl.current = true;

    const agent_id = (searchParams.get("agent_id") ?? "").trim();
    const since_minutes = clampInt(searchParams.get("since_minutes"), 1, 60 * 24 * 30, viewRef.current.since_minutes);
    const limit = clampInt(searchParams.get("limit"), 5, 200, viewRef.current.limit);

    if (agent_id || since_minutes !== viewRef.current.since_minutes || limit !== viewRef.current.limit) {
      setView((prev) => ({ ...prev, agent_id, since_minutes, limit }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const q = new URLSearchParams();
    if (view.agent_id) q.set("agent_id", view.agent_id);
    q.set("since_minutes", String(view.since_minutes));
    q.set("limit", String(view.limit));
    setSearchParams(q, { replace: true });
  }, [view.agent_id, view.since_minutes, view.limit, setSearchParams]);

  const [data, setData] = useState<NetworkSummaryResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastLoadedAt, setLastLoadedAt] = useState<number | null>(null);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerSel, setDrawerSel] = useState<IndicatorSelection | null>(null);

  const openDrawer = useCallback((kind: IndicatorKind, value: string, count?: number) => {
    setDrawerSel({ kind, value, count });
    setDrawerOpen(true);
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const r = await getNetworkSummary({
        agent_id: viewRef.current.agent_id || undefined,
        since_minutes: viewRef.current.since_minutes,
        limit: viewRef.current.limit
      });
      setData(r);
      setError(null);
      setLastLoadedAt(Date.now());
    } catch (e: any) {
      setError(e?.message || "Failed to load protocol intelligence");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [view.agent_id, view.since_minutes, view.limit, refresh]);

  useEffect(() => {
    if (!view.auto_refresh) return;
    const t = window.setInterval(() => refresh(), view.refresh_ms);
    return () => window.clearInterval(t);
  }, [view.auto_refresh, view.refresh_ms, refresh]);

  const headerRight = useMemo(() => {
    const lastAgo = lastLoadedAt ? fmtAgo(Date.now() - lastLoadedAt) : "";
    return (
      <div className="flex flex-wrap items-end justify-end gap-3">
        <MiniSelect
          label="Agent"
          value={view.agent_id}
          onChange={(v) => setView((p) => ({ ...p, agent_id: v }))}
        >
          <option value="">All agents</option>
          {agents.map((a) => (
            <option key={a.id} value={a.id}>
              {a.id}
            </option>
          ))}
        </MiniSelect>

        <MiniInput
          label="Lookback (min)"
          value={view.since_minutes}
          min={1}
          max={60 * 24 * 30}
          onChange={(v) => setView((p) => ({ ...p, since_minutes: v }))}
        />

        <MiniInput label="Top-N" value={view.limit} min={5} max={200} onChange={(v) => setView((p) => ({ ...p, limit: v }))} />

        <MiniInput
          label="Refresh (ms)"
          value={view.refresh_ms}
          min={2000}
          max={300000}
          step={500}
          onChange={(v) => setView((p) => ({ ...p, refresh_ms: v }))}
        />

        <MiniInput
          label="Samples window (min)"
          value={view.samples_window_minutes}
          min={5}
          max={60 * 24 * 7}
          onChange={(v) => setView((p) => ({ ...p, samples_window_minutes: v }))}
        />

        <div className="flex flex-col gap-1">
          <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Actions</span>
          <div className="flex gap-2">
            <ActionButton onClick={refresh} disabled={loading} title="Refresh now">
              Refresh
            </ActionButton>
            <Link
              to={toEventsLink({ agent_id: view.agent_id || undefined, search: "proto_intel_at" })}
              className={
                "inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
              }
              title="Jump to Events with protocol metadata"
            >
              Hunt
            </Link>
          </div>
        </div>

        <div className="w-[280px]">
          <MiniToggle
            label="Auto refresh"
            checked={view.auto_refresh}
            onChange={(v) => setView((p) => ({ ...p, auto_refresh: v }))}
            hint={lastAgo ? `Last updated: ${lastAgo}` : undefined}
          />
        </div>
      </div>
    );
  }, [agents, view, loading, refresh, lastLoadedAt]);

  const totals = data?.totals;
  const coveragePct = useMemo(() => {
    if (!totals) return 0;
    if (!totals.total_events) return 0;
    return Math.round((totals.proto_intel_events / totals.total_events) * 100);
  }, [totals]);

  const appProtoBars = useMemo(() => withBars((data?.app_proto || []).map((r) => ({ ...r, count: r.count }))), [data]);

  const dnsRows = data?.dns_qnames || [];
  const dnsBars = useMemo(() => withBars(dnsRows.map((r) => ({ ...r, count: r.count }))), [dnsRows]);

  const httpHosts = data?.http_hosts || [];
  const httpHostBars = useMemo(() => withBars(httpHosts.map((r) => ({ ...r, count: r.count }))), [httpHosts]);

  const tlsJa4 = data?.tls_ja4 || [];
  const tlsJa4Bars = useMemo(() => withBars(tlsJa4.map((r) => ({ ...r, count: r.count }))), [tlsJa4]);

  const tlsSni = data?.tls_sni || [];
  const tlsSniBars = useMemo(() => withBars(tlsSni.map((r) => ({ ...r, count: r.count }))), [tlsSni]);

  const httpMethods = data?.http_methods || [];
  const httpMethodBars = useMemo(() => withBars(httpMethods.map((r) => ({ ...r, count: r.count }))), [httpMethods]);

  const ja4Ptypes = data?.ja4_ptype || [];
  const ja4PtypeBars = useMemo(() => withBars(ja4Ptypes.map((r) => ({ ...r, count: r.count }))), [ja4Ptypes]);

  const tlsAlpn = data?.tls_alpn || [];
  const tlsAlpnBars = useMemo(() => withBars(tlsAlpn.map((r) => ({ ...r, count: r.count }))), [tlsAlpn]);

  const ja3Rows = data?.tls_ja3 || [];
  const ja3Bars = useMemo(() => withBars(ja3Rows.map((r) => ({ ...r, count: r.count }))), [ja3Rows]);

  const dnsCols = useMemo(
    () => [
      {
        key: "qname",
        title: "QNAME",
        render: (r: DnsQnameStat) => <span className="font-mono text-xs break-all">{r.qname}</span>
      },
      {
        key: "risk",
        title: "Risk",
        width: 110,
        render: (r: DnsQnameStat) => riskBadge(r.max_risk ?? 0)
      },
      {
        key: "count",
        title: "Count",
        width: 160,
        render: (r: DnsQnameStat) => bar(r.count, dnsBars.max)
      },
      {
        key: "actions",
        title: "",
        width: 170,
        render: (r: DnsQnameStat) => (
          <div className="flex items-center justify-end gap-2">
            <ActionButton onClick={() => openDrawer("dns_qname", r.qname, r.count)}>Inspect</ActionButton>
            <Link
              to={toEventsLink({ agent_id: view.agent_id || undefined, search: huntToken("dns_qname", r.qname) })}
              className={
                "inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
              }
            >
              Hunt
            </Link>
          </div>
        )
      }
    ],
    [dnsBars.max, openDrawer, view.agent_id]
  );

  const simpleCols = useCallback(
    (kind: IndicatorKind, label: string, rows: TopValue[], max: number) => [
      {
        key: "value",
        title: label,
        render: (r: TopValue) => <span className="font-mono text-xs break-all">{r.value}</span>
      },
      {
        key: "count",
        title: "Count",
        width: 160,
        render: (r: TopValue) => bar(r.count, max)
      },
      {
        key: "actions",
        title: "",
        width: 170,
        render: (r: TopValue) => (
          <div className="flex items-center justify-end gap-2">
            <ActionButton onClick={() => openDrawer(kind, r.value, r.count)}>Inspect</ActionButton>
            <Link
              to={toEventsLink({ agent_id: view.agent_id || undefined, search: huntToken(kind, r.value) })}
              className={
                "inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
              }
            >
              Hunt
            </Link>
          </div>
        )
      }
    ],
    [openDrawer, view.agent_id]
  );

  const ja4Cols = useMemo(
    () => [
      {
        key: "ja4",
        title: "JA4",
        render: (r: TlsJa4Stat) => <span className="font-mono text-xs break-all">{r.ja4}</span>
      },
      {
        key: "ptype",
        title: "PType",
        width: 110,
        render: (r: TlsJa4Stat) => ptypeBadge(r.ptype)
      },
      {
        key: "count",
        title: "Count",
        width: 160,
        render: (r: TlsJa4Stat) => bar(r.count, tlsJa4Bars.max)
      },
      {
        key: "actions",
        title: "",
        width: 170,
        render: (r: TlsJa4Stat) => (
          <div className="flex items-center justify-end gap-2">
            <ActionButton onClick={() => openDrawer("ja4", r.ja4, r.count)}>Inspect</ActionButton>
            <Link
              to={toEventsLink({ agent_id: view.agent_id || undefined, search: huntToken("ja4", r.ja4) })}
              className={
                "inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
              }
            >
              Hunt
            </Link>
          </div>
        )
      }
    ],
    [openDrawer, tlsJa4Bars.max, view.agent_id]
  );

  const protoCols = useMemo(
    () => [
      {
        key: "value",
        title: "App proto",
        render: (r: TopValue) => <Badge variant="neutral">{r.value || "unknown"}</Badge>
      },
      {
        key: "count",
        title: "Count",
        width: 160,
        render: (r: TopValue) => bar(r.count, appProtoBars.max)
      },
      {
        key: "actions",
        title: "",
        width: 170,
        render: (r: TopValue) => (
          <div className="flex items-center justify-end gap-2">
            <ActionButton
              onClick={() => openDrawer("http_host", r.value, r.count)}
              disabled
              title="Distribution rows are not indicators; open one of the tables below to inspect details"
            >
              Inspect
            </ActionButton>
            <Link
              to={toEventsLink({ agent_id: view.agent_id || undefined, search: huntToken("app_proto", r.value) })}
              className={
                "inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
              }
            >
              Hunt
            </Link>
          </div>
        )
      }
    ],
    [appProtoBars.max, openDrawer, view.agent_id]
  );

  return (
    <div>
      <PageHeader
        title="Protocol Intelligence"
        breadcrumb={["Telemetry", "Events"]}
        description={
          <span>
            Deep, protocol-aware metadata derived from raw network signals: DNS queries, HTTP hosts/methods, and TLS/DTLS/QUIC
            fingerprints (JA3/JA4). Use this page to pivot from high-volume indicators to the raw event timeline.
          </span>
        }
        toolbarRight={headerRight}
      />

      {loading ? <Loading /> : null}
      {error ? (
        <EmptyState
          title="Unable to load protocol intelligence"
          description={
            <span>
              {error}. If you recently enabled the <span className="font-mono">proto_intel</span> worker, wait a bit and
              refresh.
            </span>
          }
        />
      ) : null}

      {!loading && !error && data ? (
        <div className="grid grid-cols-1 gap-6">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-3">
            <StatTile label="Total events" value={totals?.total_events ?? 0} hint={`Lookback: ${data.since_minutes} min`} />
            <StatTile
              label="With protocol metadata"
              value={totals?.proto_intel_events ?? 0}
              hint={`Coverage: ${coveragePct}%`}
            />
            <StatTile label="DNS" value={totals?.dns_events ?? 0} />
            <StatTile label="HTTP" value={totals?.http_events ?? 0} />
            <StatTile label="TLS/QUIC/DTLS" value={totals?.tls_events ?? 0} />
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <Card
              title="Application protocols"
              right={
                <span>
                  Generated <span className="font-mono">{fmtWhen(data.generated_at)}</span>
                </span>
              }
            >
              <Table
                columns={protoCols as any}
                rows={data.app_proto}
                rowKey={(r: TopValue) => r.value}
                className="text-sm"
              />
            </Card>

            <Card title="JA4 ptype distribution" right="q=QUIC, d=DTLS, t=TLS">
              <Table
                columns={simpleCols("ja4_ptype", "PType", ja4Ptypes, ja4PtypeBars.max) as any}
                rows={ja4Ptypes}
                rowKey={(r: TopValue) => r.value}
                className="text-sm"
              />
            </Card>

            <Card title="HTTP methods" right="From HTTP/1 request parsing">
              <Table
                columns={simpleCols("http_method", "Method", httpMethods, httpMethodBars.max) as any}
                rows={httpMethods}
                rowKey={(r: TopValue) => r.value}
                className="text-sm"
              />
            </Card>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <Card title="Top DNS queries" right={`Top ${data.limit} by volume`}>
              <Table
                columns={dnsCols as any}
                rows={dnsRows}
                rowKey={(r: DnsQnameStat) => r.qname}
                className="text-sm"
              />
            </Card>

            <Card title="Top HTTP hosts" right={`Top ${data.limit} by volume`}>
              <Table
                columns={simpleCols("http_host", "Host", httpHosts, httpHostBars.max) as any}
                rows={httpHosts}
                rowKey={(r: TopValue) => r.value}
                className="text-sm"
              />
            </Card>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <Card title="Top TLS SNI" right={`Top ${data.limit} by volume`}>
              <Table
                columns={simpleCols("tls_sni", "SNI", tlsSni, tlsSniBars.max) as any}
                rows={tlsSni}
                rowKey={(r: TopValue) => r.value}
                className="text-sm"
              />
            </Card>

            <Card title="Top TLS/QUIC ALPN" right={`Top ${data.limit} by volume`}>
              <Table
                columns={simpleCols("tls_alpn_first", "ALPN", tlsAlpn, tlsAlpnBars.max) as any}
                rows={tlsAlpn}
                rowKey={(r: TopValue) => r.value}
                className="text-sm"
              />
            </Card>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <Card title="Top JA4 fingerprints" right={`Top ${data.limit} by volume`}>
              <Table
                columns={ja4Cols as any}
                rows={tlsJa4}
                rowKey={(r: TlsJa4Stat) => r.ja4}
                className="text-sm"
              />
            </Card>

            <Card title="Top JA3 fingerprints" right={`Top ${data.limit} by volume`}>
              <Table
                columns={simpleCols("ja3", "JA3", ja3Rows, ja3Bars.max) as any}
                rows={ja3Rows}
                rowKey={(r: TopValue) => r.value}
                className="text-sm"
              />
            </Card>
          </div>
        </div>
      ) : null}

      <NetworkIndicatorDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        selection={drawerSel}
        agent_id={view.agent_id}
        window_minutes={view.samples_window_minutes}
      />
    </div>
  );
}
