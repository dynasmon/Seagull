import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import AsyncState from "@/shared/components/AsyncState";
import EmptyState from "@/shared/components/EmptyState";
import { DataQueryStateBanner, DataStatsStrip, DataViewToolbar } from "@/shared/components/DataView";
import { Card } from "@/shared/components/Card";
import { Table } from "@/shared/components/Table";
import { Badge } from "@/shared/components/Badge";
import { cx } from "@/shared/lib/cx";
import { getErrorMessage } from "@/shared/lib/errors";
import { clampInt } from "@/shared/lib/filters";

import { useAgentsCatalog } from "@/app/providers";

import { getSshSummary } from "./api";
import type { SshAuthEvent, SshIpStat, SshLoginEvent, SshSummaryResponse, SshUserStat, SudoEventSummary } from "./types";
import SshIpDrawer from "./SshIpDrawer";

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
        "inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
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
};

const LS_KEY = "nw_ssh_insights_view_v1";

const DEFAULTS: ViewCfg = {
  agent_id: "",
  since_minutes: 60 * 24,
  limit: 50,
  auto_refresh: true,
  refresh_ms: 15000
};

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
      limit: clampInt(parsed.limit, 1, 500, DEFAULTS.limit),
      refresh_ms: clampInt(parsed.refresh_ms, 2000, 300000, DEFAULTS.refresh_ms),
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

function fmtQueryMeta(meta?: { source?: string; source_freshness_seconds?: number | null; degraded_reason?: string | null; cache_hit?: boolean; approximate?: boolean; query_latency_ms?: number | null } | null) {
  if (!meta) return "source: -";
  const src = String(meta.source || "unknown");
  const fresh = typeof meta.source_freshness_seconds === "number" ? `${meta.source_freshness_seconds}s` : "-";
  const latency = typeof meta.query_latency_ms === "number" ? `${Math.round(meta.query_latency_ms)}ms` : "-";
  const degraded = meta.degraded_reason ? `degraded (${meta.degraded_reason})` : "ok";
  const cache = meta.cache_hit ? "cache" : "live";
  return `source ${src} · fresh ${fresh} · latency ${latency} · ${cache} · ${degraded}`;
}

function toEventsLink(params: { agent_id?: string; event_type?: string; search?: string }): string {
  const q = new URLSearchParams();
  if (params.agent_id) q.set("agent_id", params.agent_id);
  if (params.event_type) q.set("event_type", params.event_type);
  if (params.search) q.set("search", params.search);
  const s = q.toString();
  return s ? `/events?${s}` : "/events";
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

function ipMeta(r: Pick<SshIpStat, "geo_country" | "geo_org" | "asn" | "asn_org">) {
  const country = (r.geo_country ?? "").trim();
  const org = (r.geo_org ?? "").trim();
  const asn = (r.asn ?? "").trim();
  const asnOrg = (r.asn_org ?? "").trim();
  return {
    country: country || null,
    org: org || null,
    asn: asn || null,
    asnOrg: asnOrg || null
  };
}

export default function SshInsightsPage() {
  const { agents } = useAgentsCatalog();
  const [searchParams, setSearchParams] = useSearchParams();

  const [view, setView] = useState<ViewCfg>(() => safeLoadView());
  const viewRef = useRef(view);
  useEffect(() => {
    viewRef.current = view;
    persistView(view);
  }, [view]);

  // One-time URL hydration (shareable links).
  const didInitFromUrl = useRef(false);
  useEffect(() => {
    if (didInitFromUrl.current) return;
    didInitFromUrl.current = true;

    const agent_id = (searchParams.get("agent_id") ?? "").trim();
    const since_minutes = clampInt(searchParams.get("since_minutes"), 1, 60 * 24 * 30, viewRef.current.since_minutes);
    const limit = clampInt(searchParams.get("limit"), 1, 500, viewRef.current.limit);

    if (agent_id || since_minutes !== viewRef.current.since_minutes || limit !== viewRef.current.limit) {
      setView((prev) => ({ ...prev, agent_id, since_minutes, limit }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sync URL with view (shareable state).
  useEffect(() => {
    const q = new URLSearchParams();
    if (view.agent_id) q.set("agent_id", view.agent_id);
    q.set("since_minutes", String(view.since_minutes));
    q.set("limit", String(view.limit));
    setSearchParams(q, { replace: true });
  }, [view.agent_id, view.since_minutes, view.limit, setSearchParams]);

  const [data, setData] = useState<SshSummaryResponse | null>(null);
  const dataRef = useRef<SshSummaryResponse | null>(null);
  useEffect(() => {
    dataRef.current = data;
  }, [data]);

  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const reqSeq = useRef(0);

  const refresh = useCallback(async () => {
    const mySeq = ++reqSeq.current;
    const hasData = Boolean(dataRef.current);
    if (hasData) setRefreshing(true);
    else setLoading(true);
    try {
      const r = await getSshSummary({
        agent_id: viewRef.current.agent_id,
        since_minutes: viewRef.current.since_minutes,
        limit: viewRef.current.limit
      });
      if (reqSeq.current !== mySeq) return;
      setData(r);
      setError(null);
      setLastUpdatedAt(Date.now());
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      const msg = getErrorMessage(e, "Failed to load SSH summary");
      setError(msg);
      // keep last known good data (no flicker)
      if (dataRef.current) setData(dataRef.current);
    } finally {
      if (reqSeq.current !== mySeq) return;
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    refresh();
  }, [refresh]);

  // Auto refresh
  useEffect(() => {
    if (!view.auto_refresh) return;
    let alive = true;
    const t = window.setInterval(() => {
      if (!alive) return;
      refresh();
    }, view.refresh_ms);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [view.auto_refresh, view.refresh_ms, refresh]);

  const totals = useMemo(() => {
    const d = data;
    const success = Number(d?.total_accepted ?? 0);
    const failed = Number(d?.total_failed_password ?? 0);
    const invalid = Number(d?.total_invalid_user ?? 0);
    const actions = Number(d?.total_actions ?? success + failed + invalid);
    const uniqueIps = Number(d?.unique_source_ips ?? 0);
    const enriched = Number(d?.enriched_source_ips ?? 0);
    const enrichPct = uniqueIps > 0 ? Math.round((enriched / uniqueIps) * 100) : 0;

    return { success, failed, invalid, actions, uniqueIps, enriched, enrichPct };
  }, [data]);

  const agentOptions = useMemo(() => {
    const rows = (agents ?? []).slice().sort((a, b) => a.agent_id.localeCompare(b.agent_id));
    return rows;
  }, [agents]);

  const agentNameById = useMemo(() => {
    const map: Record<string, string> = {};
    for (const a of agents || []) {
      if (!a?.agent_id) continue;
      map[a.agent_id] = a.display_name || a.agent_id;
    }
    return map;
  }, [agents]);

  const [ipDrawerOpen, setIpDrawerOpen] = useState(false);
  const [ipDrawerRow, setIpDrawerRow] = useState<SshIpStat | null>(null);

  function openIpDrawer(row: SshIpStat) {
    setIpDrawerRow(row);
    setIpDrawerOpen(true);
  }

  const rightHint = useMemo(() => {
    const parts: string[] = [];
    parts.push(`Lookback: ${view.since_minutes}m`);
    parts.push(`Rows: ${view.limit}`);
    if (data?.meta?.source) parts.push(`Source: ${data.meta.source}`);
    if (lastUpdatedAt) parts.push(`Updated: ${fmtAgo(Date.now() - lastUpdatedAt)}`);
    return parts.join(" • ");
  }, [view.since_minutes, view.limit, lastUpdatedAt, data?.meta?.source]);

  const headerRight = (
    <div className="flex items-center gap-2">
      {refreshing ? <Badge variant="info">Refreshing…</Badge> : null}
      {error ? <Badge variant="high">{error}</Badge> : null}
      <button
        type="button"
        onClick={refresh}
        className="h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
      >
        Refresh
      </button>
    </div>
  );

  const current = data;

  return (
    <div className="space-y-4">
      <DataViewToolbar
        left={<div className="text-sm font-semibold tracking-tight">SSH Insights</div>}
        right={headerRight}
      />

      <DataStatsStrip
        stats={[
          { label: "Accepted", value: totals.success },
          { label: "Failed password", value: totals.failed },
          { label: "Invalid user", value: totals.invalid },
          { label: "Total actions", value: totals.actions },
          { label: "Unique source IPs", value: totals.uniqueIps },
          { label: "Enriched source IPs", value: `${totals.enrichPct}%`, hint: `${totals.enriched}/${totals.uniqueIps}` },
          { label: "Scope", value: view.agent_id || "all agents", hint: `Lookback ${view.since_minutes}m` },
          { label: "Rows", value: view.limit, hint: view.auto_refresh ? `Auto ${Math.round(view.refresh_ms / 1000)}s` : "Manual refresh" },
        ]}
      />

      {current?.meta ? (
        <DataQueryStateBanner
          tone={current.meta.degraded_reason ? "warning" : "neutral"}
          message={fmtQueryMeta(current.meta)}
        />
      ) : null}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <div className="lg:col-span-8">
          <Card title="Summary" right={rightHint} className="rounded-xl overflow-hidden">
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <StatTile label="Accepted" value={totals.success} hint="Total accepted events" />
              <StatTile label="Failed password" value={totals.failed} hint="Total failed password events" />
              <StatTile label="Invalid user" value={totals.invalid} hint="Total invalid user events" />
              <StatTile label="Total actions" value={totals.actions} hint="Accepted + failed + invalid" />
              <StatTile label="Unique source IPs" value={totals.uniqueIps} hint="Distinct IPs in the selected window" />
              <StatTile label="Enriched source IPs" value={`${totals.enrichPct}%`} hint={`${totals.enriched}/${totals.uniqueIps} with geo/asn/org`} />
            </div>
          </Card>
        </div>

        <div className="lg:col-span-4">
          <Card title="Filters" className="rounded-xl overflow-hidden">
            <div className="grid grid-cols-1 gap-3">
              <MiniSelect
                label="Agent"
                value={view.agent_id}
                onChange={(v) => setView((prev) => ({ ...prev, agent_id: v }))}
              >
                <option value="">All agents</option>
                {agentOptions.map((a) => (
                  <option key={a.agent_id} value={a.agent_id}>
                    {a.agent_id}
                  </option>
                ))}
              </MiniSelect>

              <MiniSelect
                label="Lookback"
                value={String(view.since_minutes)}
                onChange={(v) => setView((prev) => ({ ...prev, since_minutes: clampInt(v, 1, 60 * 24 * 30, prev.since_minutes) }))}
              >
                <option value={60}>Last 60 minutes</option>
                <option value={6 * 60}>Last 6 hours</option>
                <option value={12 * 60}>Last 12 hours</option>
                <option value={24 * 60}>Last 24 hours</option>
                <option value={3 * 24 * 60}>Last 3 days</option>
                <option value={7 * 24 * 60}>Last 7 days</option>
                <option value={30 * 24 * 60}>Last 30 days</option>
              </MiniSelect>

              <MiniSelect
                label="Rows"
                value={String(view.limit)}
                onChange={(v) => setView((prev) => ({ ...prev, limit: clampInt(v, 1, 500, prev.limit) }))}
              >
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={200}>200</option>
                <option value={500}>500</option>
              </MiniSelect>

              <MiniToggle
                label="Auto refresh"
                checked={view.auto_refresh}
                onChange={(v) => setView((prev) => ({ ...prev, auto_refresh: v }))}
                hint={view.auto_refresh ? `Every ${Math.round(view.refresh_ms / 1000)}s` : "Off"}
              />

              <MiniSelect
                label="Refresh interval"
                value={String(view.refresh_ms)}
                onChange={(v) => setView((prev) => ({ ...prev, refresh_ms: clampInt(v, 2000, 300000, prev.refresh_ms) }))}
              >
                <option value={5000}>5s</option>
                <option value={10000}>10s</option>
                <option value={15000}>15s</option>
                <option value={30000}>30s</option>
                <option value={60000}>60s</option>
              </MiniSelect>
            </div>
          </Card>
        </div>
      </div>

      {loading || !current || (!!error && !current) ? (
        <AsyncState
          loading={loading && !current}
          error={error && !current ? error : null}
          empty={!loading && !error && !current}
          loadingLabel="Loading SSH summary..."
          errorTitle="SSH summary error"
          emptyTitle="No data"
          emptyDescription="No SSH activity found in the selected window."
          onRetry={refresh}
          className="px-0"
        />
      ) : null}

      {current ? (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-3">
          <div className="xl:col-span-8 space-y-3">
            <RecentAuthEventsCard
              title="Recent auth.log events"
              rows={current.recent_auth_events}
              viewAgentId={view.agent_id}
              hint={`Generated: ${fmtWhen(current.generated_at)}`}
              onViewIp={openIpDrawer}
            />

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              <IpTableCard title="Top source IPs" rows={current.most_active_ips} viewAgentId={view.agent_id} variant="info" onViewIp={openIpDrawer} />
              <UserTableCard title="Users attempted" rows={current.users_attempted} viewAgentId={view.agent_id} />
              <IpTableCard title="Successful logins" rows={current.successful_logins} viewAgentId={view.agent_id} variant="low" onViewIp={openIpDrawer} />
              <IpTableCard title="Failed password" rows={current.failed_attempts} viewAgentId={view.agent_id} variant="high" onViewIp={openIpDrawer} />
              <IpTableCard title="Invalid user" rows={current.invalid_user_attempts} viewAgentId={view.agent_id} variant="medium" onViewIp={openIpDrawer} />
            </div>
          </div>

          <div className="xl:col-span-4 space-y-3">
            <RootLoginsCard title="Root logins" rows={current.root_logins} viewAgentId={view.agent_id} onViewIp={openIpDrawer} />
            <SudoRecentCard title="Recent sudo" rows={current.sudo_recent} viewAgentId={view.agent_id} />
          </div>
        </div>
      ) : null}

      <SshIpDrawer
        open={ipDrawerOpen}
        ip={ipDrawerRow}
        viewAgentId={view.agent_id}
        sinceMinutes={view.since_minutes}
        agentNameById={agentNameById}
        onClose={() => setIpDrawerOpen(false)}
      />
    </div>
  );
}


function actionVariant(action?: string | null): Parameters<typeof Badge>[0]["variant"] {
  switch ((action ?? "").trim()) {
    case "accepted":
      return "low";
    case "failed_password":
      return "high";
    case "invalid_user":
      return "medium";
    default:
      return "neutral";
  }
}

function actionLabel(action?: string | null) {
  switch ((action ?? "").trim()) {
    case "accepted":
      return "accepted";
    case "failed_password":
      return "failed password";
    case "invalid_user":
      return "invalid user";
    default:
      return action || "-";
  }
}

function RecentAuthEventsCard({
  title,
  rows,
  viewAgentId,
  hint,
  onViewIp
}: {
  title: string;
  rows: SshAuthEvent[];
  viewAgentId: string;
  hint?: string;
  onViewIp?: (row: SshIpStat) => void;
}) {
  const cols = useMemo(
    () => [
      {
        key: "timestamp",
        title: "When",
        width: 180,
        render: (r: SshAuthEvent) => <span className="font-mono text-xs">{fmtWhen(r.timestamp)}</span>
      },
      {
        key: "action",
        title: "Action",
        width: 150,
        render: (r: SshAuthEvent) => <Badge variant={actionVariant(r.action)}>{actionLabel(r.action)}</Badge>
      },
      {
        key: "src_ip",
        title: "Source",
        width: 210,
        render: (r: SshAuthEvent) => (
          <div className="min-w-0">
            <div className="font-mono truncate">{r.src_ip || "-"}</div>
            <div className="mt-0.5 text-[11px] font-mono text-muted-foreground truncate">{r.agent_id}</div>
          </div>
        )
      },
      {
        key: "username",
        title: "Username",
        width: 140,
        render: (r: SshAuthEvent) => <span className="font-mono">{r.username || "-"}</span>
      },
      {
        key: "meta",
        title: "Geo / ASN",
        render: (r: SshAuthEvent) => {
          const meta = ipMeta(r);
          return (
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                {meta.country ? <Badge variant="info">{meta.country}</Badge> : <Badge variant="neutral">no geo</Badge>}
              </div>
              <div className="mt-1 truncate text-[11px] text-muted-foreground">{meta.org || "-"}</div>
              <div className="mt-0.5 truncate text-[11px] font-mono text-muted-foreground">
                {meta.asn ? `${meta.asn}${meta.asnOrg ? ` • ${meta.asnOrg}` : ""}` : "-"}
              </div>
            </div>
          );
        }
      },
      {
        key: "actions",
        title: "Actions",
        width: 230,
        render: (r: SshAuthEvent) => {
          const search = (r.src_ip || "").trim() || (r.username || "").trim();
          const to = toEventsLink({ agent_id: viewAgentId || undefined, event_type: "ssh_auth", search: search || undefined });
          return (
            <div className="flex items-center gap-2">
              <ActionButton
                title="Open IP profile drawer"
                onClick={() => {
                  const ip = (r.src_ip || "").trim();
                  if (!ip) return;
                  onViewIp?.({
                    src_ip: ip,
                    count: 1,
                    geo_country: r.geo_country,
                    geo_org: r.geo_org,
                    asn: r.asn,
                    asn_org: r.asn_org
                  });
                }}
                disabled={!onViewIp || !(r.src_ip || "").trim()}
              >
                View
              </ActionButton>

              <Link
                to={to}
                className="inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
              >
                Open
              </Link>
            </div>
          );
        }
      }
    ],
    [onViewIp, viewAgentId]
  );

  return (
    <Card title={title} right={hint} className="rounded-xl overflow-hidden">
      {rows.length === 0 ? (
        <EmptyState title="No SSH auth events" hint="No ssh_auth entries matched the selected window." />
      ) : (
        <Table columns={cols} rows={rows} rowKey={(r, i) => `${r.timestamp}-${r.agent_id}-${r.src_ip || "no-ip"}-${i}`} className="text-sm" />
      )}
    </Card>
  );
}

function IpTableCard({
  title,
  rows,
  viewAgentId,
  hint,
  variant = "neutral",
  onViewIp
}: {
  title: string;
  rows: SshIpStat[];
  viewAgentId: string;
  hint?: string;
  variant?: Parameters<typeof Badge>[0]["variant"];
  onViewIp?: (row: SshIpStat) => void;
}) {
  const cols = useMemo(
    () => [
      {
        key: "count",
        title: "Count",
        width: 90,
        className: "font-mono text-right",
        render: (r: SshIpStat) => <span className="font-mono">{r.count}</span>
      },
      {
        key: "src_ip",
        title: "Source IP",
        width: 200,
        render: (r: SshIpStat) => (
          <div className="flex items-center gap-2">
            <span className="font-mono">{r.src_ip}</span>
            {(() => {
              const meta = ipMeta(r);
              if (!meta.country) return null;
              return <Badge variant={variant}>{meta.country}</Badge>;
            })()}
          </div>
        )
      },
      {
        key: "org",
        title: "Org",
        render: (r: SshIpStat) => {
          const meta = ipMeta(r);
          return (
            <div className="min-w-0">
              <div className="truncate">{meta.org || "-"}</div>
              <div className="mt-0.5 text-[11px] text-muted-foreground font-mono truncate">
                {meta.asn ? `${meta.asn}${meta.asnOrg ? ` • ${meta.asnOrg}` : ""}` : "-"}
              </div>
            </div>
          );
        }
      },
      {
        key: "actions",
        title: "Actions",
        width: 240,
        render: (r: SshIpStat) => {
          const to = toEventsLink({ agent_id: viewAgentId || undefined, event_type: "ssh_auth", search: r.src_ip });
          return (
            <div className="flex items-center gap-2">
              <ActionButton
                title="Open IP profile drawer"
                onClick={() => onViewIp?.(r)}
                disabled={!onViewIp}
              >
                View
              </ActionButton>

              <Link
                to={to}
                className="inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
              >
                Open
              </Link>
            </div>
          );
        }
      }
    ],
    [viewAgentId, variant, onViewIp]
  );

  return (
    <Card
      title={title}
      right={hint}
      className="rounded-xl overflow-hidden"
    >
      {rows.length === 0 ? (
        <EmptyState title="No rows" hint="Nothing matched the selected window." />
      ) : (
        <Table columns={cols} rows={rows} rowKey={(r) => r.src_ip} className="text-sm" />
      )}
    </Card>
  );
}

function UserTableCard({ title, rows, viewAgentId }: { title: string; rows: SshUserStat[]; viewAgentId: string }) {
  const cols = useMemo(
    () => [
      {
        key: "count",
        title: "Count",
        width: 90,
        className: "font-mono text-right",
        render: (r: SshUserStat) => <span className="font-mono">{r.count}</span>
      },
      {
        key: "username",
        title: "Username",
        render: (r: SshUserStat) => <span className="font-mono">{r.username}</span>
      },
      {
        key: "actions",
        title: "Actions",
        width: 130,
        render: (r: SshUserStat) => {
          const to = toEventsLink({ agent_id: viewAgentId || undefined, event_type: "ssh_auth", search: r.username });
          return (
            <Link
              to={to}
              className="inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
            >
              Open
            </Link>
          );
        }
      }
    ],
    [viewAgentId]
  );

  return (
    <Card title={title} className="rounded-xl overflow-hidden">
      {rows.length === 0 ? (
        <EmptyState title="No users" hint="No failed/invalid usernames in the selected window." />
      ) : (
        <Table columns={cols} rows={rows} rowKey={(r, i) => `${r.username}-${i}`} className="text-sm" />
      )}
    </Card>
  );
}

function RootLoginsCard({
  title,
  rows,
  viewAgentId,
  onViewIp
}: {
  title: string;
  rows: SshLoginEvent[];
  viewAgentId: string;
  onViewIp?: (row: SshIpStat) => void;
}) {
  const cols = useMemo(
    () => [
      {
        key: "timestamp",
        title: "When",
        width: 180,
        render: (r: SshLoginEvent) => <span className="font-mono text-xs">{fmtWhen(r.timestamp)}</span>
      },
      {
        key: "src_ip",
        title: "IP",
        width: 180,
        render: (r: SshLoginEvent) => <span className="font-mono">{r.src_ip || "-"}</span>
      },
      {
        key: "meta",
        title: "Geo / ASN",
        render: (r: SshLoginEvent) => {
          const country = (r.geo_country ?? "").trim();
          const asn = (r.asn ?? "").trim();
          const org = (r.geo_org ?? "").trim();
          const asnOrg = (r.asn_org ?? "").trim();
          return (
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                {country ? <Badge variant="critical">{country}</Badge> : <Badge variant="neutral">no geo</Badge>}
                <span className="text-xs font-mono text-muted-foreground">{r.agent_id}</span>
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground truncate">
                {org || "-"}
              </div>
              <div className="mt-0.5 text-[11px] text-muted-foreground font-mono truncate">
                {asn ? `${asn}${asnOrg ? ` • ${asnOrg}` : ""}` : "-"}
              </div>
            </div>
          );
        }
      },
      {
        key: "actions",
        title: "Actions",
        width: 240,
        render: (r: SshLoginEvent) => {
          const search = r.src_ip ? r.src_ip : "root";
          const to = toEventsLink({ agent_id: viewAgentId || undefined, event_type: "ssh_auth", search });
          return (
            <div className="flex items-center gap-2">
              <ActionButton
                title="Open IP profile drawer"
                onClick={() => {
                  const ip = (r.src_ip || "").trim();
                  if (!ip) return;
                  onViewIp?.({
                    src_ip: ip,
                    count: 0,
                    geo_country: r.geo_country,
                    geo_org: r.geo_org,
                    asn: r.asn,
                    asn_org: r.asn_org
                  });
                }}
                disabled={!onViewIp || !(r.src_ip || "").trim()}
              >
                View
              </ActionButton>

              <Link
                to={to}
                className="inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
              >
                Open
              </Link>
            </div>
          );
        }
      }
    ],
    [viewAgentId, onViewIp]
  );

  return (
    <Card
      title={title}
      right={rows.length ? "accepted + username=root" : undefined}
      className="rounded-xl overflow-hidden"
    >
      {rows.length === 0 ? (
        <EmptyState title="No root logins" hint="No accepted root logins found." />
      ) : (
        <Table columns={cols} rows={rows} rowKey={(r, i) => `${r.timestamp}-${i}`} className="text-sm" />
      )}
    </Card>
  );
}

function SudoRecentCard({ title, rows, viewAgentId }: { title: string; rows: SudoEventSummary[]; viewAgentId: string }) {
  const cols = useMemo(
    () => [
      {
        key: "timestamp",
        title: "When",
        width: 180,
        render: (r: SudoEventSummary) => <span className="font-mono text-xs">{fmtWhen(r.timestamp)}</span>
      },
      {
        key: "who",
        title: "Who",
        width: 220,
        render: (r: SudoEventSummary) => (
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-mono">{r.username || "-"}</span>
              {r.target_user ? <Badge variant="neutral">as {r.target_user}</Badge> : null}
            </div>
            <div className="mt-1 text-[11px] font-mono text-muted-foreground truncate">{r.agent_id}</div>
          </div>
        )
      },
      {
        key: "command",
        title: "Command",
        render: (r: SudoEventSummary) => (
          <div className="min-w-0">
            <div className="font-mono truncate">{r.command || "-"}</div>
            <div className="mt-0.5 text-[11px] text-muted-foreground font-mono truncate">
              {r.pwd ? `PWD=${r.pwd}` : ""}
              {r.tty ? ` • TTY=${r.tty}` : ""}
            </div>
          </div>
        )
      },
      {
        key: "actions",
        title: "Actions",
        width: 130,
        render: (r: SudoEventSummary) => {
          const search = r.command ? r.command.split(" ")[0] : "sudo";
          const to = toEventsLink({ agent_id: viewAgentId || undefined, event_type: "sudo_cmd", search });
          return (
            <Link
              to={to}
              className="inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
            >
              Open
            </Link>
          );
        }
      }
    ],
    [viewAgentId]
  );

  return (
    <Card title={title} right={rows.length ? "event_type=sudo_cmd" : undefined} className="rounded-xl overflow-hidden">
      {rows.length === 0 ? (
        <EmptyState title="No sudo activity" hint="No sudo commands found in the selected window." />
      ) : (
        <Table columns={cols} rows={rows} rowKey={(r, i) => `${r.timestamp}-${i}`} className="text-sm" />
      )}
    </Card>
  );
}
