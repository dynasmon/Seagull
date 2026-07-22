import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import AsyncState from "@/shared/components/AsyncState";
import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { MetricCard } from "@/shared/components/MetricCard";
import { DataQueryStateBanner, DataStatsStrip, DataViewToolbar } from "@/shared/components/DataView";
import { Card } from "@/shared/components/Card";
import { SelectInput } from "@/shared/components/SelectInput";
import { StatusPill } from "@/shared/components/StatusPill";
import { Table, type Column } from "@/shared/components/Table";
import { ToggleSwitch } from "@/shared/components/ToggleSwitch";
import { Badge } from "@/shared/components/Badge";
import { getErrorMessage } from "@/shared/lib/errors";
import { clampInt } from "@/shared/lib/filters";
import { ipContextFromFlatFields, resolveIpClassification } from "@/shared/lib/ipClassification";
import { useLiveRefresh, usePortalRealtimeSubscription } from "@/shared/realtime";

import { useAgentsCatalog } from "@/app/providers";

import { EventsLinkButton } from "../../components/EventsLinkButton";
import { getSshSummary } from "./api";
import { SshActionBadge } from "./SshActionBadge";
import { SshGeoCell } from "./SshGeoCell";
import type { SshAuthEvent, SshIpStat, SshLoginEvent, SshSummaryResponse, SshUserStat, SudoEventSummary } from "./types";
import SshIpDrawer from "./SshIpDrawer";


type ViewCfg = {
  agent_id: string;
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
  refresh_ms: 15000,
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
      auto_refresh: Boolean(parsed.auto_refresh),
    };
  } catch {
    return DEFAULTS;
  }
}

function persistView(v: ViewCfg) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(v));
  } catch {
  }
}

function fmtWhen(iso?: string | null) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

function fmtDuration(minutes: number) {
  const m = Math.max(0, Math.round(minutes));
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h`;
  const d = Math.round(h / 24);
  return `${d}d`;
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

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{children}</div>
  );
}

function MiniSelect({
  label,
  value,
  onChange,
  children,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  children: ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1">
      <FieldLabel>{label}</FieldLabel>
      <SelectInput value={value} onChange={(e) => onChange(e.target.value)} className="font-mono text-[11.5px]">
        {children}
      </SelectInput>
    </label>
  );
}

function MiniToggle({
  label,
  checked,
  onChange,
  hint,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  hint?: string;
}) {
  return (
    <div className="rounded-md border border-border bg-surface-2/40 px-3 py-2">
      <ToggleSwitch label={label} checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {hint ? <div className="mt-1 text-[11px] text-muted-foreground">{hint}</div> : null}
    </div>
  );
}

function sshIpContext(r: SshIpStat | SshAuthEvent | SshLoginEvent) {
  return ipContextFromFlatFields(r, "src");
}

function ipFallbackLabel(r: SshIpStat | SshAuthEvent | SshLoginEvent) {
  return resolveIpClassification(r.src_ip, sshIpContext(r)).label;
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
  const didBootRef = useRef(false);

  const refresh = useCallback(async () => {
    const mySeq = ++reqSeq.current;
    const hasData = Boolean(dataRef.current);
    if (hasData) setRefreshing(true);
    else setLoading(true);
    try {
      const r = await getSshSummary({
        agent_id: viewRef.current.agent_id,
        since_minutes: viewRef.current.since_minutes,
        limit: viewRef.current.limit,
        widen_if_empty: true,
      });
      if (reqSeq.current !== mySeq) return;
      setData(r);
      setError(null);
      setLastUpdatedAt(Date.now());
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      const msg = getErrorMessage(e, "Failed to load SSH summary");
      setError(msg);
      if (dataRef.current) setData(dataRef.current);
    } finally {
      if (reqSeq.current !== mySeq) return;
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (!didBootRef.current) {
      didBootRef.current = true;
      if (view.auto_refresh) return;
    }
    void refresh();
  }, [refresh, view.agent_id, view.limit, view.since_minutes, view.auto_refresh]);

  const live = useLiveRefresh({
    enabled: view.auto_refresh,
    profile: "operational",
    refresh: async ({ signal }) => {
      const mySeq = ++reqSeq.current;
      const hasData = Boolean(dataRef.current);
      if (hasData) setRefreshing(true);
      else setLoading(true);
      try {
        const r = await getSshSummary(
          {
            agent_id: viewRef.current.agent_id,
            since_minutes: viewRef.current.since_minutes,
            limit: viewRef.current.limit,
            widen_if_empty: true,
          },
          { signal },
        );
        if (reqSeq.current !== mySeq) return;
        setData(r);
        setError(null);
        setLastUpdatedAt(Date.now());
      } catch (e: any) {
        if (reqSeq.current !== mySeq) return;
        const msg = getErrorMessage(e, "Failed to load SSH summary");
        setError(msg);
        if (dataRef.current) setData(dataRef.current);
      } finally {
        if (reqSeq.current !== mySeq) return;
        setLoading(false);
        setRefreshing(false);
      }
    },
  });

  usePortalRealtimeSubscription("ui.events.invalidate", (event) => {
    const eventAgentId = String(event.payload?.agent_id || "").trim();
    if (view.agent_id && eventAgentId && eventAgentId !== view.agent_id) return;
    const domains = Array.isArray(event.payload?.domains) ? event.payload.domains.map((value) => String(value)) : [];
    if (domains.length > 0 && !domains.includes("ssh")) return;
    live.invalidate();
  });

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

  const effectiveSinceMinutes = data?.effective_since_minutes ?? null;
  const shownSinceMinutes = effectiveSinceMinutes ?? view.since_minutes;

  const rightHint = useMemo(() => {
    const parts: string[] = [];
    parts.push(`Lookback: ${fmtDuration(shownSinceMinutes)}${effectiveSinceMinutes ? " (widened)" : ""}`);
    parts.push(`Rows: ${view.limit}`);
    if (data?.meta?.source) parts.push(`Source: ${data.meta.source}`);
    if (lastUpdatedAt) parts.push(`Updated: ${fmtAgo(Date.now() - lastUpdatedAt)}`);
    return parts.join(" · ");
  }, [shownSinceMinutes, effectiveSinceMinutes, view.limit, lastUpdatedAt, data?.meta?.source]);

  const headerRight = (
    <div className="flex items-center gap-2">
      {refreshing ? <StatusPill variant="info" withDot>Refreshing</StatusPill> : null}
      {error ? <StatusPill variant="danger" withDot>Error</StatusPill> : null}
      <Button variant="subtle" size="md" onClick={() => void refresh()}>
        Refresh
      </Button>
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
          { label: "Accepted", value: totals.success, tone: totals.success > 0 ? "success" : "default" },
          { label: "Failed password", value: totals.failed, tone: totals.failed > 0 ? "warning" : "default" },
          { label: "Invalid user", value: totals.invalid, tone: totals.invalid > 0 ? "warning" : "default" },
          { label: "Total actions", value: totals.actions },
          { label: "Unique source IPs", value: totals.uniqueIps },
          { label: "Enriched source IPs", value: `${totals.enrichPct}%`, hint: `${totals.enriched}/${totals.uniqueIps}` },
          { label: "Scope", value: view.agent_id || "all agents", hint: `Lookback ${fmtDuration(shownSinceMinutes)}` },
          { label: "Rows", value: view.limit, hint: view.auto_refresh ? `${Math.round(live.state.profile.fallbackMs / 1000)}s shared fallback` : "Manual refresh" },
        ]}
      />

      {effectiveSinceMinutes ? (
        <InlineAlert tone="info" className="text-xs">
          No SSH activity in the selected {fmtDuration(view.since_minutes)} window. Showing the most recent SSH activity from the last {fmtDuration(effectiveSinceMinutes)}.
        </InlineAlert>
      ) : null}

      {current?.meta ? (
        <DataQueryStateBanner
          tone={current.meta.degraded_reason ? "warning" : "neutral"}
          message={fmtQueryMeta(current.meta)}
        />
      ) : null}

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
        <div className="lg:col-span-8">
          <Card title="Summary" right={rightHint}>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
              <MetricCard size="sm" title="Accepted" value={totals.success} helper="Total accepted events" tone={totals.success > 0 ? "success" : "default"} />
              <MetricCard size="sm" title="Failed password" value={totals.failed} helper="Failed password events" tone={totals.failed > 0 ? "warning" : "default"} />
              <MetricCard size="sm" title="Invalid user" value={totals.invalid} helper="Invalid user events" tone={totals.invalid > 0 ? "warning" : "default"} />
              <MetricCard size="sm" title="Total actions" value={totals.actions} helper="Accepted + failed + invalid" />
              <MetricCard size="sm" title="Unique source IPs" value={totals.uniqueIps} helper="Distinct IPs in this window" />
              <MetricCard size="sm" title="Enriched IPs" value={`${totals.enrichPct}%`} helper={`${totals.enriched}/${totals.uniqueIps} with geo/asn`} />
            </div>
          </Card>
        </div>

        <div className="lg:col-span-4">
          <Card title="Filters">
            <div className="grid grid-cols-1 gap-3">
              <MiniSelect label="Agent" value={view.agent_id} onChange={(v) => setView((prev) => ({ ...prev, agent_id: v }))}>
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
                onChange={(v) =>
                  setView((prev) => ({ ...prev, since_minutes: clampInt(v, 1, 60 * 24 * 30, prev.since_minutes) }))
                }
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
                hint={view.auto_refresh ? "Uses the shared operational live cadence." : "Off"}
              />

              <div className="rounded-md border border-border bg-surface-2/50 px-3 py-2">
                <FieldLabel>Refresh cadence</FieldLabel>
                <div className="mt-1 font-mono text-[12px] text-muted-foreground">
                  {view.auto_refresh ? `${Math.round(live.state.profile.fallbackMs / 1000)}s shared fallback` : "Manual only"}
                </div>
              </div>
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
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
          <div className="space-y-3 xl:col-span-8">
            <RecentAuthEventsCard
              title="Recent auth.log events"
              rows={current.recent_auth_events}
              viewAgentId={view.agent_id}
              hint={`Generated: ${fmtWhen(current.generated_at)}`}
              onViewIp={openIpDrawer}
            />

            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              <IpTableCard title="Top source IPs" rows={current.most_active_ips} viewAgentId={view.agent_id} countryVariant="info" onViewIp={openIpDrawer} />
              <UserTableCard title="Users attempted" rows={current.users_attempted} viewAgentId={view.agent_id} />
              <IpTableCard title="Successful logins" rows={current.successful_logins} viewAgentId={view.agent_id} countryVariant="low" onViewIp={openIpDrawer} />
              <IpTableCard title="Failed password" rows={current.failed_attempts} viewAgentId={view.agent_id} countryVariant="high" onViewIp={openIpDrawer} />
              <IpTableCard title="Invalid user" rows={current.invalid_user_attempts} viewAgentId={view.agent_id} countryVariant="medium" onViewIp={openIpDrawer} />
            </div>
          </div>

          <div className="space-y-3 xl:col-span-4">
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

function RecentAuthEventsCard({
  title,
  rows,
  viewAgentId,
  hint,
  onViewIp,
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
        width: 140,
        render: (r: SshAuthEvent) => <span className="font-mono text-xs">{fmtWhen(r.timestamp)}</span>,
      },
      {
        key: "action",
        title: "Action",
        width: 132,
        render: (r: SshAuthEvent) => <SshActionBadge action={r.action} />,
      },
      {
        key: "src_ip",
        title: "Source / Geo",
        render: (r: SshAuthEvent) => {
          const country = (r.geo_country || "").trim();
          const org = (r.geo_org || "").trim();
          const asn = (r.asn || "").trim();
          const asnLine = asn ? `${r.asn}${r.asn_org ? ` • ${r.asn_org}` : ""}` : "";
          return (
            <div className="min-w-0 space-y-0.5">
              <IpAddressPill ip={r.src_ip} ipContext={sshIpContext(r)} compact />
              <div className="flex min-w-0 items-center gap-1.5">
                <Badge variant={country ? "info" : "neutral"}>{country || ipFallbackLabel(r)}</Badge>
                {org ? <span className="min-w-0 truncate text-[11px] text-muted-foreground" title={org}>{org}</span> : null}
              </div>
              {asnLine ? <div className="truncate font-mono text-[11px] text-muted-foreground" title={asnLine}>{asnLine}</div> : null}
              <div className="truncate font-mono text-[11px] text-muted-foreground" title={r.agent_id}>{r.agent_id}</div>
            </div>
          );
        },
      },
      {
        key: "username",
        title: "Username",
        width: 80,
        render: (r: SshAuthEvent) => <span className="block truncate font-mono">{r.username || "-"}</span>,
      },
      {
        key: "actions",
        title: "Actions",
        width: 124,
        render: (r: SshAuthEvent) => {
          const search = (r.src_ip || "").trim() || (r.username || "").trim();
          const to = toEventsLink({ agent_id: viewAgentId || undefined, event_type: "ssh_auth", search: search || undefined });
          return (
            <div className="flex items-center gap-2">
              <Button
                variant="subtle"
                size="sm"
                minWidth={0}
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
                    asn_org: r.asn_org,
                    src_ip_scope: r.src_ip_scope,
                    src_ip_label: r.src_ip_label,
                    src_is_internal: r.src_is_internal,
                    src_is_public: r.src_is_public,
                  });
                }}
                disabled={!onViewIp || !(r.src_ip || "").trim()}
              >
                View
              </Button>

              <EventsLinkButton to={to}>Open</EventsLinkButton>
            </div>
          );
        },
      },
    ],
    [onViewIp, viewAgentId],
  );

  return (
    <Card title={title} right={hint}>
      {rows.length === 0 ? (
        <EmptyState title="No SSH auth events" hint="No ssh_auth entries matched the selected window." />
      ) : (
        <Table columns={cols} rows={rows} rowKey={(r, i) => `${r.timestamp}-${r.agent_id}-${r.src_ip || "no-ip"}-${i}`} className="text-sm" layout="fixed" />
      )}
    </Card>
  );
}

function IpTableCard({
  title,
  rows,
  viewAgentId,
  hint,
  countryVariant = "neutral",
  onViewIp,
}: {
  title: string;
  rows: SshIpStat[];
  viewAgentId: string;
  hint?: string;
  countryVariant?: Parameters<typeof Badge>[0]["variant"];
  onViewIp?: (row: SshIpStat) => void;
}) {
  const cols = useMemo<Array<Column<SshIpStat>>>(
    () => [
      {
        key: "count",
        title: "Count",
        width: 52,
        align: "right",
        className: "font-mono",
        render: (r: SshIpStat) => <span className="font-mono">{r.count}</span>,
      },
      {
        key: "src_ip",
        title: "Source IP / Org",
        render: (r: SshIpStat) => {
          const org = (r.geo_org || "").trim();
          const asn = (r.asn || "").trim();
          const asnLine = asn ? `${r.asn}${r.asn_org ? ` • ${r.asn_org}` : ""}` : "";
          return (
            <div className="min-w-0">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <IpAddressPill ip={r.src_ip} ipContext={sshIpContext(r)} compact />
                {r.geo_country ? <Badge variant={countryVariant}>{r.geo_country}</Badge> : null}
              </div>
              {org ? <div className="mt-0.5 truncate text-[11px] text-muted-foreground" title={org}>{org}</div> : null}
              {asnLine ? <div className="truncate font-mono text-[11px] text-muted-foreground" title={asnLine}>{asnLine}</div> : null}
            </div>
          );
        },
      },
      {
        key: "actions",
        title: "Actions",
        width: 124,
        render: (r: SshIpStat) => {
          const to = toEventsLink({ agent_id: viewAgentId || undefined, event_type: "ssh_auth", search: r.src_ip });
          return (
            <div className="flex items-center gap-2">
              <Button
                variant="subtle"
                size="sm"
                minWidth={0}
                title="Open IP profile drawer"
                onClick={() => onViewIp?.(r)}
                disabled={!onViewIp}
              >
                View
              </Button>
              <EventsLinkButton to={to}>Open</EventsLinkButton>
            </div>
          );
        },
      },
    ],
    [viewAgentId, countryVariant, onViewIp],
  );

  return (
    <Card title={title} right={hint}>
      {rows.length === 0 ? (
        <EmptyState title="No rows" hint="Nothing matched the selected window." />
      ) : (
        <Table columns={cols} rows={rows} rowKey={(r) => r.src_ip} className="text-sm" layout="fixed" />
      )}
    </Card>
  );
}

function UserTableCard({ title, rows, viewAgentId }: { title: string; rows: SshUserStat[]; viewAgentId: string }) {
  const cols = useMemo<Array<Column<SshUserStat>>>(
    () => [
      {
        key: "count",
        title: "Count",
        width: 64,
        align: "right",
        className: "font-mono",
        render: (r: SshUserStat) => <span className="font-mono">{r.count}</span>,
      },
      {
        key: "username",
        title: "Username",
        render: (r: SshUserStat) => <span className="block truncate font-mono" title={r.username}>{r.username}</span>,
      },
      {
        key: "actions",
        title: "Actions",
        width: 92,
        align: "right",
        render: (r: SshUserStat) => {
          const to = toEventsLink({ agent_id: viewAgentId || undefined, event_type: "ssh_auth", search: r.username });
          return <EventsLinkButton to={to}>Open</EventsLinkButton>;
        },
      },
    ],
    [viewAgentId],
  );

  return (
    <Card title={title}>
      {rows.length === 0 ? (
        <EmptyState title="No users" hint="No failed/invalid usernames in the selected window." />
      ) : (
        <Table columns={cols} rows={rows} rowKey={(r, i) => `${r.username}-${i}`} className="text-sm" layout="fixed" />
      )}
    </Card>
  );
}

function RootLoginsCard({
  title,
  rows,
  viewAgentId,
  onViewIp,
}: {
  title: string;
  rows: SshLoginEvent[];
  viewAgentId: string;
  onViewIp?: (row: SshIpStat) => void;
}) {
  const cols = useMemo(
    () => [
      {
        key: "login",
        title: "Login",
        render: (r: SshLoginEvent) => (
          <div className="min-w-0 space-y-1">
            <div className="font-mono text-xs text-muted-foreground">{fmtWhen(r.timestamp)}</div>
            <IpAddressPill ip={r.src_ip} ipContext={sshIpContext(r)} compact />
            <SshGeoCell row={r} fallbackLabel={ipFallbackLabel(r)} countryVariant="critical" />
            <div className="truncate text-[11px] font-mono text-muted-foreground" title={r.agent_id}>agent: {r.agent_id}</div>
          </div>
        ),
      },
      {
        key: "actions",
        title: "Actions",
        width: 124,
        render: (r: SshLoginEvent) => {
          const search = r.src_ip ? r.src_ip : "root";
          const to = toEventsLink({ agent_id: viewAgentId || undefined, event_type: "ssh_auth", search });
          return (
            <div className="flex items-center gap-2">
              <Button
                variant="subtle"
                size="sm"
                minWidth={0}
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
                    asn_org: r.asn_org,
                    src_ip_scope: r.src_ip_scope,
                    src_ip_label: r.src_ip_label,
                    src_is_internal: r.src_is_internal,
                    src_is_public: r.src_is_public,
                  });
                }}
                disabled={!onViewIp || !(r.src_ip || "").trim()}
              >
                View
              </Button>
              <EventsLinkButton to={to}>Open</EventsLinkButton>
            </div>
          );
        },
      },
    ],
    [viewAgentId, onViewIp],
  );

  return (
    <Card title={title} right={rows.length ? "accepted + username=root" : undefined}>
      {rows.length === 0 ? (
        <EmptyState title="No root logins" hint="No accepted root logins found." />
      ) : (
        <Table columns={cols} rows={rows} rowKey={(r, i) => `${r.timestamp}-${i}`} className="text-sm" layout="fixed" />
      )}
    </Card>
  );
}

function SudoRecentCard({ title, rows, viewAgentId }: { title: string; rows: SudoEventSummary[]; viewAgentId: string }) {
  const cols = useMemo<Array<Column<SudoEventSummary>>>(
    () => [
      {
        key: "who",
        title: "Who",
        render: (r: SudoEventSummary) => (
          <div className="min-w-0 space-y-1">
            <div className="flex min-w-0 flex-wrap items-center gap-1.5">
              <span className="break-all font-mono text-[12px]">{r.username || "-"}</span>
              {r.target_user ? <Badge variant="neutral">as {r.target_user}</Badge> : null}
            </div>
            <div className="break-all font-mono text-[11px] text-muted-foreground">{fmtWhen(r.timestamp)}</div>
            <div className="break-all font-mono text-[11px] text-muted-foreground">{r.agent_id}</div>
          </div>
        ),
      },
      {
        key: "command",
        title: "Command",
        render: (r: SudoEventSummary) => (
          <div className="min-w-0 space-y-1">
            <div className="break-all font-mono text-[12px]">{r.command || "-"}</div>
            {r.pwd ? <div className="break-all font-mono text-[11px] text-muted-foreground">PWD={r.pwd}</div> : null}
            {r.tty ? <div className="break-all font-mono text-[11px] text-muted-foreground">TTY={r.tty}</div> : null}
          </div>
        ),
      },
      {
        key: "actions",
        title: "",
        width: 84,
        align: "right",
        render: (r: SudoEventSummary) => {
          const search = r.command ? r.command.split(" ")[0] : "sudo";
          const to = toEventsLink({ agent_id: viewAgentId || undefined, event_type: "sudo_cmd", search });
          return <EventsLinkButton to={to}>Open</EventsLinkButton>;
        },
      },
    ],
    [viewAgentId],
  );

  return (
    <Card title={title} right={rows.length ? "event_type=sudo_cmd" : undefined}>
      {rows.length === 0 ? (
        <EmptyState title="No sudo activity" hint="No sudo commands found in the selected window." />
      ) : (
        <div className="max-h-[520px] overflow-y-auto">
          <Table columns={cols} rows={rows} rowKey={(r, i) => `${r.timestamp}-${i}`} className="text-sm" compact layout="fixed" />
        </div>
      )}
    </Card>
  );
}
