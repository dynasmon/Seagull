import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import AsyncState from "@/shared/components/AsyncState";
import EmptyState from "@/shared/components/EmptyState";
import { Card } from "@/shared/components/Card";
import { Table } from "@/shared/components/Table";
import { Badge } from "@/shared/components/Badge";
import { getErrorMessage } from "@/shared/lib/errors";
import { clampInt } from "@/shared/lib/filters";

import { useAgentsCatalog } from "@/app/providers";

import { getSshSummary } from "./api";
import type { SshIpStat, SshLoginEvent, SshSummaryResponse, SshUserStat, SudoEventSummary } from "./types";
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
  limit: 20,
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
      limit: clampInt(parsed.limit, 1, 200, DEFAULTS.limit),
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

function ipMeta(r: SshIpStat) {
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
    const limit = clampInt(searchParams.get("limit"), 1, 200, viewRef.current.limit);

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
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const r = await getSshSummary({
        agent_id: viewRef.current.agent_id,
        since_minutes: viewRef.current.since_minutes,
        limit: viewRef.current.limit
      });
      setData(r);
      setError(null);
      setLastUpdatedAt(Date.now());
    } catch (e: any) {
      const msg = getErrorMessage(e, "Failed to load SSH summary");
      setError(msg);
      // keep last known good data (no flicker)
      if (dataRef.current) setData(dataRef.current);
    } finally {
      setLoading(false);
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
    const sum = (rows?: Array<{ count: number }>) => (rows ?? []).reduce((acc, r) => acc + (Number(r.count) || 0), 0);
    const success = sum(d?.successful_logins);
    const failed = sum(d?.failed_attempts);
    const invalid = sum(d?.invalid_user_attempts);
    const actions = success + failed + invalid;

    const uniqueIps = (d?.most_active_ips ?? []).length;
    const enriched = (d?.most_active_ips ?? []).filter((r) => Boolean((r.geo_country ?? "").trim() || (r.geo_org ?? "").trim() || (r.asn ?? "").trim())).length;
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
    parts.push(`Top-N: ${view.limit}`);
    if (lastUpdatedAt) parts.push(`Updated: ${fmtAgo(Date.now() - lastUpdatedAt)}`);
    return parts.join(" • ");
  }, [view.since_minutes, view.limit, lastUpdatedAt]);

  const headerRight = (
    <div className="flex items-center gap-2">
      {loading ? <Badge variant="info">Refreshing…</Badge> : null}
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
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-semibold tracking-tight">SSH Insights</div>
        {headerRight}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <div className="lg:col-span-8">
          <Card title="Summary" right={rightHint} className="rounded-xl overflow-hidden">
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <StatTile label="Accepted" value={totals.success} hint="Total accepted events" />
              <StatTile label="Failed password" value={totals.failed} hint="Total failed password events" />
              <StatTile label="Invalid user" value={totals.invalid} hint="Total invalid user events" />
              <StatTile label="Total actions" value={totals.actions} hint="Accepted + failed + invalid" />
              <StatTile label="Top active IPs" value={totals.uniqueIps} hint="Unique IPs in Top-N" />
              <StatTile label="Enriched" value={`${totals.enrichPct}%`} hint={`${totals.enriched}/${totals.uniqueIps} with geo/asn/org`} />
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
                label="Top-N"
                value={String(view.limit)}
                onChange={(v) => setView((prev) => ({ ...prev, limit: clampInt(v, 1, 200, prev.limit) }))}
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={200}>200</option>
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
          <div className="xl:col-span-7 space-y-3">
            <IpTableCard
              title="Most active IPs"
              rows={current.most_active_ips}
              viewAgentId={view.agent_id}
              hint={`Generated: ${fmtWhen(current.generated_at)}`}
              variant="info"
              onViewIp={openIpDrawer}
            />

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              <IpTableCard title="Successful logins" rows={current.successful_logins} viewAgentId={view.agent_id} variant="low" onViewIp={openIpDrawer} />
              <IpTableCard title="Failed password" rows={current.failed_attempts} viewAgentId={view.agent_id} variant="high" onViewIp={openIpDrawer} />
              <IpTableCard title="Invalid user" rows={current.invalid_user_attempts} viewAgentId={view.agent_id} variant="medium" onViewIp={openIpDrawer} />
              <UserTableCard title="Users attempted" rows={current.users_attempted} viewAgentId={view.agent_id} />
            </div>
          </div>

          <div className="xl:col-span-5 space-y-3">
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
