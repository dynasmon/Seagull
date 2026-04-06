import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";

import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Badge } from "@/shared/components/Badge";
import { Table } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";

import { huntEvents } from "@/features/events/api";
import EventDrawer from "@/features/events/components/EventDrawer";
import type { NetEvent, QueryProvenanceMeta } from "@/features/events/types";

import type { SshIpStat } from "./types";

function fmtWhen(iso?: string | null) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

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
      className={cx(
        "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
        "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
        "hover:bg-muted/15 hover:text-foreground",
        "focus:outline-none focus:ring-2 focus:ring-primary/30",
        disabled && "opacity-60 cursor-not-allowed hover:bg-background/40 hover:text-muted-foreground"
      )}
    >
      {children}
    </button>
  );
}

function safeCopy(text: string) {
  const t = (text || "").trim();
  if (!t) return;
  navigator.clipboard?.writeText(t).catch(() => {
    /* ignore */
  });
}

function toEventsLink(params: { agent_id?: string; event_type?: string; search?: string; event_id?: number }): string {
  const q = new URLSearchParams();
  if (params.agent_id) q.set("agent_id", params.agent_id);
  if (params.event_type) q.set("event_type", params.event_type);
  if (params.search) q.set("search", params.search);
  if (typeof params.event_id === "number") q.set("event_id", String(params.event_id));
  const s = q.toString();
  return s ? `/events?${s}` : "/events";
}

export default function SshIpDrawer({
  open,
  ip,
  viewAgentId,
  sinceMinutes,
  agentNameById,
  onClose
}: {
  open: boolean;
  ip: SshIpStat | null;
  viewAgentId: string;
  sinceMinutes: number;
  agentNameById?: Record<string, string>;
  onClose: () => void;
}) {
  const srcIp = (ip?.src_ip || "").trim();

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [queryMeta, setQueryMeta] = useState<QueryProvenanceMeta | null>(null);

  // No-flicker behavior on intermittent API failures.
  const eventsRef = useRef<NetEvent[]>([]);
  useEffect(() => {
    eventsRef.current = events;
  }, [events]);

  const [eventDrawerOpen, setEventDrawerOpen] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<NetEvent | null>(null);

  const load = useCallback(async () => {
    if (!srcIp) return;
    setLoading(true);
    try {
      const payload = await huntEvents({
        page_size: 200,
        agent_id: viewAgentId || undefined,
        event_type: "ssh_auth",
        since_minutes: sinceMinutes,
        search: srcIp,
      });
      setEvents(Array.isArray(payload?.items) ? payload.items : []);
      setQueryMeta(payload?.meta ?? null);
      setError(null);
    } catch (e: any) {
      setError(e?.message || "Failed to load SSH events for this source IP");
      if (eventsRef.current.length) setEvents(eventsRef.current);
    } finally {
      setLoading(false);
    }
  }, [srcIp, viewAgentId, sinceMinutes]);

  useEffect(() => {
    if (!open) return;
    // reset event drawer when switching IPs
    setSelectedEvent(null);
    setEventDrawerOpen(false);
    setEvents([]);
    setQueryMeta(null);
    setError(null);
    eventsRef.current = [];
    load();
  }, [open, srcIp, load]);

  const meta = useMemo(() => {
    const country = (ip?.geo_country || "").trim();
    const org = (ip?.geo_org || "").trim();
    const asn = (ip?.asn || "").trim();
    const asnOrg = (ip?.asn_org || "").trim();
    return {
      country: country || null,
      org: org || null,
      asn: asn || null,
      asnOrg: asnOrg || null
    };
  }, [ip]);

  const counts = useMemo(() => {
    let accepted = 0;
    let failed = 0;
    let invalid = 0;
    let other = 0;
    const users: Record<string, number> = {};
    let lastSeen: string | null = null;

    for (const e of events) {
      const action = String(e.extra?.action || "").trim();
      if (action === "accepted") accepted += 1;
      else if (action === "failed_password") failed += 1;
      else if (action === "invalid_user") invalid += 1;
      else other += 1;

      const u = String(e.extra?.username || "").trim();
      if (u) users[u] = (users[u] || 0) + 1;

      if (!lastSeen) lastSeen = e.timestamp;
      else {
        // timestamps are ISO strings; compare as Date for safety
        const a = new Date(lastSeen);
        const b = new Date(e.timestamp);
        if (!Number.isNaN(a.getTime()) && !Number.isNaN(b.getTime()) && b.getTime() > a.getTime()) lastSeen = e.timestamp;
      }
    }

    const topUsers = Object.entries(users)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([username, count]) => ({ username, count }));

    return {
      accepted,
      failed,
      invalid,
      other,
      total: accepted + failed + invalid + other,
      lastSeen,
      topUsers
    };
  }, [events]);

  const title = srcIp ? `Source IP · ${srcIp}` : "Source IP";
  const description = srcIp
    ? `Lookback: ${sinceMinutes}m · Server-side SSH hunt filtered by source IP`
    : undefined;

  const cols = useMemo(
    () => [
      {
        key: "timestamp",
        title: "When",
        width: 180,
        render: (r: NetEvent) => <span className="font-mono text-xs">{fmtWhen(r.timestamp)}</span>
      },
      {
        key: "action",
        title: "Action",
        width: 160,
        render: (r: NetEvent) => {
          const a = String(r.extra?.action || "-");
          const v = a === "accepted" ? "low" : a === "failed_password" ? "high" : a === "invalid_user" ? "medium" : "neutral";
          return <Badge variant={v as any}>{a}</Badge>;
        }
      },
      {
        key: "username",
        title: "Username",
        width: 180,
        render: (r: NetEvent) => <span className="font-mono">{String(r.extra?.username || "-")}</span>
      },
      {
        key: "agent_id",
        title: "Agent",
        width: 220,
        render: (r: NetEvent) => {
          const name = agentNameById?.[r.agent_id];
          const label = name && name !== r.agent_id ? `${name} (${r.agent_id})` : r.agent_id;
          return <span className="font-mono text-xs text-muted-foreground">{label}</span>;
        }
      },
      {
        key: "actions",
        title: "Actions",
        width: 230,
        render: (r: NetEvent) => (
          <div className="flex items-center gap-2">
            <ActionButton
              onClick={() => {
                setSelectedEvent(r);
                setEventDrawerOpen(true);
              }}
              title="Open full event drawer"
            >
              View
            </ActionButton>
            <Link
              to={toEventsLink({ agent_id: viewAgentId || undefined, event_type: "ssh_auth", search: srcIp, event_id: r.id })}
              className={cx(
                "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground",
                "focus:outline-none focus:ring-2 focus:ring-primary/30"
              )}
              title="Open in Events with this event selected"
            >
              Open
            </Link>
          </div>
        )
      }
    ],
    [agentNameById, srcIp, viewAgentId]
  );

  return (
    <>
      <Drawer
        open={open}
        title={title}
        description={description}
        onClose={onClose}
        widthClassName="w-[980px]"
      >
        {!srcIp ? (
          <EmptyState title="No IP selected" hint="Pick an IP from the tables to open its profile." />
        ) : (
          <div className="space-y-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[12px] font-mono text-muted-foreground">src_ip</span>
                  <span className="text-base font-semibold font-mono truncate">{srcIp}</span>
                  {meta.country ? <Badge variant="info">{meta.country}</Badge> : <Badge variant="neutral">no geo</Badge>}
                  {meta.asn ? <Badge variant="neutral">{meta.asn}</Badge> : null}
                </div>
                <div className="mt-2 text-sm text-muted-foreground">
                  <div className="truncate">{meta.org || "-"}</div>
                  <div className="mt-0.5 text-[11px] font-mono truncate">{meta.asnOrg || ""}</div>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <ActionButton onClick={() => safeCopy(srcIp)} title="Copy IP to clipboard">
                  Copy IP
                </ActionButton>
                <Link
                  to={toEventsLink({ agent_id: viewAgentId || undefined, event_type: "ssh_auth", search: srcIp })}
                  className={cx(
                    "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                    "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                    "hover:bg-muted/15 hover:text-foreground",
                    "focus:outline-none focus:ring-2 focus:ring-primary/30"
                  )}
                >
                  Open in Events
                </Link>
                <ActionButton onClick={load} disabled={loading} title="Reload recent events">
                  {loading ? "Refreshing…" : "Refresh"}
                </ActionButton>
              </div>
            </div>

            {queryMeta ? (
              <div
                className={cx(
                  "rounded-lg border px-3 py-2 text-[11px] font-mono",
                  queryMeta.degraded_reason ? "border-amber-500/40 bg-amber-500/10 text-amber-200" : "border-border/60 bg-background/40 text-muted-foreground"
                )}
              >
                source {queryMeta.source}
                {typeof queryMeta.source_freshness_seconds === "number" ? ` · freshness ${queryMeta.source_freshness_seconds}s` : ""}
                {queryMeta.cache_hit ? " · cache" : ""}
                {queryMeta.degraded_reason ? ` · ${queryMeta.degraded_reason}` : ""}
              </div>
            ) : null}

            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              <div className="rounded-lg border border-border/60 bg-background/40 px-3 py-2">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">accepted</div>
                <div className="mt-1 text-xl font-semibold tracking-tight">{counts.accepted}</div>
              </div>
              <div className="rounded-lg border border-border/60 bg-background/40 px-3 py-2">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">failed</div>
                <div className="mt-1 text-xl font-semibold tracking-tight">{counts.failed}</div>
              </div>
              <div className="rounded-lg border border-border/60 bg-background/40 px-3 py-2">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">invalid</div>
                <div className="mt-1 text-xl font-semibold tracking-tight">{counts.invalid}</div>
              </div>
              <div className="rounded-lg border border-border/60 bg-background/40 px-3 py-2">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">other</div>
                <div className="mt-1 text-xl font-semibold tracking-tight">{counts.other}</div>
              </div>
              <div className="rounded-lg border border-border/60 bg-background/40 px-3 py-2">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">last seen</div>
                <div className="mt-1 text-sm font-mono text-foreground truncate">{fmtWhen(counts.lastSeen)}</div>
              </div>
            </div>

            {counts.topUsers.length ? (
              <div className="rounded-xl border border-border/60 bg-background/60 p-4">
                <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
                  Top usernames (from recent events)
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {counts.topUsers.map((u) => (
                    <span
                      key={u.username}
                      className="inline-flex items-center gap-2 rounded-full border border-border/60 bg-background/40 px-3 py-1"
                    >
                      <span className="text-xs font-mono">{u.username}</span>
                      <span className="text-[11px] font-mono text-muted-foreground">{u.count}</span>
                    </span>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="rounded-xl border border-border/60 bg-background/70 overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-border/60 bg-muted/10">
                <div className="text-sm font-semibold tracking-tight truncate">Recent SSH events</div>
                <div className="text-xs text-muted-foreground truncate">
                  {error ? <span className="text-red-400">{error}</span> : `${events.length} rows`}
                </div>
              </div>
              <div className="p-4">
                {loading && events.length === 0 ? <Loading label="Loading recent events…" /> : null}
                {!loading && events.length === 0 ? (
                  <EmptyState
                    title="No SSH events"
                    hint="No events matched this source IP in the selected lookback window."
                  />
                ) : null}
                {events.length ? <Table columns={cols as any} rows={events} rowKey={(r) => String(r.id)} className="text-sm" /> : null}
              </div>
            </div>
          </div>
        )}
      </Drawer>

      <EventDrawer
        open={eventDrawerOpen}
        event={selectedEvent}
        agentNameById={agentNameById}
        onClose={() => {
          setEventDrawerOpen(false);
          setSelectedEvent(null);
        }}
      />
    </>
  );
}
