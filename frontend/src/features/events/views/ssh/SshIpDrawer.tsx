import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { Button } from "@/shared/components/Button";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import Loading from "@/shared/components/Loading";
import { Badge } from "@/shared/components/Badge";
import { Table } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";
import { ipContextFromFlatFields, resolveIpClassification } from "@/shared/lib/ipClassification";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationFactCard,
  InvestigationMetaStrip,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
  copyTextToClipboard,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";

import { huntEvents } from "@/features/events/api";
import EventDrawer from "@/features/events/components/EventDrawer";
import type { NetEvent, QueryProvenanceMeta } from "@/features/events/types";

import type { SshIpStat } from "./types";

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
  const srcIpContext = ipContextFromFlatFields(ip, "src");

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
  const [copied, setCopied] = useState<null | "ok" | "fail">(null);

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
    setCopied(null);
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
        render: (r: NetEvent) => <span className="font-mono text-xs">{formatInvestigationTimestamp(r.timestamp)}</span>
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
            <Button variant="subtle" size="sm"
              onClick={() => {
                setSelectedEvent(r);
                setEventDrawerOpen(true);
              }}
              title="Open full event drawer"
            >
              View
            </Button>
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
        headerLabel="SSH intel"
        onClose={onClose}
        widthClassName="w-[980px]"
      >
        {!srcIp ? (
          <EmptyState title="No IP selected" hint="Pick an IP from the tables to open its profile." />
        ) : (
          <InvestigationShell>
            <InvestigationMetaStrip
              items={[
                { label: "Source IP", value: <IpAddressPill ip={srcIp} ipContext={srcIpContext} compact /> },
                { label: "Lookback", value: `${sinceMinutes}m` },
                { label: "Scoped agent", value: viewAgentId || "all agents" },
                { label: "Country", value: meta.country || "unknown", variant: meta.country ? "info" : "neutral" },
                { label: "ASN", value: meta.asn || "-" },
                { label: "Org", value: meta.org || meta.asnOrg || "-" },
                { label: "Events loaded", value: String(events.length) },
                { label: "Last seen", value: formatInvestigationTimestamp(counts.lastSeen) },
              ]}
            />

            <InvestigationActionBar>
              <InvestigationActionButton
                onClick={async () => {
                  const ok = await copyTextToClipboard(srcIp);
                  setCopied(ok ? "ok" : "fail");
                  window.setTimeout(() => setCopied(null), 1200);
                }}
              >
                {copied === "ok" ? "Copied" : copied === "fail" ? "Copy failed" : "Copy IP"}
              </InvestigationActionButton>
              <InvestigationActionButton onClick={() => void load()} disabled={loading}>
                {loading ? "Refreshing..." : "Refresh"}
              </InvestigationActionButton>
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
            </InvestigationActionBar>

            <InvestigationSection title="SSH source overview" subtitle="Recent authentication activity, enrichment, and top identities for this source.">
              {queryMeta ? (
                <div
                  className={cx(
                    "mb-4 rounded-lg border px-3 py-2 text-[11px] font-mono",
                    queryMeta.degraded_reason ? "border-warning/40 bg-warning/10 text-warning" : "border-border/60 bg-background/30 text-muted-foreground"
                  )}
                >
                  source {queryMeta.source}
                  {typeof queryMeta.source_freshness_seconds === "number" ? ` · freshness ${queryMeta.source_freshness_seconds}s` : ""}
                  {queryMeta.cache_hit ? " · cache" : ""}
                  {queryMeta.degraded_reason ? ` · ${queryMeta.degraded_reason}` : ""}
                </div>
              ) : null}

              <InvestigationSummaryGrid className="xl:grid-cols-4">
                <InvestigationFactCard label="Accepted" value={String(counts.accepted)} mono />
                <InvestigationFactCard label="Failed password" value={String(counts.failed)} mono />
                <InvestigationFactCard label="Invalid user" value={String(counts.invalid)} mono />
                <InvestigationFactCard label="Other actions" value={String(counts.other)} mono />
                <InvestigationFactCard label="Total actions" value={String(counts.total)} mono />
                <InvestigationFactCard label="IP scope" value={resolveIpClassification(srcIp, srcIpContext).label} />
                <InvestigationFactCard label="Geo country" value={meta.country || "-"} />
                <InvestigationFactCard label="ASN" value={meta.asn || "-"} mono />
                <InvestigationFactCard label="Last seen" value={formatInvestigationTimestamp(counts.lastSeen)} mono />
              </InvestigationSummaryGrid>

              {counts.topUsers.length ? (
                <div className="mt-4">
                  <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">
                    Top usernames
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
            </InvestigationSection>

            <InvestigationSection title="Recent SSH events" subtitle="Server-side hunt results filtered by source IP.">
              {loading && events.length === 0 ? <Loading label="Loading recent events..." /> : null}
              {!loading && events.length === 0 ? (
                <EmptyState
                  title="No SSH events"
                  hint="No events matched this source IP in the selected lookback window."
                />
              ) : null}
              {events.length ? <Table columns={cols as any} rows={events} rowKey={(r) => String(r.id)} className="text-sm" /> : null}
              {error ? <div className="mt-3 text-[12px] text-danger">{error}</div> : null}
            </InvestigationSection>
          </InvestigationShell>
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
