import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { EuiPanel } from "@elastic/eui";

import { useAgentsCatalog } from "@/app/providers";
import { getRecentEvents } from "@/features/events/api";
import type { NetEvent } from "@/features/events/types";
import { getAgent } from "@/features/agents/api";
import type { AgentDetail, AgentPublic } from "@/features/agents/types";
import { getInventoryHistory, getInventoryLatest } from "@/features/inventory/api";
import type { InventorySnapshotOut } from "@/features/inventory/types";
import { Card } from "@/shared/components/Card";
import { DebouncedSearchInput } from "@/shared/components/DataView";
import EmptyState from "@/shared/components/EmptyState";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { JsonBlock } from "@/shared/components/JsonBlock";
import Loading from "@/shared/components/Loading";
import { Table } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";
import { getFlowIpContext } from "@/shared/lib/ipClassification";
import { useLiveRefresh } from "@/shared/realtime";
import { MetricCard } from "@/shared/components/MetricCard";
import InternalRefreshToolbar from "@/features/internal/components/InternalRefreshToolbar";

function pretty(v: any) {
  try {
    return JSON.stringify(v ?? {}, null, 2);
  } catch {
    return "{}";
  }
}

function fmtDateTime(iso?: string | null) {
  if (!iso) return "-";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const d = new Date(t);
  return d.toLocaleString();
}

function isOnline(lastSeenAt?: string | null): boolean {
  if (!lastSeenAt) return false;
  const t = new Date(lastSeenAt).getTime();
  if (!Number.isFinite(t)) return false;
  return Date.now() - t <= 5 * 60_000;
}

function statusOfAgent(a?: AgentPublic | null): "online" | "offline" | "disabled" {
  if (!a) return "offline";
  if (a.is_revoked) return "disabled";
  return isOnline(a.last_seen_at) ? "online" : "offline";
}

function StatusDot({ status }: { status: "online" | "offline" | "disabled" }) {
  const klass =
    status === "online"
      ? "bg-success"
      : status === "disabled"
        ? "bg-muted-foreground"
        : "bg-warning";
  return <span className={cx("inline-block h-2.5 w-2.5 rounded-full", klass)} />;
}

export default function InternalAgentsInspectorView() {
  const { agents } = useAgentsCatalog();
  const [sp, setSp] = useSearchParams();

  const [query, setQuery] = useState("");
  const [agent, setAgent] = useState<AgentDetail | null>(null);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [latestInventory, setLatestInventory] = useState<InventorySnapshotOut | null>(null);
  const [history, setHistory] = useState<InventorySnapshotOut[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedAgentId = (sp.get("agent_id") || "").trim();
  const inFlight = useRef(false);

  const filteredAgents = useMemo(() => {
    const q = query.trim().toLowerCase();
    const rows = [...agents].sort((a, b) => (a.display_name || a.agent_id).localeCompare(b.display_name || b.agent_id));
    if (!q) return rows;
    return rows.filter((a) => [a.display_name, a.agent_id, ...(a.tags || [])].filter(Boolean).join(" ").toLowerCase().includes(q));
  }, [agents, query]);

  const selectedAgentRow = useMemo(
    () => agents.find((a) => a.agent_id === selectedAgentId) || null,
    [agents, selectedAgentId]
  );

  const refresh = useCallback(async () => {
    if (!selectedAgentId) return;
    if (inFlight.current) return;

    inFlight.current = true;
    setBusy(true);
    try {
      const [a, ev, latest, hist] = await Promise.all([
        getAgent(selectedAgentId),
        getRecentEvents({ agent_id: selectedAgentId, limit: 80 }),
        getInventoryLatest(selectedAgentId).catch(() => null),
        getInventoryHistory(selectedAgentId, { limit: 12 }).catch(() => [])
      ]);

      setAgent(a);
      setEvents(ev);
      setLatestInventory(latest);
      setHistory(hist);
      setError(null);
    } catch (e: any) {
      setError(e?.message || "Failed to load technical agent inspection");
    } finally {
      setBusy(false);
      inFlight.current = false;
    }
  }, [selectedAgentId]);
  const live = useLiveRefresh({
    enabled: Boolean(selectedAgentId),
    profile: "admin",
    refresh,
  });

  useEffect(() => {
    if (!selectedAgentId) {
      setAgent(null);
      setEvents([]);
      setLatestInventory(null);
      setHistory([]);
      setError(null);
      return;
    }
    live.invalidate("dependency", { immediate: true, supersede: true });
  }, [live.invalidate, selectedAgentId]);

  return (
    <div className="space-y-6 min-w-0">
      <Card title="Agents" right={`${filteredAgents.length}/${agents.length}`}>
        <div className="space-y-3">
          <DebouncedSearchInput
            value={query}
            onChange={setQuery}
            placeholder="Search by name, id, tags..."
            className="h-10 text-sm"
          />

          <div className="max-h-[240px] overflow-y-auto pr-1">
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
              {filteredAgents.length === 0 ? (
                <div className="sm:col-span-2 xl:col-span-3">
                  <EmptyState title="No agents" hint="Try another filter." />
                </div>
              ) : (
                filteredAgents.map((a) => {
                  const status = statusOfAgent(a);
                  const active = a.agent_id === selectedAgentId;
                  return (
                    <EuiPanel
                      key={a.agent_id}
                      onClick={() => {
                        const next = new URLSearchParams(sp);
                        next.set("agent_id", a.agent_id);
                        setSp(next, { replace: true });
                      }}
                      hasBorder
                      hasShadow={false}
                      paddingSize="s"
                      borderRadius="m"
                      color={active ? "primary" : "plain"}
                      className="w-full text-left"
                      aria-pressed={active}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="min-w-0 flex items-center gap-2">
                          <StatusDot status={status} />
                          <div className="truncate font-mono text-sm">{a.display_name || a.agent_id}</div>
                        </div>
                        <div className="text-[10px] font-mono text-muted-foreground uppercase">{status}</div>
                      </div>
                      <div className="mt-1 text-[10px] font-mono text-muted-foreground truncate">{a.agent_id}</div>
                    </EuiPanel>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </Card>

      {!selectedAgentId ? (
        <EmptyState title="Select an agent" hint="Choose an agent above to open technical inspection." />
      ) : busy && !agent ? (
        <Loading label="Loading technical inspection..." />
      ) : (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold">{agent?.display_name || selectedAgentId}</h2>
              <div className="text-[11px] font-mono text-muted-foreground">{selectedAgentId}</div>
            </div>
            <div className="min-w-[320px] grow max-w-[540px]">
              <InternalRefreshToolbar
                lastUpdatedLabel={live.state.lastUpdatedAt ? live.state.lastUpdatedAt.toLocaleString() : "-"}
                onRefresh={live.refreshNow}
                busy={busy}
              />
            </div>
          </div>

          {error ? <div className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">{error}</div> : null}

          <Card title="Runtime Snapshot">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <MetricCard title="Status" value={statusOfAgent(selectedAgentRow)} />
              <MetricCard title="Last seen" value={fmtDateTime(selectedAgentRow?.last_seen_at)} />
              <MetricCard title="Uptime sec" value={agent?.metrics?.uptime_seconds ?? "-"} />
              <MetricCard title="Events sample" value={events.length} />
            </div>
          </Card>

          <div className="grid gap-6 xl:grid-cols-2">
            <Card title="Heartbeat / Modules">
              <JsonBlock value={pretty({ status: agent?.metrics?.status, modules: agent?.metrics?.modules, metrics: agent?.metrics?.metrics })} maxHeight="320px" />
            </Card>

            <Card title="Metadata">
              <JsonBlock value={pretty(agent?.metadata || {})} maxHeight="320px" />
            </Card>
          </div>

          <div className="grid gap-6 xl:grid-cols-2">
            <Card title="Config (raw JSON)">
              <JsonBlock value={pretty(agent?.config || {})} maxHeight="320px" />
            </Card>

            <Card title="Latest Inventory Snapshot">
              {!latestInventory ? (
                <EmptyState title="No inventory" hint="No latest inventory snapshot for this agent." />
              ) : (
                <div className="grid gap-3 sm:grid-cols-2">
                  <MetricCard title="Collected at" value={fmtDateTime(latestInventory.collected_at)} />
                  <MetricCard title="Packages" value={latestInventory.packages_count ?? (latestInventory.packages || []).length} />
                  <MetricCard title="Manager" value={latestInventory.manager || "-"} />
                  <MetricCard title="Schema" value={latestInventory.schema_version || "-"} />
                </div>
              )}
            </Card>
          </div>

          <Card title="Inventory History" right={`Last ${history.length}`}>
            {history.length === 0 ? (
              <EmptyState title="No history" hint="No inventory history available." />
            ) : (
              <Table
                rows={history}
                rowKey={(r, i) => `${r.id || i}`}
                columns={[
                  { key: "collected_at", title: "Collected", className: "font-mono text-xs", render: (r) => fmtDateTime(r.collected_at) },
                  {
                    key: "packages_count",
                    title: "Packages",
                    className: "font-mono text-xs text-right",
                    render: (r) => Number(r.packages_count ?? (r.packages || []).length).toLocaleString("en-US")
                  },
                  { key: "manager", title: "Manager", className: "font-mono text-xs" }
                ]}
              />
            )}
          </Card>

          <Card title="Recent Events" right={`Top ${events.length}`}>
            {events.length === 0 ? (
              <EmptyState title="No events" hint="No recent events for this agent." />
            ) : (
              <div className="max-h-[360px] overflow-y-auto">
                <Table
                  rows={events}
                  rowKey={(row, idx) => `${row.id || "na"}-${row.timestamp || "na"}-${row.agent_id || "na"}-${idx}`}
                  columns={[
                    { key: "timestamp", title: "Timestamp", className: "font-mono text-xs", render: (r) => fmtDateTime(r.timestamp) },
                    { key: "event_type", title: "Type", className: "font-mono text-xs" },
                    { key: "src_ip", title: "Source", className: "font-mono text-xs", render: (r) => <IpAddressPill ip={r.src_ip} ipContext={getFlowIpContext(r.extra?.ip_context, "src")} compact /> },
                    { key: "dst_ip", title: "Destination", className: "font-mono text-xs", render: (r) => <IpAddressPill ip={r.dst_ip} ipContext={getFlowIpContext(r.extra?.ip_context, "dst")} compact /> },
                    { key: "dst_port", title: "Port", className: "font-mono text-xs text-right", render: (r) => r.dst_port ?? "-" }
                  ]}
                />
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
