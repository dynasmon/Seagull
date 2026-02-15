import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import Drawer from "@/shared/components/Drawer";
import Loading from "@/shared/components/Loading";
import EmptyState from "@/shared/components/EmptyState";
import { Badge } from "@/shared/components/Badge";
import { Table } from "@/shared/components/Table";

import { getRecentEvents } from "@/features/events/api";
import type { NetEvent } from "@/features/events/types";

export type IndicatorKind =
  | "dns_qname"
  | "http_host"
  | "http_method"
  | "tls_sni"
  | "tls_alpn_first"
  | "ja3"
  | "ja4"
  | "ja4_ptype";

export type IndicatorSelection = {
  kind: IndicatorKind;
  value: string;
  count?: number;
};

function ActionButton({
  children,
  onClick,
  title,
  disabled
}: {
  children: ReactNode;
  onClick: () => void;
  title?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      disabled={disabled}
      className={
        "inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20 disabled:opacity-50"
      }
    >
      {children}
    </button>
  );
}

function fmtWhen(iso?: string | null) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

function huntSearch(kind: IndicatorKind, value: string): string {
  // Events page search is a substring match over JSON.stringify(extra).
  // Using a JSON-ish token reduces accidental matches.
  const v = JSON.stringify(String(value));
  switch (kind) {
    case "dns_qname":
      return `"dns_qname":${v}`;
    case "http_host":
      return `"http_host":${v}`;
    case "http_method":
      return `"http_method":${v}`;
    case "tls_sni":
      return `"tls_sni":${v}`;
    case "tls_alpn_first":
      return `"tls_alpn_first":${v}`;
    case "ja3":
      return `"ja3":${v}`;
    case "ja4":
      return `"ja4":${v}`;
    case "ja4_ptype":
      return `"ja4_ptype":${v}`;
    default:
      return String(value);
  }
}

function matches(e: NetEvent, sel: IndicatorSelection): boolean {
  const x: any = e.extra || {};
  const v = sel.value;
  switch (sel.kind) {
    case "dns_qname":
      return String(x.dns_qname || "") === v;
    case "http_host":
      return String(x.http_host || "") === v;
    case "http_method":
      return String(x.http_method || "") === v;
    case "tls_sni":
      return String(x.tls_sni || "") === v;
    case "tls_alpn_first":
      return String(x.tls_alpn_first || "") === v;
    case "ja3":
      return String(x.ja3 || "") === v;
    case "ja4":
      return String(x.ja4 || "") === v;
    case "ja4_ptype":
      return String(x.ja4_ptype || "") === v;
    default:
      return false;
  }
}

function kindLabel(k: IndicatorKind): string {
  switch (k) {
    case "dns_qname":
      return "DNS Query";
    case "http_host":
      return "HTTP Host";
    case "http_method":
      return "HTTP Method";
    case "tls_sni":
      return "TLS SNI";
    case "tls_alpn_first":
      return "TLS ALPN";
    case "ja3":
      return "TLS JA3";
    case "ja4":
      return "TLS JA4";
    case "ja4_ptype":
      return "JA4 PType";
    default:
      return "Indicator";
  }
}

function ptypeBadge(v: string) {
  const x = String(v || "").toLowerCase();
  if (x === "q") return <Badge variant="info">quic</Badge>;
  if (x === "d") return <Badge variant="medium">dtls</Badge>;
  if (x === "t") return <Badge variant="neutral">tls</Badge>;
  return <Badge variant="neutral">unknown</Badge>;
}

export default function NetworkIndicatorDrawer({
  open,
  onClose,
  selection,
  agent_id,
  window_minutes
}: {
  open: boolean;
  onClose: () => void;
  selection: IndicatorSelection | null;
  agent_id: string;
  window_minutes: number;
}) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<NetEvent[]>([]);

  const hunt = useMemo(() => {
    if (!selection) return "";
    return huntSearch(selection.kind, selection.value);
  }, [selection]);

  const title = useMemo(() => {
    if (!selection) return "";
    return `${kindLabel(selection.kind)}: ${selection.value}`;
  }, [selection]);

  const refresh = useCallback(async () => {
    if (!selection) return;
    setLoading(true);
    try {
      // Backend doesn't support arbitrary JSON filters yet.
      // We fetch a bounded window and filter client-side.
      const recents = await getRecentEvents({
        limit: 800,
        agent_id: agent_id || undefined,
        window_minutes
      });
      const filtered = recents.filter((e) => matches(e, selection));
      setEvents(filtered.slice(0, 200));
      setError(null);
    } catch (e: any) {
      setError(e?.message || "Failed to load sample events");
      setEvents([]);
    } finally {
      setLoading(false);
    }
  }, [selection, agent_id, window_minutes]);

  useEffect(() => {
    if (!open) return;
    if (!selection) return;
    refresh();
  }, [open, selection, refresh]);

  const evCols = useMemo(
    () => [
      {
        key: "when",
        title: "Time",
        width: 190,
        render: (e: NetEvent) => <span className="text-xs font-mono">{fmtWhen(e.timestamp)}</span>
      },
      {
        key: "agent",
        title: "Agent",
        width: 140,
        render: (e: NetEvent) => <span className="text-xs">{e.agent_id}</span>
      },
      {
        key: "flow",
        title: "Flow",
        render: (e: NetEvent) => (
          <span className="text-xs font-mono">
            {(e.src_ip || "-") + (e.src_port ? ":" + e.src_port : "")}
            <span className="text-muted-foreground"> → </span>
            {(e.dst_ip || "-") + (e.dst_port ? ":" + e.dst_port : "")}
          </span>
        )
      },
      {
        key: "proto",
        title: "Proto",
        width: 90,
        render: (e: NetEvent) => <span className="text-xs font-mono uppercase">{e.proto || "-"}</span>
      },
      {
        key: "etype",
        title: "Type",
        width: 110,
        render: (e: NetEvent) => <span className="text-xs font-mono">{e.event_type}</span>
      }
    ],
    []
  );

  const actionBar = useMemo(() => {
    if (!selection) return null;

    const q = new URLSearchParams();
    if (agent_id) q.set("agent_id", agent_id);
    q.set("search", hunt);

    const eventsHref = `/events?${q.toString()}`;

    return (
      <div className="flex flex-wrap items-center gap-2">
        <Link
          to={eventsHref}
          className={
            "inline-flex items-center justify-center h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs font-mono uppercase tracking-widest hover:bg-muted/20"
          }
        >
          Open in Events
        </Link>

        <ActionButton
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(hunt);
            } catch {
              // no-op
            }
          }}
          title="Copy the search token used for Events filtering"
        >
          Copy hunt token
        </ActionButton>

        {selection.kind === "ja4_ptype" ? (
          <div className="ml-auto">{ptypeBadge(selection.value)}</div>
        ) : null}
      </div>
    );
  }, [selection, agent_id, hunt]);

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={title || "Indicator"}
      description={
        selection
          ? `Sample events in the last ${window_minutes} minutes. Filtered client-side for now; a dedicated server-side hunt endpoint can be added later.`
          : undefined
      }
      widthClassName="w-[860px]"
    >
      {actionBar}

      <div className="mt-4 grid grid-cols-1 gap-4">
        {loading ? <Loading /> : null}
        {error ? (
          <EmptyState title="Unable to load samples" description={error} />
        ) : null}

        {!loading && !error ? (
          <>
            <div className="rounded-lg border border-border/60 bg-background/40 px-3 py-2">
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Indicator</div>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <Badge variant="neutral">{selection ? kindLabel(selection.kind) : "-"}</Badge>
                <span className="text-sm font-mono break-all">{selection?.value ?? "-"}</span>
                {typeof selection?.count === "number" ? (
                  <span className="ml-auto text-xs text-muted-foreground">
                    Top count: <span className="font-mono text-foreground">{selection.count}</span>
                  </span>
                ) : null}
              </div>
            </div>

            <div>
              <div className="mb-2 flex items-center justify-between">
                <div className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Matching events</div>
                <div className="text-xs text-muted-foreground">
                  Showing <span className="font-mono text-foreground">{events.length}</span> samples
                </div>
              </div>

              {events.length === 0 ? (
                <EmptyState
                  title="No matching samples"
                  description="No recent events matched this indicator within the requested window."
                />
              ) : (
                <Table
                  columns={evCols as any}
                  rows={events}
                  rowKey={(e) => String(e.id)}
                  className="text-sm"
                />
              )}
            </div>
          </>
        ) : null}
      </div>
    </Drawer>
  );
}
