import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";

import AsyncState from "@/shared/components/AsyncState";
import Drawer from "@/shared/components/Drawer";
import { Badge } from "@/shared/components/Badge";
import { Table, type Column } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";
import { getErrorMessage } from "@/shared/lib/errors";

import type { NetEvent } from "../../types";
import { fmtDateTime } from "../../lib/aggregates";
import EventDrawer from "../../components/EventDrawer";

import { getProtocolIntelSamples } from "./api";
import type { ProtocolIntelIndicatorKind } from "./types";

function fmtAddr(ip?: string | null, port?: number | null) {
  if (!ip) return "-";
  if (typeof port === "number") return `${ip}:${port}`;
  return ip;
}

export type ProtocolIndicatorSelection = {
  kind: ProtocolIntelIndicatorKind;
  value: string;
  label: string;
  hint?: string;
  count?: number;
};

export default function ProtocolIndicatorDrawer({
  open,
  selection,
  onClose,
  agentId,
  sinceMinutes,
  agentNameById
}: {
  open: boolean;
  selection: ProtocolIndicatorSelection | null;
  onClose: () => void;
  agentId?: string;
  sinceMinutes: number;
  agentNameById?: Record<string, string>;
}) {
  const reqSeq = useRef(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [items, setItems] = useState<NetEvent[]>([]);

  const [eventDrawerOpen, setEventDrawerOpen] = useState(false);
  const [eventDrawerEvent, setEventDrawerEvent] = useState<NetEvent | null>(null);

  const title = selection ? selection.label : "Indicator";

  const sampleColumns = useMemo<Array<Column<NetEvent>>>(() => {
    return [
      {
        key: "when",
        title: "WHEN",
        width: 190,
        render: (ev) => {
          const ts = new Date(ev.timestamp);
          const when = Number.isNaN(ts.getTime()) ? ev.timestamp : fmtDateTime(ts);
          return <span className="font-mono text-[12px]">{when}</span>;
        }
      },
      {
        key: "agent",
        title: "AGENT",
        width: 160,
        render: (ev) => <span className="text-[12px]">{agentNameById?.[ev.agent_id] || ev.agent_id}</span>
      },
      {
        key: "type",
        title: "TYPE",
        width: 150,
        render: (ev) => <span className="font-mono text-[12px]">{ev.event_type}</span>
      },
      {
        key: "src",
        title: "SRC",
        width: 170,
        render: (ev) => <span className="font-mono text-[12px]">{fmtAddr(ev.src_ip, ev.src_port)}</span>
      },
      {
        key: "dst",
        title: "DST",
        width: 170,
        render: (ev) => <span className="font-mono text-[12px]">{fmtAddr(ev.dst_ip, ev.dst_port)}</span>
      },
      {
        key: "proto",
        title: "PROTO",
        width: 90,
        render: (ev) => <span className="font-mono text-[12px]">{ev.proto || "-"}</span>
      },
      {
        key: "open",
        title: "",
        width: 96,
        className: "text-right",
        render: (ev) => (
          <button
            type="button"
            onClick={() => {
              setEventDrawerEvent(ev);
              setEventDrawerOpen(true);
            }}
            className={cx(
              "inline-flex items-center rounded-md border border-border/60 bg-background/40",
              "px-2 py-1 text-xs font-medium text-muted-foreground",
              "hover:bg-muted/15 hover:text-foreground",
              "focus:outline-none focus:ring-2 focus:ring-primary/30"
            )}
          >
            Open
          </button>
        )
      }
    ];
  }, [agentNameById]);

  const eventsLink = useMemo(() => {
    if (!selection) return "/events";
    const sp = new URLSearchParams();
    if (agentId) sp.set("agent_id", agentId);
    sp.set("search", selection.value);
    return `/events?${sp.toString()}`;
  }, [selection, agentId]);

  useEffect(() => {
    if (!open || !selection) return;

    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);

    getProtocolIntelSamples({
      kind: selection.kind,
      value: selection.value,
      since_minutes: sinceMinutes,
      limit: 80,
      agent_id: agentId
    })
      .then((r) => {
        if (reqSeq.current !== mySeq) return;
        setItems(Array.isArray(r) ? r : []);
      })
      .catch((e: any) => {
        if (reqSeq.current !== mySeq) return;
        const msg = getErrorMessage(e, "Failed to load samples");
        setError(msg);
      })
      .finally(() => {
        if (reqSeq.current !== mySeq) return;
        setLoading(false);
      });
  }, [open, selection?.kind, selection?.value, agentId, sinceMinutes, selection]);

  return (
    <>
      <Drawer
        open={open}
        title={title}
        description={selection?.hint}
        onClose={() => {
          setItems([]);
          setError(null);
          setEventDrawerEvent(null);
          setEventDrawerOpen(false);
          onClose();
        }}
        widthClassName="w-[980px]"
      >
        {!selection ? (
          <div className="text-sm text-muted-foreground">No indicator selected.</div>
        ) : (
          <div className="space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <Badge>{selection.kind}</Badge>
              <span className="text-xs text-muted-foreground">Value</span>
              <span className="text-xs font-mono text-foreground break-all">{selection.value}</span>
                {typeof selection.count === "number" ? (
                <span className="ml-2 text-xs text-muted-foreground">~{selection.count} hits</span>
                ) : null}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <Link
                  to={eventsLink}
                  className={cx(
                    "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                    "px-3 py-2 text-xs font-medium text-muted-foreground",
                    "hover:bg-muted/15 hover:text-foreground",
                    "focus:outline-none focus:ring-2 focus:ring-primary/30"
                  )}
                >
                  Open in Events
                </Link>
              </div>
            </div>

            <div className="rounded-lg border border-border/60 bg-background/40 p-4">
              <div className="text-sm font-semibold tracking-tight">Matching samples</div>

              <div className="mt-3">
                {loading || error || items.length === 0 ? (
                  <AsyncState
                    loading={loading}
                    error={error}
                    empty={!loading && !error && items.length === 0}
                    emptyTitle="No matches"
                    emptyDescription="No events matched this indicator in the selected window."
                    loadingLabel="Loading samples..."
                    errorTitle="Samples error"
                    onRetry={() => {
                      if (!selection) return;
                      const mySeq = ++reqSeq.current;
                      setLoading(true);
                      setError(null);
                      getProtocolIntelSamples({
                        kind: selection.kind,
                        value: selection.value,
                        since_minutes: sinceMinutes,
                        limit: 80,
                        agent_id: agentId
                      })
                        .then((r) => {
                          if (reqSeq.current !== mySeq) return;
                          setItems(Array.isArray(r) ? r : []);
                        })
                        .catch((e: unknown) => {
                          if (reqSeq.current !== mySeq) return;
                          setError(getErrorMessage(e, "Failed to load samples"));
                        })
                        .finally(() => {
                          if (reqSeq.current !== mySeq) return;
                          setLoading(false);
                        });
                    }}
                    className="px-0"
                  />
                ) : null}

                {!loading && !error && items.length > 0 ? (
                  <div className="overflow-auto">
                    {/* Table.rowKey expects a string; id can be numeric depending on backend schema */}
                    <Table columns={sampleColumns} rows={items} rowKey={(r) => String((r as any).id)} />
                  </div>
                ) : null}
              </div>
            </div>

            <div className="rounded-lg border border-border/60 bg-background/40 p-4">
              <div className="text-sm font-semibold tracking-tight">Notes</div>
              <div className="mt-3 text-sm text-muted-foreground leading-relaxed">
                These samples are scoped to your current lookback window and (optionally) agent selection.
                If you expect results but see none, verify that the <span className="font-mono">netwatch-proto-intel</span> worker
                is running and that agents are shipping the evidence fields (DNS/HTTP payloads or TLS/DTLS/QUIC handshakes).
              </div>
            </div>
          </div>
        )}
      </Drawer>

      <EventDrawer
        open={eventDrawerOpen}
        event={eventDrawerEvent}
        agentNameById={agentNameById}
        onClose={() => {
          setEventDrawerOpen(false);
          setEventDrawerEvent(null);
        }}
      />
    </>
  );
}
