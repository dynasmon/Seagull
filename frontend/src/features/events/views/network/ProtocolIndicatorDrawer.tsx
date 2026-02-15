import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";

import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Badge } from "@/shared/components/Badge";
import { Table, TBody, TD, TH, THead, TR } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";

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
        const msg = typeof e?.message === "string" ? e.message : "Failed to load samples";
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
                <span className="text-[11px] font-mono text-muted-foreground">value</span>
                <span className="text-[12px] font-mono text-foreground break-all">{selection.value}</span>
                {typeof selection.count === "number" ? (
                  <span className="ml-2 text-[11px] font-mono text-muted-foreground">~{selection.count} hits</span>
                ) : null}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <Link
                  to={eventsLink}
                  className={cx(
                    "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                    "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                    "hover:bg-muted/15 hover:text-foreground",
                    "focus:outline-none focus:ring-2 focus:ring-primary/30"
                  )}
                >
                  Open in Events
                </Link>
              </div>
            </div>

            <div className="rounded-lg border border-border/60 bg-background/40 p-4">
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
                Matching samples
              </div>

              <div className="mt-3">
                {loading ? <Loading label="Loading samples..." /> : null}
                {error ? <div className="text-sm text-red-300">{error}</div> : null}

                {!loading && !error && items.length === 0 ? (
                  <EmptyState title="No matches" description="No events matched this indicator in the selected window." />
                ) : null}

                {!loading && !error && items.length > 0 ? (
                  <div className="overflow-auto">
                    <Table>
                      <THead>
                        <TR>
                          <TH>When</TH>
                          <TH>Agent</TH>
                          <TH>Type</TH>
                          <TH>Src</TH>
                          <TH>Dst</TH>
                          <TH>Proto</TH>
                        </TR>
                      </THead>
                      <TBody>
                        {items.map((ev) => {
                          const agentLabel = agentNameById?.[ev.agent_id] || ev.agent_id;
                          const ts = new Date(ev.timestamp);
                          const when = Number.isNaN(ts.getTime()) ? ev.timestamp : fmtDateTime(ts);

                          return (
                            <TR
                              key={ev.id}
                              className={cx(
                                "cursor-pointer",
                                "hover:bg-muted/10"
                              )}
                              onClick={() => {
                                setEventDrawerEvent(ev);
                                setEventDrawerOpen(true);
                              }}
                            >
                              <TD className="font-mono text-[12px]">{when}</TD>
                              <TD className="text-[12px]">{agentLabel}</TD>
                              <TD className="font-mono text-[12px]">{ev.event_type}</TD>
                              <TD className="font-mono text-[12px]">{fmtAddr(ev.src_ip, ev.src_port)}</TD>
                              <TD className="font-mono text-[12px]">{fmtAddr(ev.dst_ip, ev.dst_port)}</TD>
                              <TD className="font-mono text-[12px]">{ev.proto || "-"}</TD>
                            </TR>
                          );
                        })}
                      </TBody>
                    </Table>
                  </div>
                ) : null}
              </div>
            </div>

            <div className="rounded-lg border border-border/60 bg-background/40 p-4">
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
                Notes
              </div>
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
