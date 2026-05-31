import { useEffect, useMemo, useRef, useState } from "react";

import { Button } from "@/shared/components/Button";
import Drawer from "@/shared/components/Drawer";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { Table, type Column } from "@/shared/components/Table";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationFactCard,
  InvestigationListItem,
  InvestigationMetaStrip,
  InvestigationSection,
  InvestigationShell,
  InvestigationStateBlock,
  InvestigationSummaryGrid,
  copyTextToClipboard,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";
import { getErrorMessage } from "@/shared/lib/errors";
import { getFlowIpContext } from "@/shared/lib/ipClassification";

import type { NetEvent } from "../../types";
import { fmtDateTime } from "../../lib/aggregates";
import EventDetailsPanel from "../../components/EventDetailsPanel";
import EventDrawer from "../../components/EventDrawer";
import PinToWorkspaceDrawer from "@/features/investigations/PinToWorkspaceDrawer";
import { pinProtocolIntelEventToWorkspace } from "@/features/investigations/api";

import { getProtocolIntelSamples } from "./api";
import type { ProtocolIntelIndicatorKind } from "./types";

function ipEndpoint(ev: NetEvent, side: "src" | "dst") {
  const ip = side === "src" ? ev.src_ip : ev.dst_ip;
  const port = side === "src" ? ev.src_port : ev.dst_port;
  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
      <IpAddressPill ip={ip} ipContext={getFlowIpContext(ev.extra?.ip_context, side)} compact />
      {typeof port === "number" ? <span className="text-muted-foreground">:{port}</span> : null}
    </span>
  );
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
  focusEventId,
  onClose,
  agentId,
  sinceMinutes,
  agentNameById,
}: {
  open: boolean;
  selection: ProtocolIndicatorSelection | null;
  focusEventId?: number | null;
  onClose: () => void;
  agentId?: string;
  sinceMinutes: number;
  agentNameById?: Record<string, string>;
}) {
  const reqSeq = useRef(0);
  const focusHandledRef = useRef<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [items, setItems] = useState<NetEvent[]>([]);
  const [selectedSampleId, setSelectedSampleId] = useState<number | null>(null);
  const [copied, setCopied] = useState<null | "ok" | "fail">(null);

  const [eventDrawerOpen, setEventDrawerOpen] = useState(false);
  const [eventDrawerEvent, setEventDrawerEvent] = useState<NetEvent | null>(null);
  const [pinEvent, setPinEvent] = useState<NetEvent | null>(null);

  const title = selection ? selection.label : "Indicator";

  const eventsLink = useMemo(() => {
    if (!selection) return "/events";
    const sp = new URLSearchParams();
    if (agentId) sp.set("agent_id", agentId);
    sp.set("search", selection.value);
    return `/events?${sp.toString()}`;
  }, [selection, agentId]);

  const selectedSample = useMemo(() => {
    if (selectedSampleId === null) return null;
    return items.find((x) => Number(x.id) === Number(selectedSampleId)) || null;
  }, [items, selectedSampleId]);

  const sampleColumns = useMemo<Array<Column<NetEvent>>>(() => {
    return [
      {
        key: "when",
        title: "WHEN",
        width: 160,
        render: (ev) => {
          const ts = new Date(ev.timestamp);
          const when = Number.isNaN(ts.getTime()) ? ev.timestamp : fmtDateTime(ts);
          return <span className="font-mono text-[12px]">{when}</span>;
        },
      },
      {
        key: "agent",
        title: "AGENT",
        width: 140,
        render: (ev) => <span className="text-[12px]">{agentNameById?.[ev.agent_id] || ev.agent_id}</span>,
      },
      {
        key: "type",
        title: "TYPE",
        width: 120,
        render: (ev) => <span className="font-mono text-[12px]">{ev.event_type}</span>,
      },
      {
        key: "src",
        title: "SRC",
        width: 150,
        render: (ev) => <span className="font-mono text-[12px]">{ipEndpoint(ev, "src")}</span>,
      },
      {
        key: "dst",
        title: "DST",
        width: 150,
        render: (ev) => <span className="font-mono text-[12px]">{ipEndpoint(ev, "dst")}</span>,
      },
      {
        key: "open",
        title: "",
        className: "text-right",
        render: (ev) => (
          <Button
            variant="subtle"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              setSelectedSampleId(ev.id);
              setEventDrawerEvent(ev);
              setEventDrawerOpen(true);
            }}
          >
            Full view
          </Button>
        ),
      },
      {
        key: "pin",
        title: "",
        className: "text-right",
        render: (ev) => (
          <Button variant="subtle" size="sm" onClick={(e) => { e.stopPropagation(); setPinEvent(ev); }}>
            Pin
          </Button>
        ),
      },
    ];
  }, [agentNameById]);

  useEffect(() => {
    if (!open || !selection) return;

    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);
    setCopied(null);

    getProtocolIntelSamples({
      kind: selection.kind,
      value: selection.value,
      since_minutes: sinceMinutes,
      limit: 80,
      agent_id: agentId,
    })
      .then((r) => {
        if (reqSeq.current !== mySeq) return;
        const next = Array.isArray(r) ? r : [];
        setItems(next);
        setSelectedSampleId(next[0]?.id ?? null);
      })
      .catch((e: unknown) => {
        if (reqSeq.current !== mySeq) return;
        setError(getErrorMessage(e, "Failed to load samples"));
      })
      .finally(() => {
        if (reqSeq.current !== mySeq) return;
        setLoading(false);
      });
  }, [open, selection, agentId, sinceMinutes]);

  useEffect(() => {
    if (!open || !focusEventId || items.length === 0) return;
    if (focusHandledRef.current === focusEventId) return;
    const found = items.find((x) => Number(x.id) === Number(focusEventId));
    if (!found) return;
    focusHandledRef.current = focusEventId;
    setSelectedSampleId(found.id);
  }, [open, focusEventId, items]);

  return (
    <>
      <Drawer
        open={open}
        title={title}
        description={selection?.hint || "Protocol intelligence indicator context and matching evidence."}
        headerLabel="Protocol intel"
        onClose={() => {
          setItems([]);
          setError(null);
          setSelectedSampleId(null);
          setEventDrawerEvent(null);
          setEventDrawerOpen(false);
          focusHandledRef.current = null;
          onClose();
        }}
        widthClassName="w-[1140px]"
      >
        {!selection ? (
          <div className="text-sm text-muted-foreground">No indicator selected.</div>
        ) : (
          <InvestigationShell className="flex min-h-full flex-col">
            <InvestigationMetaStrip
              items={[
                { label: "Kind", value: selection.kind, variant: "info" },
                { label: "Value", value: selection.value },
                { label: "Lookback", value: `${sinceMinutes}m` },
                { label: "Scope", value: agentId || "all agents" },
                { label: "Approx hits", value: typeof selection.count === "number" ? String(selection.count) : "n/a" },
              ]}
            />

            <InvestigationActionBar>
              <InvestigationActionButton
                title="Open this indicator directly in Events"
                onClick={() => window.open(eventsLink, "_blank", "noopener,noreferrer")}
              >
                Open in Events
              </InvestigationActionButton>
              <InvestigationActionButton
                onClick={async () => {
                  const ok = await copyTextToClipboard(selection.value);
                  setCopied(ok ? "ok" : "fail");
                  window.setTimeout(() => setCopied(null), 1200);
                }}
              >
                {copied === "ok" ? "Copied" : copied === "fail" ? "Copy failed" : "Copy indicator"}
              </InvestigationActionButton>
              <InvestigationActionButton
                onClick={() => {
                  if (!selectedSample) return;
                  setEventDrawerEvent(selectedSample);
                  setEventDrawerOpen(true);
                }}
                disabled={!selectedSample}
              >
                Open full event view
              </InvestigationActionButton>
              <InvestigationActionButton
                onClick={() => {
                  if (selectedSample) setPinEvent(selectedSample);
                }}
                disabled={!selectedSample}
                tone="primary"
              >
                Pin selected sample
              </InvestigationActionButton>
            </InvestigationActionBar>

            <InvestigationSection title="Indicator summary" subtitle="Protocol-level context for this IOC-like value.">
              <InvestigationSummaryGrid>
                <InvestigationFactCard label="Indicator" value={selection.label} mono />
                <InvestigationFactCard label="Value" value={selection.value} mono />
                <InvestigationFactCard
                  label="Approximate hit count"
                  value={typeof selection.count === "number" ? String(selection.count) : "-"}
                  mono
                />
                <InvestigationFactCard label="Lookback window" value={`${sinceMinutes} minutes`} mono />
                <InvestigationFactCard label="Scoped agent" value={agentId || "all agents"} mono />
                <InvestigationFactCard label="Samples loaded" value={String(items.length)} mono />
              </InvestigationSummaryGrid>
            </InvestigationSection>

            <InvestigationSection
              title="Matching samples"
              subtitle="Click a row to inspect details. Use Full view for the complete event drawer."
              className="flex min-h-[520px] flex-1 flex-col"
              bodyClassName="flex min-h-0 flex-1 flex-col"
            >
              <InvestigationStateBlock
                loading={loading}
                loadingLabel="Loading samples..."
                error={error}
                empty={!loading && !error && items.length === 0}
                emptyTitle="No matches"
                emptyHint="No events matched this indicator in the selected window."
              />

              {!loading && !error && items.length > 0 ? (
                <div className="flex min-h-0 flex-1 flex-col gap-3">
                  <div className="min-h-[180px] overflow-auto rounded-lg border border-border/60 bg-background/35" style={{ maxHeight: "min(34vh, 360px)" }}>
                    <Table
                      className="!shadow-none !border-0 !bg-transparent !rounded-none"
                      scrollX
                      columns={sampleColumns}
                      rows={items}
                      rowKey={(r) => String(r.id)}
                      selectedRowKey={selectedSampleId !== null ? String(selectedSampleId) : null}
                      onRowClick={(ev) => setSelectedSampleId(ev.id)}
                    />
                  </div>

                  <div className="flex min-h-0 flex-1 flex-col rounded-lg border border-border/60 bg-background/35">
                    <div className="shrink-0 border-b border-border/50 px-3 pb-2 pt-3 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                      Selected sample
                    </div>
                    {!selectedSample ? (
                      <div className="p-3 text-sm text-muted-foreground">Click a row above to inspect its details.</div>
                    ) : (
                      <div className="grid min-h-0 flex-1 grid-cols-1 divide-y divide-border/50 xl:grid-cols-2 xl:divide-x xl:divide-y-0">
                        <div className="p-3">
                          <InvestigationListItem
                            title={`Event #${selectedSample.id}`}
                            description={
                              <span className="inline-flex max-w-full flex-wrap items-center gap-1.5">
                                {ipEndpoint(selectedSample, "src")}
                                <span className="text-muted-foreground">→</span>
                                {ipEndpoint(selectedSample, "dst")}
                              </span>
                            }
                            badges={[{ label: selectedSample.event_type, variant: "info" }]}
                            meta={[
                              { label: "when", value: formatInvestigationTimestamp(selectedSample.timestamp) },
                              { label: "agent", value: agentNameById?.[selectedSample.agent_id] || selectedSample.agent_id },
                            ]}
                          />
                        </div>
                        <div className="min-h-0 overflow-y-auto p-3">
                          <EventDetailsPanel event={selectedSample} />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : null}
            </InvestigationSection>
          </InvestigationShell>
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

      {pinEvent ? (
        <PinToWorkspaceDrawer
          open={Boolean(pinEvent)}
          onClose={() => setPinEvent(null)}
          title={`protocol intel · event #${pinEvent.id}`}
          defaultWorkspaceTitle={`Protocol intel investigation · ${selection?.value || "indicator"}`}
          workspaceDefaults={{ primary_agent_id: pinEvent.agent_id }}
          onPin={(workspaceId, options) =>
            pinProtocolIntelEventToWorkspace(workspaceId, pinEvent.id, {
              ...options,
              source_module: "protocol_intel",
              metadata: {
                ...(options.metadata || {}),
                protocol_indicator_kind: selection?.kind,
                protocol_indicator_value: selection?.value,
              },
            })
          }
        />
      ) : null}
    </>
  );
}
