import { useEffect, useMemo, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import Drawer from "@/shared/components/Drawer";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationFactCard,
  InvestigationMetaStrip,
  InvestigationRawJsonPanel,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
  InvestigationTabs,
  copyTextToClipboard,
  safeJson,
} from "@/shared/components/investigation";
import PinToWorkspaceDrawer from "@/features/investigations/PinToWorkspaceDrawer";
import { pinEventToWorkspace } from "@/features/investigations/api";

import type { NetEvent } from "../types";
import { fmtDateTime } from "../lib/aggregates";
import EventDetailsPanel from "./EventDetailsPanel";

function fmtAddr(ip?: string | null, port?: number | null) {
  if (!ip) return "-";
  if (typeof port === "number") return `${ip}:${port}`;
  return ip;
}

type DrawerTab = "summary" | "evidence" | "raw";

export default function EventDrawer({
  open,
  event,
  agentNameById,
  onClose,
  onApplyAgent,
  onApplyType,
  onApplySearch,
}: {
  open: boolean;
  event: NetEvent | null;
  agentNameById?: Record<string, string>;
  onClose: () => void;
  onApplyAgent?: (agentId: string) => void;
  onApplyType?: (type: string) => void;
  onApplySearch?: (q: string) => void;
}) {
  const [tab, setTab] = useState<DrawerTab>("summary");
  const [copied, setCopied] = useState<null | "ok" | "fail">(null);
  const [pinOpen, setPinOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    setTab("summary");
    setCopied(null);
  }, [open, event?.id]);

  const title = useMemo(() => {
    if (!event) return "Event";
    return `${event.event_type} · #${event.id}`;
  }, [event]);

  const desc = useMemo(() => {
    if (!event) return "";
    const ts = new Date(event.timestamp);
    const t = Number.isNaN(ts.getTime()) ? event.timestamp : fmtDateTime(ts);
    const agent = agentNameById?.[event.agent_id] || event.agent_id;
    return `${t} · ${agent}`;
  }, [event, agentNameById]);

  const agentLabel = useMemo(() => {
    if (!event) return "";
    const name = agentNameById?.[event.agent_id];
    if (!name || name === event.agent_id) return event.agent_id;
    return `${name} (${event.agent_id})`;
  }, [event, agentNameById]);

  const rawJson = useMemo(() => (event ? safeJson(event) : ""), [event]);

  const netSummary = useMemo(() => {
    if (!event) return "-";
    return `${fmtAddr(event.src_ip, event.src_port)} → ${fmtAddr(event.dst_ip, event.dst_port)}`;
  }, [event]);

  return (
    <Drawer
      open={open}
      title={title}
      description={desc}
      onClose={() => {
        setCopied(null);
        onClose();
      }}
      widthClassName="w-[960px]"
    >
      {!event ? (
        <div className="text-sm text-muted-foreground">No event selected.</div>
      ) : (
        <InvestigationShell>
          <InvestigationMetaStrip
            items={[
              { label: "Type", value: event.event_type, variant: "info" },
              { label: "Agent", value: agentLabel },
              { label: "Timestamp", value: fmtDateTime(new Date(event.timestamp)) },
              { label: "Source", value: "events" },
              { label: "Schema", value: String(event.schema_version) },
            ]}
          />

          <InvestigationActionBar>
            <InvestigationActionButton
              title="Copy raw JSON"
              onClick={async () => {
                const ok = await copyTextToClipboard(rawJson);
                setCopied(ok ? "ok" : "fail");
                window.setTimeout(() => setCopied(null), 1400);
              }}
            >
              {copied === "ok" ? "Copied" : copied === "fail" ? "Copy failed" : "Copy JSON"}
            </InvestigationActionButton>
            <InvestigationActionButton
              title="Open this indicator in Events search"
              onClick={() => {
                const q = String(event.id);
                const sp = new URLSearchParams();
                sp.set("search", q);
                if (event.agent_id) sp.set("agent_id", event.agent_id);
                window.open(`/events?${sp.toString()}`, "_blank", "noopener,noreferrer");
              }}
            >
              Open in Events
            </InvestigationActionButton>
            <InvestigationActionButton
              title="Filter to this agent"
              onClick={() => onApplyAgent?.(event.agent_id)}
              disabled={!onApplyAgent}
            >
              Scope agent
            </InvestigationActionButton>
            <InvestigationActionButton
              title="Filter to this event type"
              onClick={() => onApplyType?.(event.event_type)}
              disabled={!onApplyType}
            >
              Scope type
            </InvestigationActionButton>
            <InvestigationActionButton
              title="Search this source IP"
              onClick={() => {
                const q = (event.src_ip || "").trim();
                if (q) onApplySearch?.(q);
              }}
              disabled={!onApplySearch || !event.src_ip}
            >
              Search src
            </InvestigationActionButton>
            <InvestigationActionButton
              title="Pin this event into an investigation workspace"
              onClick={() => setPinOpen(true)}
              tone="primary"
            >
              Pin to workspace
            </InvestigationActionButton>
          </InvestigationActionBar>

          <InvestigationTabs
            value={tab}
            onChange={setTab}
            tabs={[
              { key: "summary", label: "Summary" },
              { key: "evidence", label: "Evidence" },
              { key: "raw", label: "Raw" },
            ]}
          />

          {tab === "summary" ? (
            <InvestigationSection title="High-value facts" subtitle="Start with network path, protocol, and event identity.">
              <InvestigationSummaryGrid>
                <InvestigationFactCard label="Event ID" value={`#${event.id}`} mono />
                <InvestigationFactCard label="Agent" value={agentLabel} mono />
                <InvestigationFactCard label="Type" value={<Badge variant="info">{event.event_type}</Badge>} />
                <InvestigationFactCard label="Network path" value={netSummary} mono />
                <InvestigationFactCard label="Protocol" value={event.proto || "-"} mono />
                <InvestigationFactCard
                  label="Bytes"
                  value={typeof event.bytes === "number" ? String(event.bytes) : "-"}
                  mono
                />
              </InvestigationSummaryGrid>
            </InvestigationSection>
          ) : null}

          {tab === "evidence" ? (
            <InvestigationSection title="Evidence context" subtitle="Structured event details for investigation.">
              <EventDetailsPanel event={event} />
            </InvestigationSection>
          ) : null}

          {tab === "raw" ? <InvestigationRawJsonPanel value={event} title="Raw event payload" /> : null}
        </InvestigationShell>
      )}

      {event ? (
        <PinToWorkspaceDrawer
          open={pinOpen}
          onClose={() => setPinOpen(false)}
          title={`${event.event_type} · #${event.id}`}
          defaultWorkspaceTitle={`Investigation · ${event.event_type} #${event.id}`}
          workspaceDefaults={{ primary_agent_id: event.agent_id }}
          onPin={(workspaceId, options) => pinEventToWorkspace(workspaceId, event.id, { ...options, source_module: "events" })}
        />
      ) : null}
    </Drawer>
  );
}
