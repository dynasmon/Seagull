import { useMemo, useState } from "react";

import Drawer from "@/shared/components/Drawer";
import { Badge } from "@/shared/components/Badge";
import { cx } from "@/shared/lib/cx";

import type { NetEvent } from "../types";
import { fmtDateTime } from "../lib/aggregates";
import EventDetailsPanel from "./EventDetailsPanel";

function fmtAddr(ip?: string | null, port?: number | null) {
  if (!ip) return "-";
  if (typeof port === "number") return `${ip}:${port}`;
  return ip;
}

function safeJson(v: any) {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

async function copyToClipboard(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}

function ActionButton({
  children,
  onClick,
  title,
  disabled
}: {
  children: any;
  onClick: () => void;
  title?: string;
  disabled?: boolean;
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

export default function EventDrawer({
  open,
  event,
  agentNameById,
  onClose,
  onApplyAgent,
  onApplyType,
  onApplySearch
}: {
  open: boolean;
  event: NetEvent | null;
  agentNameById?: Record<string, string>;
  onClose: () => void;
  onApplyAgent?: (agentId: string) => void;
  onApplyType?: (type: string) => void;
  onApplySearch?: (q: string) => void;
}) {
  const [copied, setCopied] = useState<null | "ok" | "fail">(null);

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

  return (
    <Drawer
      open={open}
      title={title}
      description={desc}
      onClose={() => {
        setCopied(null);
        onClose();
      }}
      widthClassName="w-[900px]"
    >
      {!event ? (
        <div className="text-sm text-muted-foreground">No event selected.</div>
      ) : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge>{event.event_type}</Badge>
              <span className="text-[11px] font-mono text-muted-foreground">agent</span>
              <span className="text-[12px] font-mono text-foreground">{agentLabel}</span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <ActionButton
                title="Copy raw JSON"
                onClick={async () => {
                  const ok = await copyToClipboard(rawJson);
                  setCopied(ok ? "ok" : "fail");
                  window.setTimeout(() => setCopied(null), 1400);
                }}
              >
                {copied === "ok" ? "Copied" : copied === "fail" ? "Copy failed" : "Copy JSON"}
              </ActionButton>

              <ActionButton
                title="Filter to this agent"
                onClick={() => {
                  onApplyAgent?.(event.agent_id);
                }}
                disabled={!onApplyAgent}
              >
                Scope agent
              </ActionButton>

              <ActionButton
                title="Filter to this event type"
                onClick={() => {
                  onApplyType?.(event.event_type);
                }}
                disabled={!onApplyType}
              >
                Scope type
              </ActionButton>

              <ActionButton
                title="Search this source IP"
                onClick={() => {
                  const q = (event.src_ip || "").trim();
                  if (q) onApplySearch?.(q);
                }}
                disabled={!onApplySearch || !event.src_ip}
              >
                Search src
              </ActionButton>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div className="space-y-3">
              <div className="rounded-lg border border-border/60 bg-background/60 p-4">
                <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Network</div>
                <div className="mt-3 grid grid-cols-2 gap-3 text-[12px] font-mono">
                  <div className="space-y-1">
                    <div className="text-[10px] uppercase tracking-widest text-muted-foreground">src</div>
                    <div className="text-foreground">{fmtAddr(event.src_ip, event.src_port)}</div>
                  </div>
                  <div className="space-y-1">
                    <div className="text-[10px] uppercase tracking-widest text-muted-foreground">dst</div>
                    <div className="text-foreground">{fmtAddr(event.dst_ip, event.dst_port)}</div>
                  </div>
                  <div className="space-y-1">
                    <div className="text-[10px] uppercase tracking-widest text-muted-foreground">proto</div>
                    <div className="text-foreground">{event.proto || "-"}</div>
                  </div>
                  <div className="space-y-1">
                    <div className="text-[10px] uppercase tracking-widest text-muted-foreground">bytes</div>
                    <div className="text-foreground">{typeof event.bytes === "number" ? String(event.bytes) : "-"}</div>
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-border/60 bg-background/60 p-4">
                <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Raw (quick)</div>
                <pre className="mt-3 max-h-[240px] overflow-auto border border-border/60 bg-background/40 p-3 text-[11px] leading-relaxed">
                  {rawJson}
                </pre>
              </div>
            </div>

            <div className="rounded-lg border border-border/60 bg-background/60 p-4">
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Details</div>
              <div className="mt-3">
                <EventDetailsPanel event={event} />
              </div>
            </div>
          </div>
        </div>
      )}
    </Drawer>
  );
}
