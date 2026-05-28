import type { ReactNode } from "react";

import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { getFlowIpContext } from "@/shared/lib/ipClassification";

import type { NetEvent } from "../types";

function endpoint(event: NetEvent, side: "src" | "dst"): ReactNode {
  const ip = side === "src" ? event.src_ip : event.dst_ip;
  const port = side === "src" ? event.src_port : event.dst_port;
  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
      <IpAddressPill ip={ip} ipContext={getFlowIpContext(event.extra?.ip_context, side)} compact />
      {typeof port === "number" ? <span className="text-muted-foreground">:{port}</span> : null}
    </span>
  );
}

export function SrcEndpoint({ event }: { event: NetEvent }) {
  return <>{endpoint(event, "src")}</>;
}

export function DstEndpoint({ event }: { event: NetEvent }) {
  return <>{endpoint(event, "dst")}</>;
}

export function SrcDstFlow({ event }: { event: NetEvent }) {
  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-1.5">
      {endpoint(event, "src")}
      <span className="text-muted-foreground">→</span>
      {endpoint(event, "dst")}
    </span>
  );
}
