import { useMemo, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import EmptyState from "@/shared/components/EmptyState";
import { StatusPill } from "@/shared/components/StatusPill";
import { Table, type Column } from "@/shared/components/Table";
import { Tabs, type TabItem } from "@/shared/components/Tabs";
import { TextInput } from "@/shared/components/TextInput";

import type { ResponseActionResultOut } from "../types";
import { formatUptime, tcpStateLabel } from "./lib";

type TriageTab = "host" | "processes" | "network" | "auth" | "config" | "modules";
type NetTab = "tcp" | "tcp6" | "udp" | "udp6";

type InterfaceRow = { name?: string; mtu?: number; flags?: string; ips?: string[] };
type ProcessRow = { pid?: number; name?: string; state?: string; uid?: string };
type ConnRow = { proto?: string; local_ip?: string; local_port?: number; remote_ip?: string; remote_port?: number; state?: string };

type AuthVariant = "danger" | "warning" | "success" | "neutral";

const AUTH_LINE_CLASS: Record<AuthVariant, string> = {
  danger: "text-severity-high",
  warning: "text-severity-medium",
  success: "text-severity-low",
  neutral: "text-muted-foreground",
};

function authLineVariant(line: string): AuthVariant {
  const lc = line.toLowerCase();
  if (lc.includes("failed") || lc.includes("invalid") || lc.includes("failure")) return "danger";
  if (lc.includes("accepted")) return "success";
  if (lc.includes("sudo")) return "warning";
  return "neutral";
}

export default function TriageBundleResultRenderer({ result }: { result: ResponseActionResultOut }) {
  const payload = result.result_payload || {};
  const [tab, setTab] = useState<TriageTab>("host");
  const [netTab, setNetTab] = useState<NetTab>("tcp");
  const [procFilter, setProcFilter] = useState("");
  const [cfgFilter, setCfgFilter] = useState("");

  const host = payload.host || {};
  const runtime = payload.runtime || {};
  const interfaces: InterfaceRow[] = Array.isArray(host.interfaces) ? host.interfaces : [];
  const processes = useMemo<ProcessRow[]>(
    () => (Array.isArray(payload.processes) ? payload.processes : []),
    [payload.processes],
  );
  const network = payload.network || {};
  const authLog = payload.auth_log || {};
  const authLines: string[] = Array.isArray(authLog.lines) ? authLog.lines : [];
  const effectiveConfig = useMemo<Record<string, any>>(
    () => (payload.effective_config && typeof payload.effective_config === "object" ? payload.effective_config : {}),
    [payload.effective_config],
  );
  const modules: Record<string, any> = payload.modules && typeof payload.modules === "object" ? payload.modules : {};

  const filteredProcesses = useMemo(() => {
    const q = procFilter.trim().toLowerCase();
    const rows = q
      ? processes.filter((row) => String(row.name || "").toLowerCase().includes(q) || String(row.pid ?? "").includes(q))
      : processes;
    return [...rows].sort((a, b) => (Number(b.pid) || 0) - (Number(a.pid) || 0));
  }, [processes, procFilter]);

  const configEntries = useMemo(() => {
    const q = cfgFilter.trim().toLowerCase();
    return Object.entries(effectiveConfig)
      .filter(([key]) => (q ? key.toLowerCase().includes(q) : true))
      .sort(([a], [b]) => a.localeCompare(b));
  }, [effectiveConfig, cfgFilter]);

  const netRows: ConnRow[] = Array.isArray(network[netTab]) ? network[netTab] : [];

  const ifaceColumns: Array<Column<InterfaceRow>> = [
    { key: "name", title: "Name", render: (row) => <span className="font-mono text-[11px]">{row.name || "—"}</span> },
    { key: "ips", title: "IPs", render: (row) => <span className="font-mono text-[11px]">{(row.ips || []).join(", ") || "—"}</span> },
    { key: "mtu", title: "MTU", width: 80, render: (row) => <span className="font-mono text-[11px]">{row.mtu ?? "—"}</span> },
    { key: "flags", title: "Flags", render: (row) => <span className="font-mono text-[10.5px] text-muted-foreground">{row.flags || "—"}</span> },
  ];

  const procColumns: Array<Column<ProcessRow>> = [
    { key: "pid", title: "PID", width: 90, render: (row) => <span className="font-mono text-[11px]">{row.pid ?? "—"}</span> },
    { key: "name", title: "Name", render: (row) => <span className="font-mono text-[11px]">{row.name || "—"}</span> },
    { key: "state", title: "State", width: 90, render: (row) => <span className="font-mono text-[11px]">{row.state || "—"}</span> },
    { key: "uid", title: "UID", width: 130, render: (row) => <span className="font-mono text-[10.5px] text-muted-foreground">{row.uid || "—"}</span> },
  ];

  const connColumns: Array<Column<ConnRow>> = [
    { key: "proto", title: "Proto", width: 70, render: (row) => <span className="font-mono text-[11px]">{row.proto || netTab}</span> },
    { key: "local", title: "Local", render: (row) => <span className="font-mono text-[11px]">{`${row.local_ip ?? ""}:${row.local_port ?? ""}`}</span> },
    { key: "remote", title: "Remote", render: (row) => <span className="font-mono text-[11px]">{`${row.remote_ip ?? ""}:${row.remote_port ?? ""}`}</span> },
    { key: "state", title: "State", width: 130, render: (row) => <span className="font-mono text-[11px]">{tcpStateLabel(String(row.state || ""))}</span> },
  ];

  const tabs: Array<TabItem<TriageTab>> = [
    { key: "host", label: "Host" },
    { key: "processes", label: "Processes", badge: processes.length || undefined },
    { key: "network", label: "Network" },
    { key: "auth", label: "Auth log", badge: authLines.length || undefined },
    { key: "config", label: "Config", badge: Object.keys(effectiveConfig).length || undefined },
    { key: "modules", label: "Modules", badge: Object.keys(modules).length || undefined },
  ];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {payload.hostname ? <Badge variant="neutral">{String(payload.hostname)}</Badge> : null}
        {runtime.goos ? <Badge variant="neutral">{`${runtime.goos}/${runtime.goarch}`}</Badge> : null}
        {payload.agent_version ? <Badge variant="info">{`agent ${payload.agent_version}`}</Badge> : null}
        {typeof payload.agent_uptime_seconds === "number" ? (
          <span className="text-[11px] text-muted-foreground">up {formatUptime(payload.agent_uptime_seconds)}</span>
        ) : null}
      </div>

      <Tabs value={tab} onChange={setTab} tabs={tabs} />

      {tab === "host" ? (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
            {runtime.pid ? <span>pid {runtime.pid}</span> : null}
            {runtime.go_version ? <span>{runtime.go_version}</span> : null}
            {runtime.num_cpu ? <span>{runtime.num_cpu} CPU</span> : null}
            {runtime.gomaxprocs ? <span>GOMAXPROCS {runtime.gomaxprocs}</span> : null}
            {runtime.num_goroutine ? <span>{runtime.num_goroutine} goroutines</span> : null}
          </div>
          {interfaces.length === 0 ? (
            <EmptyState title="No host data" hint="The host collector was disabled or returned nothing." />
          ) : (
            <Table<InterfaceRow> columns={ifaceColumns} rows={interfaces} rowKey={(row, idx) => row.name || String(idx)} compact />
          )}
        </div>
      ) : tab === "processes" ? (
        <div className="space-y-2">
          <TextInput
            className="font-mono text-[11px]"
            placeholder="Filter by name or PID"
            value={procFilter}
            onChange={(event) => setProcFilter(event.target.value)}
          />
          {filteredProcesses.length === 0 ? (
            <EmptyState title="No processes" hint={procFilter ? "No processes match the filter." : "The process collector returned nothing."} />
          ) : (
            <Table<ProcessRow> columns={procColumns} rows={filteredProcesses} rowKey={(row, idx) => String(row.pid ?? idx)} compact />
          )}
        </div>
      ) : tab === "network" ? (
        <div className="space-y-2">
          <Tabs
            value={netTab}
            onChange={setNetTab}
            tabs={[
              { key: "tcp", label: "TCP", badge: (Array.isArray(network.tcp) ? network.tcp.length : 0) || undefined },
              { key: "tcp6", label: "TCP6", badge: (Array.isArray(network.tcp6) ? network.tcp6.length : 0) || undefined },
              { key: "udp", label: "UDP", badge: (Array.isArray(network.udp) ? network.udp.length : 0) || undefined },
              { key: "udp6", label: "UDP6", badge: (Array.isArray(network.udp6) ? network.udp6.length : 0) || undefined },
            ]}
          />
          {netRows.length === 0 ? (
            <EmptyState title="No connections" hint="No sockets in this table." />
          ) : (
            <Table<ConnRow>
              columns={connColumns}
              rows={netRows}
              rowKey={(row, idx) => `${row.proto}-${row.local_ip}:${row.local_port}-${row.remote_ip}:${row.remote_port}-${idx}`}
              compact
              scrollX
            />
          )}
        </div>
      ) : tab === "auth" ? (
        authLines.length === 0 ? (
          <EmptyState title="No auth log" hint="No readable auth log on the host." />
        ) : (
          <div className="space-y-2">
            {authLog.source ? <div className="font-mono text-[10.5px] text-muted-foreground">{String(authLog.source)}</div> : null}
            <div className="max-h-[420px] space-y-1 overflow-y-auto rounded-md border border-border/60 bg-background/30 p-2">
              {authLines.map((line, idx) => (
                <div key={idx} className={`font-mono text-[10.5px] ${AUTH_LINE_CLASS[authLineVariant(line)]}`}>
                  {line}
                </div>
              ))}
            </div>
          </div>
        )
      ) : tab === "config" ? (
        <div className="space-y-2">
          <TextInput
            className="font-mono text-[11px]"
            placeholder="Filter keys"
            value={cfgFilter}
            onChange={(event) => setCfgFilter(event.target.value)}
          />
          {configEntries.length === 0 ? (
            <EmptyState title="No config" hint={cfgFilter ? "No keys match the filter." : "The effective config collector was disabled."} />
          ) : (
            <div className="divide-y divide-border/40 rounded-md border border-border/60 bg-background/30">
              {configEntries.map(([key, value]) => (
                <div key={key} className="flex items-baseline gap-3 px-2 py-1">
                  <div className="w-48 shrink-0 truncate font-mono text-[11px] text-muted-foreground" title={key}>
                    {key}
                  </div>
                  <div
                    className="min-w-0 flex-1 truncate font-mono text-[11px] text-foreground"
                    title={typeof value === "string" ? value : JSON.stringify(value)}
                  >
                    {typeof value === "object" && value !== null ? JSON.stringify(value) : String(value)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : Object.keys(modules).length === 0 ? (
        <EmptyState title="No modules" hint="No module state reported." />
      ) : (
        <div className="flex flex-wrap gap-2">
          {Object.entries(modules)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([name, value]) => {
              const enabled =
                value === true ||
                (value && typeof value === "object" && (value.enabled === true || value.active === true || value.running === true));
              return (
                <div key={name} className="flex items-center gap-2 rounded-md border border-border/60 bg-background/30 px-2 py-1">
                  <StatusPill variant={enabled ? "success" : "inactive"}>{enabled ? "on" : "off"}</StatusPill>
                  <span className="font-mono text-[11px] text-foreground">{name}</span>
                </div>
              );
            })}
        </div>
      )}
    </div>
  );
}
