import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";

import type { NetEvent } from "../types";
import { fmtDateTime } from "../lib/aggregates";
import { extractDdosFields, ddosLabel, fmtHumanRate, isDdosEvent } from "../lib/ddos";
import { normalizeDetails, safeNumber } from "../lib/normalize";
import { formatProtocolLabel, getEventProtocolIntel } from "../lib/protocol";

function Kv({ k, v }: { k: string; v: any }) {
  const val = v === undefined || v === null || v === "" ? "-" : String(v);
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{k}</div>
      <div className="text-[11px] font-mono text-foreground text-right">{val}</div>
    </div>
  );
}

export default function EventDetailsPanel({ event }: { event: NetEvent | null }) {
  if (!event) {
    return <EmptyState title="Select an event" hint="Click an event row to inspect fields and metadata." />;
  }

  const extra = normalizeDetails(event.extra);
  const src = event.src_ip ? `${event.src_ip}${event.src_port ? `:${event.src_port}` : ""}` : "-";
  const dst = event.dst_ip ? `${event.dst_ip}${event.dst_port ? `:${event.dst_port}` : ""}` : "-";

  const isDdos = isDdosEvent(event);
  const ddos = isDdos ? extractDdosFields(extra) : null;
  const isProcExec = event.event_type === "proc_exec";
  const isFim = ["fim_change", "persistence_systemd", "persistence_cron", "ssh_key_change"].includes(event.event_type);
  const isHeuristic = ["beacon_suspect", "exfil_suspect", "c2_suspect", "egress_anomaly"].includes(event.event_type);
  const protocol = getEventProtocolIntel(event);

  const reasons = Array.isArray(extra.reasons) ? extra.reasons.map((x) => String(x)).filter(Boolean).join("; ") : "";
  const procPatterns = Array.isArray(extra.exec_patterns) ? extra.exec_patterns.map((x) => String(x)).filter(Boolean).join(", ") : "";

  return (
    <div className="space-y-4">
      <div className="grid gap-3">
        <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Summary</div>
        <div className="border border-border/60 bg-background/40 p-3">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-xs font-mono uppercase tracking-widest text-muted-foreground">{event.event_type}</div>
              <div className="mt-1 text-sm">
                <span className="font-mono">{src}</span> → <span className="font-mono">{dst}</span>
                {protocol.appProto ? (
                  <span className="text-muted-foreground">
                    {" "}
                    ({formatProtocolLabel(protocol.appProto)}
                    {protocol.transportProto ? ` over ${formatProtocolLabel(protocol.transportProto)}` : ""})
                  </span>
                ) : protocol.transportProto ? (
                  <span className="text-muted-foreground"> ({formatProtocolLabel(protocol.transportProto)})</span>
                ) : null}
              </div>
              <div className="mt-2 text-[11px] text-muted-foreground font-mono">
                ts={fmtDateTime(new Date(event.timestamp))} · agent={event.agent_id} · schema={event.schema_version} · id={event.id}
              </div>
            </div>

            {isDdos && ddos && (
              <div className="shrink-0 text-right">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Detection</div>
                <div className="mt-1 text-sm font-mono">{ddosLabel(ddos)}</div>
                <div
                  className={cx(
                    "mt-1 inline-flex items-center gap-2 rounded-md border px-2 py-1 text-[10px] font-mono uppercase tracking-widest",
                    ddos.severity.toLowerCase() === "critical"
                      ? "border-red-500/60 bg-red-500/10 text-red-400"
                      : ddos.severity.toLowerCase() === "high"
                        ? "border-orange-500/60 bg-orange-500/10 text-orange-300"
                        : "border-border/60 bg-background/30 text-muted-foreground"
                  )}
                >
                  sev {ddos.severity || "-"}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {isDdos && ddos && (
        <div className="space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">DDoS fields</div>
          <div className="border border-border/60 bg-background/40 p-3 space-y-2">
            <Kv k="confidence" v={ddos.confidence === null ? "-" : ddos.confidence.toFixed(2)} />
            <Kv k="pps" v={ddos.pps === null ? "-" : fmtHumanRate(ddos.pps)} />
            <Kv k="bps" v={ddos.bps === null ? "-" : fmtHumanRate(ddos.bps)} />
            <Kv k="unique_src_ips" v={ddos.unique_src_ips === null ? "-" : Math.round(ddos.unique_src_ips)} />
            <Kv k="src_entropy_norm" v={ddos.src_entropy_norm === null ? "-" : ddos.src_entropy_norm.toFixed(3)} />
            <Kv k="http_rps" v={ddos.http_rps === null ? "-" : fmtHumanRate(ddos.http_rps)} />
            <Kv k="tls_handshake_rps" v={ddos.tls_handshake_rps === null ? "-" : fmtHumanRate(ddos.tls_handshake_rps)} />
            <Kv k="tcp_syn_ratio" v={ddos.tcp_syn_ratio === null ? "-" : ddos.tcp_syn_ratio.toFixed(3)} />
          </div>
        </div>
      )}

      {isDdos && ddos && ddos.top_src.length > 0 && (
        <div className="space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Top sources</div>
          <div className="border border-border/60 bg-background/40 p-3 space-y-2">
            {ddos.top_src.slice(0, 10).map((x, i) => (
              <div key={`${x.ip || "-"}-${i}`} className="flex items-center justify-between gap-3 text-[11px] font-mono">
                <div className="text-foreground truncate">{x.ip || "-"}</div>
                <div className="text-muted-foreground">{safeNumber(x.count) ?? "-"}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {isProcExec && (
        <div className="space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Process execution</div>
          <div className="border border-border/60 bg-background/40 p-3 space-y-2">
            <Kv k="pid" v={extra.pid} />
            <Kv k="ppid" v={extra.ppid} />
            <Kv k="exe_name" v={extra.exe_name || extra.comm || extra.binary} />
            <Kv k="exe_path" v={extra.exe_path} />
            <Kv k="cmdline" v={extra.cmdline} />
            <Kv k="parent_exe_name" v={extra.parent_exe_name || extra.parent_comm} />
            <Kv k="uid/euid" v={`${extra.uid ?? "-"} / ${extra.euid ?? "-"}`} />
            <Kv k="gid/egid" v={`${extra.gid ?? "-"} / ${extra.egid ?? "-"}`} />
            <Kv k="username" v={extra.username} />
            <Kv k="cwd" v={extra.cwd} />
            <Kv k="process_start_time" v={extra.process_start_time} />
            <Kv k="exe_sha256" v={extra.exe_sha256} />
            <Kv k="exec_patterns" v={procPatterns} />
            <Kv k="collection_method" v={extra.collection_method} />
          </div>
        </div>
      )}

      {isFim && (
        <div className="space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">FIM / Persistence</div>
          <div className="border border-border/60 bg-background/40 p-3 space-y-2">
            <Kv k="path" v={extra.path} />
            <Kv k="path_category" v={extra.path_category} />
            <Kv k="action" v={extra.action} />
            <Kv k="persistence_related" v={extra.persistence_related} />
            <Kv k="tamper_related" v={extra.tamper_related} />
            <Kv k="path_from" v={extra.path_from} />
            <Kv k="path_to" v={extra.path_to} />
            <Kv k="uid/gid" v={`${extra.uid ?? "-"} / ${extra.gid ?? "-"}`} />
            <Kv k="mode" v={extra.mode} />
            <Kv k="digest_before" v={extra.digest_before} />
            <Kv k="digest_after" v={extra.digest_after} />
          </div>
        </div>
      )}

      {protocol.hasProtocolIntel && (
        <div className="space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Protocol intel</div>
          <div className="border border-border/60 bg-background/40 p-3 space-y-2">
            <Kv k="transport_proto" v={formatProtocolLabel(protocol.transportProto)} />
            <Kv k="app_proto" v={formatProtocolLabel(protocol.appProto)} />
            <Kv k="app_proto_reason" v={protocol.appProtoReason} />
            <Kv k="app_proto_conf_band" v={protocol.appProtoConfBand} />
            <Kv k="flow_direction" v={protocol.flowDirection} />
            <Kv k="dns_qname" v={protocol.dnsQname} />
            <Kv k="dns_qtype" v={protocol.dnsQtype} />
            <Kv k="dns_rcode" v={protocol.dnsRcode} />
            <Kv k="dns_answers" v={protocol.dnsAnswers} />
            <Kv k="http_method" v={protocol.httpMethod} />
            <Kv k="http_host" v={protocol.httpHost} />
            <Kv k="http_path" v={protocol.httpPath} />
            <Kv k="http_status" v={protocol.httpStatus} />
            <Kv k="http_user_agent" v={protocol.httpUserAgent} />
            <Kv k="tls_sni" v={protocol.tlsSni} />
            <Kv k="tls_alpn_first" v={protocol.tlsAlpnFirst} />
            <Kv k="tls_version" v={protocol.tlsVersion} />
            <Kv k="ja3" v={protocol.ja3} />
            <Kv k="ja4" v={protocol.ja4} />
            <Kv k="ja4_ptype" v={protocol.ja4Ptype} />
          </div>
        </div>
      )}

      {isHeuristic && (
        <div className="space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Heuristic reasoning</div>
          <div className="border border-border/60 bg-background/40 p-3 space-y-2">
            <Kv k="heuristic_name" v={extra.heuristic_name} />
            <Kv k="heuristic_kind" v={extra.heuristic_kind} />
            <Kv k="reason_kind" v={extra.reason_kind} />
            <Kv k="confidence" v={extra.confidence} />
            <Kv k="sample_count" v={extra.sample_count} />
            <Kv k="interval_mean_s" v={extra.interval_mean_s} />
            <Kv k="interval_jitter_cv" v={extra.interval_jitter_cv} />
            <Kv k="recent_events" v={extra.recent_events} />
            <Kv k="baseline_events" v={extra.baseline_events} />
            <Kv k="recent_bytes" v={extra.recent_bytes || extra.bytes_total} />
            <Kv k="baseline_bytes" v={extra.baseline_bytes} />
            <Kv k="spike_factor_observed" v={extra.spike_factor_observed} />
            <Kv k="dst_host" v={extra.dst_host} />
            <Kv k="app_proto" v={extra.app_proto} />
            <Kv k="reasons" v={reasons} />
          </div>
        </div>
      )}

      <div>
        <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground mb-2">Extra (raw)</div>
        <pre className="border border-border/60 bg-background/40 p-3 text-[11px] leading-relaxed overflow-auto">
          {JSON.stringify(extra, null, 2)}
        </pre>
      </div>
    </div>
  );
}
