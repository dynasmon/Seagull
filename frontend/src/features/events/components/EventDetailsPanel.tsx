import EmptyState from "@/shared/components/EmptyState";
import { JsonBlock } from "@/shared/components/JsonBlock";
import { Panel } from "@/shared/components/Panel";
import {
  InvestigationFieldGroup,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";

import type { NetEvent } from "../types";
import { extractDdosFields, ddosLabel, fmtHumanRate, isDdosEvent } from "../lib/ddos";
import { normalizeDetails, safeNumber } from "../lib/normalize";
import { formatProtocolLabel, getEventProtocolIntel } from "../lib/protocol";
import { DstEndpoint, SrcEndpoint } from "./SrcDstFlow";

export default function EventDetailsPanel({ event }: { event: NetEvent | null }) {
  if (!event) {
    return <EmptyState title="Select an event" hint="Click an event row to inspect fields and metadata." />;
  }

  const extra = normalizeDetails(event.extra);
  const src = <SrcEndpoint event={event} />;
  const dst = <DstEndpoint event={event} />;

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
      <InvestigationFieldGroup
        title="Core summary"
        subtitle="Primary path, classification, and collection context."
        entries={[
          { key: "event_type", value: event.event_type },
          { key: "source", value: src },
          { key: "destination", value: dst },
          {
            key: "protocol",
            value: protocol.appProto
              ? `${formatProtocolLabel(protocol.appProto)}${protocol.transportProto ? ` over ${formatProtocolLabel(protocol.transportProto)}` : ""}`
              : protocol.transportProto
                ? formatProtocolLabel(protocol.transportProto)
                : "-",
          },
          { key: "timestamp", value: formatInvestigationTimestamp(event.timestamp) },
          { key: "agent_id", value: event.agent_id },
          { key: "schema_version", value: String(event.schema_version) },
          { key: "event_id", value: String(event.id) },
          ...(isDdos && ddos
            ? [
                { key: "ddos_kind", value: ddosLabel(ddos) },
                { key: "ddos_severity", value: ddos.severity || "-" },
              ]
            : []),
        ]}
      />

      {isDdos && ddos && (
        <InvestigationFieldGroup
          title="DDoS fields"
          entries={[
            { key: "confidence", value: ddos.confidence === null ? "-" : ddos.confidence.toFixed(2) },
            { key: "pps", value: ddos.pps === null ? "-" : fmtHumanRate(ddos.pps) },
            { key: "bps", value: ddos.bps === null ? "-" : fmtHumanRate(ddos.bps) },
            { key: "unique_src_ips", value: ddos.unique_src_ips === null ? "-" : String(Math.round(ddos.unique_src_ips)) },
            { key: "src_entropy_norm", value: ddos.src_entropy_norm === null ? "-" : ddos.src_entropy_norm.toFixed(3) },
            { key: "http_rps", value: ddos.http_rps === null ? "-" : fmtHumanRate(ddos.http_rps) },
            { key: "tls_handshake_rps", value: ddos.tls_handshake_rps === null ? "-" : fmtHumanRate(ddos.tls_handshake_rps) },
            { key: "tcp_syn_ratio", value: ddos.tcp_syn_ratio === null ? "-" : ddos.tcp_syn_ratio.toFixed(3) },
          ]}
        />
      )}

      {isDdos && ddos && ddos.top_src.length > 0 && (
        <InvestigationFieldGroup
          title="Top sources"
          entries={ddos.top_src.slice(0, 10).map((x, i) => ({
            key: x.ip || `source_${i + 1}`,
            value: String(safeNumber(x.count) ?? "-"),
          }))}
        />
      )}

      {isProcExec && (
        <InvestigationFieldGroup
          title="Process execution"
          entries={[
            { key: "pid", value: String(extra.pid ?? "-") },
            { key: "ppid", value: String(extra.ppid ?? "-") },
            { key: "exe_name", value: String(extra.exe_name || extra.comm || extra.binary || "-") },
            { key: "exe_path", value: String(extra.exe_path || "-") },
            { key: "cmdline", value: String(extra.cmdline || "-") },
            { key: "parent_exe_name", value: String(extra.parent_exe_name || extra.parent_comm || "-") },
            { key: "uid/euid", value: `${extra.uid ?? "-"} / ${extra.euid ?? "-"}` },
            { key: "gid/egid", value: `${extra.gid ?? "-"} / ${extra.egid ?? "-"}` },
            { key: "username", value: String(extra.username || "-") },
            { key: "cwd", value: String(extra.cwd || "-") },
            { key: "process_start_time", value: String(extra.process_start_time || "-") },
            { key: "exe_sha256", value: String(extra.exe_sha256 || "-") },
            { key: "exec_patterns", value: procPatterns || "-" },
            { key: "collection_method", value: String(extra.collection_method || "-") },
          ]}
        />
      )}

      {isFim && (
        <InvestigationFieldGroup
          title="FIM / persistence"
          entries={[
            { key: "path", value: String(extra.path || "-") },
            { key: "path_category", value: String(extra.path_category || "-") },
            { key: "action", value: String(extra.action || "-") },
            { key: "persistence_related", value: String(extra.persistence_related ?? "-") },
            { key: "tamper_related", value: String(extra.tamper_related ?? "-") },
            { key: "path_from", value: String(extra.path_from || "-") },
            { key: "path_to", value: String(extra.path_to || "-") },
            { key: "uid/gid", value: `${extra.uid ?? "-"} / ${extra.gid ?? "-"}` },
            { key: "mode", value: String(extra.mode || "-") },
            { key: "digest_before", value: String(extra.digest_before || "-") },
            { key: "digest_after", value: String(extra.digest_after || "-") },
          ]}
        />
      )}

      {protocol.hasProtocolIntel && (
        <InvestigationFieldGroup
          title="Protocol intel"
          entries={[
            { key: "transport_proto", value: formatProtocolLabel(protocol.transportProto) },
            { key: "app_proto", value: formatProtocolLabel(protocol.appProto) },
            { key: "app_proto_reason", value: protocol.appProtoReason || "-" },
            { key: "app_proto_conf_band", value: protocol.appProtoConfBand || "-" },
            { key: "flow_direction", value: protocol.flowDirection || "-" },
            { key: "dns_qname", value: protocol.dnsQname || "-" },
            { key: "dns_qtype", value: protocol.dnsQtype || "-" },
            { key: "dns_rcode", value: protocol.dnsRcode || "-" },
            { key: "dns_answers", value: protocol.dnsAnswers || "-" },
            { key: "http_method", value: protocol.httpMethod || "-" },
            { key: "http_host", value: protocol.httpHost || "-" },
            { key: "http_path", value: protocol.httpPath || "-" },
            { key: "http_status", value: protocol.httpStatus || "-" },
            { key: "http_user_agent", value: protocol.httpUserAgent || "-" },
            { key: "tls_sni", value: protocol.tlsSni || "-" },
            { key: "tls_alpn_first", value: protocol.tlsAlpnFirst || "-" },
            { key: "tls_version", value: protocol.tlsVersion || "-" },
            { key: "ja3", value: protocol.ja3 || "-" },
            { key: "ja4", value: protocol.ja4 || "-" },
            { key: "ja4_ptype", value: protocol.ja4Ptype || "-" },
          ]}
        />
      )}

      {isHeuristic && (
        <InvestigationFieldGroup
          title="Heuristic reasoning"
          entries={[
            { key: "heuristic_name", value: String(extra.heuristic_name || "-") },
            { key: "heuristic_kind", value: String(extra.heuristic_kind || "-") },
            { key: "reason_kind", value: String(extra.reason_kind || "-") },
            { key: "confidence", value: String(extra.confidence ?? "-") },
            { key: "sample_count", value: String(extra.sample_count ?? "-") },
            { key: "interval_mean_s", value: String(extra.interval_mean_s ?? "-") },
            { key: "interval_jitter_cv", value: String(extra.interval_jitter_cv ?? "-") },
            { key: "recent_events", value: String(extra.recent_events ?? "-") },
            { key: "baseline_events", value: String(extra.baseline_events ?? "-") },
            { key: "recent_bytes", value: String(extra.recent_bytes || extra.bytes_total || "-") },
            { key: "baseline_bytes", value: String(extra.baseline_bytes ?? "-") },
            { key: "spike_factor_observed", value: String(extra.spike_factor_observed ?? "-") },
            { key: "dst_host", value: String(extra.dst_host || "-") },
            { key: "app_proto", value: String(extra.app_proto || "-") },
            { key: "reasons", value: reasons || "-" },
          ]}
        />
      )}

      <Panel title="Extra raw" compact>
        <JsonBlock value={extra} showControls={false} />
      </Panel>
    </div>
  );
}
