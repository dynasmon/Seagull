import type { NetEvent } from "../types";
import { normalizeDetails } from "./normalize";

export type EventProtocolIntel = {
  transportProto: string;
  appProto: string;
  appProtoReason: string;
  appProtoConfBand: string;
  flowDirection: string;
  dnsQname: string;
  dnsQtype: string;
  dnsRcode: string;
  dnsAnswers: string;
  httpMethod: string;
  httpHost: string;
  httpPath: string;
  httpStatus: string;
  httpUserAgent: string;
  tlsSni: string;
  tlsAlpnFirst: string;
  tlsVersion: string;
  ja3: string;
  ja4: string;
  ja4Ptype: string;
  hint: string;
  hasProtocolIntel: boolean;
};

function asRecord(value: unknown): Record<string, any> {
  if (!value || typeof value !== "object") return {};
  return value as Record<string, any>;
}

function pickString(...values: unknown[]): string {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (trimmed) return trimmed;
      continue;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      return String(value);
    }
  }
  return "";
}

function pickList(values: unknown): string {
  if (!Array.isArray(values)) return "";
  const items = values.map((value) => pickString(value)).filter(Boolean);
  return items.join(", ");
}

function upperToken(value: string): string {
  return value
    .trim()
    .replace(/[_\s]+/g, "-")
    .toUpperCase();
}

export function formatProtocolLabel(value: string | null | undefined): string {
  const proto = pickString(value).toLowerCase();
  if (!proto) return "-";
  switch (proto) {
    case "http":
      return "HTTP";
    case "dns":
      return "DNS";
    case "tls":
      return "TLS";
    case "quic":
      return "QUIC";
    case "dtls":
      return "DTLS";
    case "tcp":
      return "TCP";
    case "udp":
      return "UDP";
    default:
      return upperToken(proto);
  }
}

function buildHint(intel: Omit<EventProtocolIntel, "hint" | "hasProtocolIntel">): string {
  if (intel.appProto === "http" || intel.httpMethod || intel.httpHost) {
    const httpParts = [
      intel.httpMethod ? upperToken(intel.httpMethod) : "",
      intel.httpHost || intel.httpPath,
    ].filter(Boolean);
    if (httpParts.length > 0) return httpParts.join(" ");
  }
  if (intel.dnsQname) return intel.dnsQname;
  if (intel.tlsSni) return intel.tlsSni;
  if (intel.tlsAlpnFirst) return `ALPN ${intel.tlsAlpnFirst}`;
  if (intel.ja4) return `JA4 ${intel.ja4}`;
  if (intel.ja3) return `JA3 ${intel.ja3}`;
  return "";
}

export function getEventProtocolIntel(event: NetEvent): EventProtocolIntel {
  const row = event as NetEvent & Record<string, any>;
  const extra = normalizeDetails(event.extra);
  const l7 = asRecord(extra.l7);
  const l7Dns = asRecord(l7.dns);
  const l7Http = asRecord(l7.http);
  const l7Tls = asRecord(l7.tls);

  const intelBase = {
    transportProto: pickString(row.proto, extra.proto).toLowerCase(),
    // l7_protocol is a legacy field name; app_proto is canonical.
    appProto: pickString(row.app_proto, extra.app_proto, row.l7_protocol, extra.l7_protocol, l7.protocol).toLowerCase(),
    appProtoReason: pickString(row.app_proto_reason, extra.app_proto_reason),
    appProtoConfBand: pickString(row.app_proto_conf_band, extra.app_proto_conf_band),
    // http_direction is the backend field name for HTTP request vs response.
    flowDirection: pickString(row.flow_direction, extra.flow_direction, extra.http_direction).toLowerCase(),
    dnsQname: pickString(row.dns_qname, extra.dns_qname, l7Dns.qname).toLowerCase(),
    dnsQtype: pickString(row.dns_qtype, extra.dns_qtype, l7Dns.qtype).toUpperCase(),
    dnsRcode: pickString(row.dns_rcode, extra.dns_rcode, l7Dns.rcode).toUpperCase(),
    dnsAnswers: pickString(row.dns_answers, extra.dns_answers, pickList(l7Dns.answers)),
    httpMethod: pickString(row.http_method, extra.http_method, l7Http.method).toUpperCase(),
    httpHost: pickString(row.http_host, extra.http_host, l7Http.host).toLowerCase(),
    httpPath: pickString(row.http_path, extra.http_path, l7Http.path),
    httpStatus: pickString(row.http_status, extra.http_status, l7Http.status),
    httpUserAgent: pickString(row.http_user_agent, extra.http_user_agent, l7Http.user_agent),
    tlsSni: pickString(row.tls_sni, extra.tls_sni, l7Tls.sni).toLowerCase(),
    tlsAlpnFirst: pickString(row.tls_alpn_first, extra.tls_alpn_first, l7Tls.alpn).toLowerCase(),
    tlsVersion: pickString(row.tls_version, extra.tls_version, l7Tls.version, l7Tls.record_version).toUpperCase(),
    ja3: pickString(row.ja3, extra.ja3),
    ja4: pickString(row.ja4, extra.ja4),
    ja4Ptype: pickString(row.ja4_ptype, extra.ja4_ptype).toLowerCase(),
  };

  const hint = buildHint(intelBase);
  const hasProtocolIntel = Boolean(
    intelBase.appProto ||
      intelBase.appProtoReason ||
      intelBase.appProtoConfBand ||
      intelBase.flowDirection ||
      intelBase.dnsQname ||
      intelBase.httpMethod ||
      intelBase.httpHost ||
      intelBase.httpPath ||
      intelBase.httpStatus ||
      intelBase.tlsSni ||
      intelBase.tlsAlpnFirst ||
      intelBase.tlsVersion ||
      intelBase.ja3 ||
      intelBase.ja4 ||
      intelBase.ja4Ptype
  );

  return {
    ...intelBase,
    hint,
    hasProtocolIntel,
  };
}
