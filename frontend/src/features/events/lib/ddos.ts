import { normalizeDetails, safeNumber, safeString } from "./normalize";

export type DdosFields = {
  attack: string;
  vector: string;
  severity: string;
  confidence: number | null;
  pps: number | null;
  bps: number | null;
  http_rps: number | null;
  tls_handshake_rps: number | null;
  tcp_syn_ratio: number | null;
  unique_src_ips: number | null;
  src_entropy_norm: number | null;
  top_src: Array<{ ip?: string; count?: number }>;
};

export function extractDdosFields(extraRaw: any): DdosFields {
  const extra = normalizeDetails(extraRaw);
  const top = extra.top_src || extra.top_sources || [];
  const top_src: Array<{ ip?: string; count?: number }> = Array.isArray(top)
    ? top.map((x: any) => ({ ip: x?.ip ?? x?.src_ip ?? x?.address, count: safeNumber(x?.count) ?? undefined }))
    : [];

  return {
    attack: safeString(extra.attack || extra.kind || "dos"),
    vector: safeString(extra.vector || extra.subtype || ""),
    severity: safeString(extra.severity || ""),
    confidence: safeNumber(extra.confidence),
    pps: safeNumber(extra.pps),
    bps: safeNumber(extra.bps),
    http_rps: safeNumber(extra.http_rps),
    tls_handshake_rps: safeNumber(extra.tls_handshake_rps),
    tcp_syn_ratio: safeNumber(extra.tcp_syn_ratio),
    unique_src_ips: safeNumber(extra.unique_src_ips),
    src_entropy_norm: safeNumber(extra.src_entropy_norm),
    top_src
  };
}

export function ddosLabel(fields: Pick<DdosFields, "attack" | "vector">): string {
  const a = (fields.attack || "dos").trim() || "dos";
  const v = (fields.vector || "").trim();
  return v ? `${a} / ${v}` : a;
}

export function fmtHumanRate(n: number | null): string {
  if (n === null) return "-";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(2)}K`;
  return `${Math.round(n)}`;
}
