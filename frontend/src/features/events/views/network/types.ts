export type ProtoCount = { key: string; count: number };

export type ProtoDnsQueryStat = { qname: string; risk: number; count: number };

export type ProtoJa4Stat = { ja4: string; ptype: string; count: number };

export type ProtocolIntelSummaryResponse = {
  generated_at: string;
  since_minutes: number;
  agent_id?: string | null;

  total_events: number;
  with_proto_metadata: number;
  dns_events: number;
  http_events: number;
  tls_events: number;

  app_protocols: ProtoCount[];
  transport_protocols: ProtoCount[];
  top_dst_ports: ProtoCount[];
  top_src_ports: ProtoCount[];
  app_proto_reasons: ProtoCount[];
  app_proto_conf_bands: ProtoCount[];
  ja4_ptypes: ProtoCount[];
  http_methods: ProtoCount[];

  top_dns_queries: ProtoDnsQueryStat[];
  top_http_hosts: ProtoCount[];
  top_tls_sni: ProtoCount[];
  top_alpn: ProtoCount[];
  top_ja4: ProtoJa4Stat[];
  top_ja3: ProtoCount[];
};

export type ProtocolIntelIndicatorKind =
  | "app_proto"
  | "transport"
  | "dst_port"
  | "src_port"
  | "app_proto_reason"
  | "app_proto_conf_band"
  | "dns_qname"
  | "http_host"
  | "http_method"
  | "tls_sni"
  | "tls_alpn_first"
  | "ja4"
  | "ja4_ptype"
  | "ja3";
