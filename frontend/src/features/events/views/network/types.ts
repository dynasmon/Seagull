export type TopValue = {
  value: string;
  count: number;
};

export type DnsQnameStat = {
  qname: string;
  count: number;
  max_risk?: number | null;
};

export type TlsJa4Stat = {
  ja4: string;
  count: number;
  ptype?: string | null;
};

export type NetworkSummaryResponse = {
  generated_at: string;
  since_minutes: number;
  agent_id?: string | null;
  limit: number;

  totals: {
    total_events: number;
    proto_intel_events: number;
    dns_events: number;
    http_events: number;
    tls_events: number;
  };

  app_proto: TopValue[];
  dns_qnames: DnsQnameStat[];
  http_hosts: TopValue[];
  http_methods: TopValue[];
  tls_sni: TopValue[];
  tls_alpn: TopValue[];
  tls_ja4: TlsJa4Stat[];
  tls_ja3: TopValue[];
  ja4_ptype: TopValue[];
};
